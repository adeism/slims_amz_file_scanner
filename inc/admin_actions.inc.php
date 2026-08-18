<?php
/**
 * AMZ File Scanner & Sanitizer - Actions Controller
 * 
 * Corrective actions, CSV export, and Print Log Handlers
 */

defined('INDEX_AUTH') OR die('Direct access not allowed');

// Apply corrective actions on the active scan findings
if ($can_write && isset($_POST['apply_corrective'])) {
    if (!amzscannerValidateCsrf()) {
        die('<div class="alert alert-danger">' . __('Invalid CSRF token!') . '</div>');
    }

    $findings  = $_SESSION['amzscanner_current_findings'] ?? $_SESSION['amzscanner_current_results'] ?? [];
    $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
    
    if (!empty($findings)) {
        $allowedTypes  = amzscannerAllowedTypes();
        $dangerousExts = amzscannerDangerousExtensions();
        $isStrict      = amzscannerIsStrictImageDir($targetDir);
        $updated       = false;

        foreach ($findings as &$r) {
            if ($r['status'] === 'danger' || $r['status'] === 'error') {
                // Skip if already actioned
                if (!empty($r['action_done'])) {
                    continue;
                }

                $physicalPath = amzscannerResolvePhysicalPath($r['file'], $targetDir);

                if (file_exists($physicalPath)) {
                    if (amzscannerIsValidDeletePath($physicalPath)) {
                        // 1. Always back up to quarantine before any alteration
                        amzscannerQuarantineFile($physicalPath);

                        $mimeType = $r['mime'] ?? '';
                        $ext = strtolower(pathinfo($physicalPath, PATHINFO_EXTENSION));

                        // 2. Dangerous executable files must ALWAYS be deleted
                        if (in_array($ext, $dangerousExts, true)) {
                            if (@unlink($physicalPath)) {
                                $r['action_done'] = 'File berbahaya dihapus (Karantina)';
                                $updated = true;
                            } else {
                                $r['action_done'] = 'Gagal dihapus (Izin file server)';
                                $updated = true;
                            }
                        } elseif ($isStrict && !in_array($mimeType, $allowedTypes, true)) {
                            // Non-image file in strict image folder
                            if (@unlink($physicalPath)) {
                                $r['action_done'] = 'File ilegal dihapus (Karantina)';
                                $updated = true;
                            } else {
                                $r['action_done'] = 'Gagal dihapus (Izin file server)';
                                $updated = true;
                            }
                        } else {
                            // Legitimate image extension: attempt GD sanitization
                            $sanitized = false;
                            if (in_array($mimeType, $allowedTypes, true)) {
                                $sanitized = amzscannerSanitizeImage($physicalPath, $mimeType);
                            }

                            if ($sanitized) {
                                $r['action_done'] = 'Gambar dibersihkan (Payload dibuang)';
                                $updated = true;
                            } else {
                                // Sanitization failed; delete with quarantine backup
                                if (@unlink($physicalPath)) {
                                    $r['action_done'] = 'File dihapus (Karantina)';
                                    $updated = true;
                                } else {
                                    $r['action_done'] = 'Gagal dibersihkan/dihapus';
                                    $updated = true;
                                }
                            }
                        }
                    } else {
                        $r['action_done'] = 'Di luar whitelist jalur aman';
                        $updated = true;
                    }
                } else {
                    $r['action_done'] = 'Berkas sudah tidak ada';
                    $updated = true;
                }
            }
        }
        unset($r);

        if ($updated) {
            $_SESSION['amzscanner_current_findings'] = $findings;
            if (isset($_SESSION['amzscanner_current_results'])) {
                $_SESSION['amzscanner_current_results'] = $findings;
            }
        }
    }

    $success_msg = __('Tindakan korektif berhasil diterapkan! Berkas telah dicadangkan ke folder karantina dan dibersihkan/dihapus dari server.');
    if (class_exists('utility') && method_exists('utility', 'jsToastr')) {
        utility::jsToastr(__('AMZ File Scanner'), $success_msg, 'success');
    }
}

// Export and Print Actions
if ($can_read && isset($_GET['action'])) {
    // ── Export to Standard CSV (RFC 4180 Compliant with UTF-8 BOM) ─────────
    if ($_GET['action'] === 'export_excel' || $_GET['action'] === 'export_csv') {
        $findings = $_SESSION['amzscanner_current_findings'] ?? $_SESSION['amzscanner_current_results'] ?? [];
        $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
        
        $problematicResults = array_filter($findings, fn($r) => $r['status'] === 'danger' || $r['status'] === 'error');
        
        $filename = 'amz_scanner_report_' . date('Ymd_His') . '.csv';

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        $out = fopen('php://output', 'w');
        // UTF-8 BOM for Excel compatibility
        fwrite($out, "\xEF\xBB\xBF");

        // Header metadata
        fputcsv($out, ['LAPORAN TEMUAN HASIL PEMINDAIAN - AMZ FILE SCANNER']);
        fputcsv($out, ['Tanggal Ekspor', date('Y-m-d H:i:s')]);
        fputcsv($out, ['Folder Target', $targetDir]);
        fputcsv($out, ['Petugas', $_SESSION['realname'] ?? $_SESSION['username'] ?? 'Admin']);
        fputcsv($out, []); // Blank line

        // Table headers
        fputcsv($out, ['No', 'Path Berkas (Relatif)', 'Tipe MIME', 'Status', 'Keterangan Temuan', 'Hasil Tindakan Korektif']);

        if (empty($problematicResults)) {
            fputcsv($out, ['-', 'Tidak ada temuan berkas berbahaya.', '-', 'AMAN', '-', '-']);
        } else {
            $i = 1;
            foreach ($problematicResults as $r) {
                $details = is_array($r['msgs']) ? implode('; ', $r['msgs']) : ($r['msgs'] ?? '-');
                $action  = !empty($r['action_done']) ? $r['action_done'] : 'Terdeteksi (Belum Tindakan)';
                fputcsv($out, [
                    $i++,
                    $r['file'],
                    $r['mime'] ?? 'Unknown',
                    strtoupper($r['status']),
                    $details,
                    $action
                ]);
            }
        }

        fclose($out);
        exit;
    }
    
    // ── Print Report View ──────────────────────────────────────────────────
    if ($_GET['action'] === 'print_logs') {
        $findings = $_SESSION['amzscanner_current_findings'] ?? $_SESSION['amzscanner_current_results'] ?? [];
        $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
        
        $problematicResults = array_filter($findings, fn($r) => $r['status'] === 'danger' || $r['status'] === 'error');
        ?>
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>Cetak Laporan Temuan - AMZ File Scanner</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; font-size: 12px; line-height: 1.5; color: #222; margin: 20px; }
                h2 { text-align: center; margin-bottom: 4px; color: #111; }
                .meta { text-align: center; margin-bottom: 20px; color: #555; font-size: 11px; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { border: 1px solid #999; padding: 6px 8px; text-align: left; vertical-align: top; }
                th { background-color: #f0f0f0; font-weight: bold; }
                .badge { display: inline-block; padding: 2px 6px; font-weight: bold; border-radius: 3px; font-size: 10px; }
                .badge-danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                .badge-warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
                .badge-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                .actions-bar { text-align: right; margin-bottom: 12px; }
                .btn-print { background-color: #007bff; color: white; border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-weight: bold; }
                @media print {
                    .actions-bar { display: none; }
                    body { margin: 10px; }
                }
            </style>
        </head>
        <body>
            <div class="actions-bar">
                <button onclick="window.print();" class="btn-print">🖨️ Cetak Dokumen</button>
            </div>
            
            <h2>LAPORAN PEMINDAIAN KEAMANAN BERKAS SLiMS</h2>
            <div class="meta">
                Tanggal: <?= date('d/m/Y H:i:s') ?> &nbsp;|&nbsp; Target: <strong><?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></strong> &nbsp;|&nbsp; Petugas: <?= htmlspecialchars($_SESSION['realname'] ?? $_SESSION['username'] ?? 'System', ENT_QUOTES, 'UTF-8') ?>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th style="width: 5%">No</th>
                        <th style="width: 35%">Path Berkas (Relatif)</th>
                        <th style="width: 15%">Tipe MIME</th>
                        <th style="width: 10%">Status</th>
                        <th style="width: 20%">Keterangan Temuan</th>
                        <th style="width: 15%">Hasil Tindakan</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($problematicResults)): ?>
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 25px; color: #28a745; font-weight: bold;">
                                ✅ Tidak ditemukan berkas berbahaya pada target ini.
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php 
                        $i = 1;
                        foreach ($problematicResults as $r): 
                            $badgeClass = $r['status'] === 'danger' ? 'badge-danger' : 'badge-warning';
                            $details = is_array($r['msgs']) ? implode(', ', $r['msgs']) : ($r['msgs'] ?? '-');
                        ?>
                            <tr>
                                <td><?= $i++ ?></td>
                                <td><code><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></code></td>
                                <td><?= htmlspecialchars($r['mime'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?></td>
                                <td>
                                    <span class="badge <?= $badgeClass ?>"><?= htmlspecialchars(strtoupper($r['status']), ENT_QUOTES, 'UTF-8') ?></span>
                                </td>
                                <td><?= htmlspecialchars($details, ENT_QUOTES, 'UTF-8') ?></td>
                                <td>
                                    <?php if (!empty($r['action_done'])): ?>
                                        <span class="badge badge-success"><?= htmlspecialchars($r['action_done'], ENT_QUOTES, 'UTF-8') ?></span>
                                    <?php else: ?>
                                        <span style="color: #888;">Menunggu Tindakan</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </body>
        </html>
        <?php
        exit;
    }
}
