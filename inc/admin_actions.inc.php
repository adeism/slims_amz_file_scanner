<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

// Apply corrective actions on the active scan results
if ($can_write && isset($_POST['apply_corrective'])) {
    if (!amzscannerValidateCsrf()) {
        die('<div class="alert alert-danger">Invalid CSRF token!</div>');
    }

    $results = $_SESSION['amzscanner_current_results'] ?? [];
    $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
    $extraPatterns = $_SESSION['amzscanner_current_meta']['extra_patterns'] ?? '';
    
    if (!empty($results)) {
        $allowedTypes = amzscannerAllowedTypes();
        $updated = false;

        foreach ($results as &$r) {
            if ($r['status'] === 'danger' || $r['status'] === 'error') {
                // Skip if already actioned
                if (!empty($r['action_done'])) {
                    continue;
                }

                $physicalPath = amzscannerResolvePhysicalPath($r['file'], $targetDir);
                if (amzscannerIsValidDeletePath($physicalPath)) {
                    if (file_exists($physicalPath)) {
                        $mimeType = $r['mime'] ?? '';
                        $ext = strtolower(pathinfo($physicalPath, PATHINFO_EXTENSION));
                        
                        $isStrict = amzscannerIsStrictImageDir($targetDir);
                        
                        $illegal = false;
                        $suspicious = false;

                        $dangerousExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'sh', 'pl', 'py', 'htaccess'];
                        $webXssExts    = ['html', 'htm', 'js'];

                        if (in_array($ext, $dangerousExts, true) || in_array($ext, $webXssExts, true)) {
                            $suspicious = true;
                        }

                        if ($isStrict) {
                            if (!in_array($mimeType, $allowedTypes, true)) {
                                $illegal = true;
                            } else {
                                $suspicious = true;
                            }
                        }

                        if ($illegal) {
                            if (@unlink($physicalPath)) {
                                $r['action_done'] = 'File dihapus';
                                $updated = true;
                            } else {
                                $r['action_done'] = 'Gagal dihapus (Izin ditolak)';
                                $updated = true;
                            }
                        } elseif ($suspicious) {
                            $rewrote = false;
                            if (in_array($mimeType, $allowedTypes, true)) {
                                if ($mimeType === 'image/jpeg') {
                                    $img = @imagecreatefromjpeg($physicalPath);
                                    if ($img) { $rewrote = @imagejpeg($img, $physicalPath, 90); imagedestroy($img); }
                                } elseif ($mimeType === 'image/png') {
                                    $img = @imagecreatefrompng($physicalPath);
                                    if ($img) { $rewrote = @imagepng($img, $physicalPath, 9); imagedestroy($img); }
                                } elseif ($mimeType === 'image/gif') {
                                    $img = @imagecreatefromgif($physicalPath);
                                    if ($img) { $rewrote = @imagegif($img, $physicalPath); imagedestroy($img); }
                                } elseif ($mimeType === 'image/webp') {
                                    $img = @imagecreatefromwebp($physicalPath);
                                    if ($img) { $rewrote = @imagewebp($img, $physicalPath, 80); imagedestroy($img); }
                                }
                            }

                            if ($rewrote) {
                                $r['action_done'] = 'Gambar dibersihkan';
                                $updated = true;
                            } else {
                                if (@unlink($physicalPath)) {
                                    $r['action_done'] = 'File dihapus';
                                    $updated = true;
                                } else {
                                    $r['action_done'] = 'Gagal dibersihkan/dihapus';
                                    $updated = true;
                                }
                            }
                        }
                    } else {
                        $r['action_done'] = 'Sudah dihapus';
                        $updated = true;
                    }
                } else {
                    $r['action_done'] = 'Di luar whitelist jalur';
                    $updated = true;
                }
            }
        }
        unset($r);

        if ($updated) {
            $_SESSION['amzscanner_current_results'] = $results;
        }
    }

    header('Location: ' . amzscannerRedirect('', ['success' => 'corrective_done']));
    exit;
}

// Export and Print GET actions
if ($can_read && isset($_GET['action'])) {
    if ($_GET['action'] === 'export_excel') {
        $results = $_SESSION['amzscanner_current_results'] ?? [];
        $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
        
        $problematicResults = array_filter($results, fn($r) => $r['status'] === 'danger' || $r['status'] === 'error');
        
        header('Content-Type: application/vnd.ms-excel');
        header('Content-Disposition: attachment; filename="amz_scan_report_' . date('Ymd_His') . '.xls"');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        ?>
        <html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <title>Laporan Temuan AMZ File Scanner</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .status-danger { color: #721c24; background-color: #f8d7da; font-weight: bold; }
                .status-error { color: #721c24; background-color: #f8d7da; font-weight: bold; }
            </style>
        </head>
        <body>
            <h2>Laporan Temuan Hasil Pemindaian - AMZ File Scanner</h2>
            <p>Dicetak pada: <?= date('Y-m-d H:i:s') ?></p>
            <p>Target Folder: <?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></p>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Path File (Relatif)</th>
                        <th>MIME Type</th>
                        <th>Status</th>
                        <th>Keterangan / Pola Terdeteksi</th>
                        <th>Hasil Tindakan Korektif</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($problematicResults)): ?>
                        <tr>
                            <td colspan="6" style="text-align: center;">Tidak ada temuan berkas bermasalah.</td>
                        </tr>
                    <?php else: ?>
                        <?php 
                        $i = 1;
                        foreach ($problematicResults as $r): 
                            $statusClass = 'status-danger';
                            $details = is_array($r['msgs']) ? implode(', ', $r['msgs']) : $r['msgs'];
                        ?>
                            <tr>
                                <td><?= $i++ ?></td>
                                <td><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></td>
                                <td><?= htmlspecialchars($r['mime'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?></td>
                                <td class="<?= $statusClass ?>"><?= htmlspecialchars(strtoupper($r['status']), ENT_QUOTES, 'UTF-8') ?></td>
                                <td><?= htmlspecialchars($details, ENT_QUOTES, 'UTF-8') ?></td>
                                <td><?= htmlspecialchars($r['action_done'] !== '' ? $r['action_done'] : 'Terdeteksi (Belum Tindakan)', ENT_QUOTES, 'UTF-8') ?></td>
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
    
    if ($_GET['action'] === 'print_logs') {
        $results = $_SESSION['amzscanner_current_results'] ?? [];
        $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
        
        $problematicResults = array_filter($results, fn($r) => $r['status'] === 'danger' || $r['status'] === 'error');
        ?>
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <title>Cetak Laporan Temuan - AMZ File Scanner</title>
            <style>
                body { font-family: Arial, sans-serif; font-size: 12px; line-height: 1.5; color: #333; margin: 20px; }
                h2 { text-align: center; margin-bottom: 5px; }
                .meta { text-align: center; margin-bottom: 20px; color: #666; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { border: 1px solid #333; padding: 6px 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .badge { display: inline-block; padding: 2px 5px; font-weight: bold; border-radius: 3px; font-size: 10px; }
                .badge-danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                @media print {
                    button { display: none; }
                    body { margin: 10px; }
                }
            </style>
        </head>
        <body>
            <h2>LAPORAN HASIL PEMINDAIAN FILE SCANNER</h2>
            <div class="meta">
                Tanggal Pemindaian: <?= date('d-m-Y H:i:s') ?> | Folder: <?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?> | Oleh: <?= htmlspecialchars($_SESSION['realname'] ?? $_SESSION['username'] ?? 'System', ENT_QUOTES, 'UTF-8') ?>
            </div>
            
            <div style="text-align: right; margin-bottom: 10px;">
                <button onclick="window.print();" style="padding: 5px 10px; font-size: 12px; cursor: pointer;">🖨️ Cetak</button>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th style="width: 5%">#</th>
                        <th style="width: 40%">Path File (Relatif)</th>
                        <th style="width: 15%">MIME Type</th>
                        <th style="width: 10%">Status</th>
                        <th style="width: 15%">Keterangan / Pola</th>
                        <th style="width: 15%">Hasil Tindakan</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($problematicResults)): ?>
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 20px;">Tidak ada temuan berkas bermasalah.</td>
                        </tr>
                    <?php else: ?>
                        <?php 
                        $i = 1;
                        foreach ($problematicResults as $r): 
                            $badgeClass = 'badge-danger';
                            $details = is_array($r['msgs']) ? implode(', ', $r['msgs']) : $r['msgs'];
                        ?>
                            <tr>
                                <td><?= $i++ ?></td>
                                <td><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></td>
                                <td><?= htmlspecialchars($r['mime'] ?? 'Unknown', ENT_QUOTES, 'UTF-8') ?></td>
                                <td>
                                    <span class="badge <?= $badgeClass ?>"><?= htmlspecialchars(strtoupper($r['status']), ENT_QUOTES, 'UTF-8') ?></span>
                                </td>
                                <td><?= htmlspecialchars($details, ENT_QUOTES, 'UTF-8') ?></td>
                                <td><?= htmlspecialchars($r['action_done'] !== '' ? $r['action_done'] : 'Terdeteksi (Belum Tindakan)', ENT_QUOTES, 'UTF-8') ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            
            <script>
                window.onload = function() {
                    window.print();
                }
            </script>
        </body>
        </html>
        <?php
        exit;
    }
}
