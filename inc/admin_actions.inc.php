<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');
global $dbs, $sysconf;

// ─── AJAX: scan_chunk ────────────────────────────────────────────────────────
// Called by the chunked AJAX scanner. Process a batch of files.
if (isset($_GET['action']) && $_GET['action'] === 'scan_chunk') {
    header('Content-Type: application/json; charset=utf-8');

    if (!$can_read) {
        echo json_encode(['error' => 'Akses ditolak.']);
        exit;
    }

    $settings   = amzscannerLoadSettings();
    $targetDir  = $_GET['target_dir'] ?? 'images/docs';
    $allowed    = amzscannerAllowedDirs();
    if (!in_array($targetDir, $allowed, true)) $targetDir = 'images/docs';

    $offset     = max(0, (int)($_GET['offset'] ?? 0));
    $batchSize  = 50;

    $dirPath    = SB . $targetDir;
    $allFiles   = amzscannerGetFilesRecursive($dirPath);
    $total      = count($allFiles);
    $batch      = array_slice($allFiles, $offset, $batchSize);

    $batchResults = [];
    foreach ($batch as $fullPath) {
        $result = amzscannerScanSingleFile($fullPath, $targetDir, $settings);
        if ($result === null) continue;
        $result['file'] = ltrim(str_replace($dirPath, '', $fullPath), DIRECTORY_SEPARATOR);
        $batchResults[] = $result;
    }

    // Cache into session (merge)
    if ($offset === 0) {
        $_SESSION['amzscanner_current_results'] = [];
        $_SESSION['amzscanner_current_meta']    = [
            'target_dir'    => $targetDir,
            'extra_patterns'=> $settings['extra_patterns'] ?? '',
        ];
    }
    $existing = $_SESSION['amzscanner_current_results'] ?? [];
    $_SESSION['amzscanner_current_results'] = array_merge($existing, $batchResults);

    echo json_encode([
        'total'      => $total,
        'processed'  => $offset + count($batch),
        'batch_size' => $batchSize,
        'done'       => ($offset + count($batch)) >= $total,
        'results'    => $batchResults,
    ]);
    exit;
}

// ─── AJAX: apply_corrective ─────────────────────────────────────────────────
if ($can_write && isset($_POST['apply_corrective'])) {
    if (!amzscannerValidateCsrf()) {
        die('<div class="alert alert-danger">Invalid CSRF token!</div>');
    }

    $results   = $_SESSION['amzscanner_current_results'] ?? [];
    $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
    $settings  = amzscannerLoadSettings();
    $mode      = $settings['corrective_mode'] ?? 'quarantine';
    $allowedTypes = amzscannerAllowedTypes();

    if (!empty($results)) {
        foreach ($results as &$r) {
            if (($r['status'] === 'danger' || $r['status'] === 'notice') && empty($r['action_done'])) {
                $physicalPath = amzscannerResolvePhysicalPath($r['file'], $targetDir);
                if (!amzscannerIsValidDeletePath($physicalPath) || !file_exists($physicalPath)) {
                    $r['action_done'] = 'Berkas tidak ditemukan atau jalur tidak valid';
                    continue;
                }

                $mimeType = $r['mime'] ?? '';

                if ($mode === 'report_only') {
                    $r['action_done'] = 'Dilaporkan (Report Only)';
                    continue;
                }

                if ($mode === 'delete') {
                    if (@unlink($physicalPath)) {
                        $r['action_done'] = 'Dihapus Permanen';
                        amzscannerWriteLog('delete', basename($physicalPath), $physicalPath, $r['score'] ?? 0, $r['msgs'] ?? [], $r['layers_triggered'] ?? []);
                    } else {
                        $r['action_done'] = 'Gagal dihapus (Izin ditolak)';
                    }
                    continue;
                }

                // Default: quarantine, try GD clean first for images
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
                    $r['action_done'] = 'Gambar Dibersihkan (GD Library)';
                    amzscannerWriteLog('clean', basename($physicalPath), $physicalPath, $r['score'] ?? 0, $r['msgs'] ?? [], $r['layers_triggered'] ?? []);
                } else {
                    if (amzscannerQuarantineFile($physicalPath, $r)) {
                        $r['action_done'] = 'Dipindahkan ke Karantina';
                        amzscannerWriteLog('quarantine', basename($physicalPath), $physicalPath, $r['score'] ?? 0, $r['msgs'] ?? [], $r['layers_triggered'] ?? []);
                    } else {
                        $r['action_done'] = 'Gagal dikarantina';
                    }
                }
            }
        }
        unset($r);
        $_SESSION['amzscanner_current_results'] = $results;
    }

    header('Location: ' . amzscannerAdminUrl(['tab' => 'scan', 'success' => 'corrective_done']));
    exit;
}

// ─── Quarantine: Restore ────────────────────────────────────────────────────
if ($can_write && isset($_POST['action']) && $_POST['action'] === 'quarantine_restore') {
    if (!amzscannerValidateCsrf()) {
        header('Location: ' . amzscannerAdminUrl(['tab' => 'quarantine', 'error' => 'csrf_error']));
        exit;
    }
    $qname  = basename($_POST['quarantine_name'] ?? '');
    $result = amzscannerRestoreFromQuarantine($qname);
    $status = $result['success'] ? 'restored' : 'restore_failed';
    header('Location: ' . amzscannerAdminUrl(['tab' => 'quarantine', 'success' => $status]));
    exit;
}

// ─── Quarantine: Delete Permanent ──────────────────────────────────────────
if ($can_write && isset($_POST['action']) && $_POST['action'] === 'quarantine_delete') {
    if (!amzscannerValidateCsrf()) {
        header('Location: ' . amzscannerAdminUrl(['tab' => 'quarantine', 'error' => 'csrf_error']));
        exit;
    }
    $qname  = basename($_POST['quarantine_name'] ?? '');
    $result = amzscannerDeleteFromQuarantine($qname);
    $status = $result['success'] ? 'deleted' : 'delete_failed';
    header('Location: ' . amzscannerAdminUrl(['tab' => 'quarantine', 'success' => $status]));
    exit;
}

// ─── Logs: Prune old logs ───────────────────────────────────────────────────
if ($can_write && isset($_POST['action']) && $_POST['action'] === 'prune_logs') {
    if (!amzscannerValidateCsrf()) {
        header('Location: ' . amzscannerAdminUrl(['tab' => 'logs', 'error' => 'csrf_error']));
        exit;
    }
    $days   = max(7, (int)($_POST['prune_days'] ?? 90));
    $pruned = amzscannerPruneLogs($days);
    header('Location: ' . amzscannerAdminUrl(['tab' => 'logs', 'success' => 'log_pruned']));
    exit;
}

// ─── Logs: Export CSV ───────────────────────────────────────────────────────
if ($can_read && isset($_GET['action']) && $_GET['action'] === 'export_log_csv') {
    $logs = amzscannerLoadLogs();
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="amz_security_log_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Timestamp', 'Action', 'Filename', 'Path', 'Score', 'Messages', 'Layers', 'Actor', 'IP']);
    foreach ($logs as $entry) {
        fputcsv($out, [
            $entry['timestamp']  ?? '',
            $entry['action']     ?? '',
            $entry['filename']   ?? '',
            $entry['path']       ?? '',
            $entry['score']      ?? 0,
            implode(' | ', $entry['msgs']   ?? []),
            implode(', ', $entry['layers']  ?? []),
            $entry['actor']      ?? '',
            $entry['ip']         ?? '',
        ]);
    }
    fclose($out);
    exit;
}

// ─── Export Excel (backward compat) ─────────────────────────────────────────
if ($can_read && isset($_GET['action']) && $_GET['action'] === 'export_excel') {
    $results   = $_SESSION['amzscanner_current_results'] ?? [];
    $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
    $problematicResults = array_filter($results, fn($r) => $r['status'] !== 'safe');

    header('Content-Type: application/vnd.ms-excel');
    header('Content-Disposition: attachment; filename="amz_scan_report_' . date('Ymd_His') . '.xls"');
    header('Pragma: no-cache'); header('Expires: 0');
    ?>
    <html><head><meta charset="UTF-8"><style>
    table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:8px;text-align:left}
    th{background:#f2f2f2}.danger{color:#721c24;background:#f8d7da;font-weight:bold}
    </style></head><body>
    <h2>Laporan Temuan Hasil Pemindaian — AMZ File Scanner v<?= AMZSCANNER_VERSION ?></h2>
    <p>Dicetak: <?= date('Y-m-d H:i:s') ?> | Folder: <?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></p>
    <table><thead><tr>
        <th>#</th><th>Path File</th><th>MIME Type</th><th>Status</th>
        <th>Skor</th><th>Layer Terdeteksi</th><th>Keterangan</th><th>Tindakan</th>
    </tr></thead><tbody>
    <?php if (empty($problematicResults)): ?>
        <tr><td colspan="8" style="text-align:center">Tidak ada temuan.</td></tr>
    <?php else: $i=1; foreach($problematicResults as $r): ?>
        <tr>
            <td><?= $i++ ?></td>
            <td><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars($r['mime'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
            <td class="danger"><?= htmlspecialchars(strtoupper($r['status'] ?? ''), ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= (int)($r['score'] ?? 0) ?></td>
            <td><?= htmlspecialchars(implode(', ', $r['layers_triggered'] ?? []), ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars(implode(' | ', $r['msgs'] ?? []), ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars($r['action_done'] ?? '—', ENT_QUOTES, 'UTF-8') ?></td>
        </tr>
    <?php endforeach; endif; ?>
    </tbody></table></body></html>
    <?php
    exit;
}

// ─── Print Logs (HTML Print View) ───────────────────────────────────────────
if ($can_read && isset($_GET['action']) && $_GET['action'] === 'print_logs') {
    $results   = $_SESSION['amzscanner_current_results'] ?? [];
    $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? 'images/docs';
    $problematicResults = array_filter($results, fn($r) => $r['status'] !== 'safe');
    ?>
    <!DOCTYPE html><html lang="id"><head><meta charset="UTF-8">
    <title>Cetak Laporan AMZ File Scanner</title>
    <style>body{font-family:Arial,sans-serif;font-size:12px}
    table{width:100%;border-collapse:collapse}th,td{border:1px solid #333;padding:6px}
    th{background:#f2f2f2}.badge-danger{background:#f8d7da;color:#721c24;font-weight:bold;padding:2px 5px;border-radius:3px}
    @media print{button{display:none}}</style></head><body>
    <h2 style="text-align:center">LAPORAN HASIL PEMINDAIAN — AMZ FILE SCANNER v<?= AMZSCANNER_VERSION ?></h2>
    <p style="text-align:center">Tanggal: <?= date('d-m-Y H:i:s') ?> | Folder: <?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></p>
    <div style="text-align:right;margin-bottom:10px">
        <button onclick="window.print()">🖨️ Cetak</button>
    </div>
    <table><thead><tr>
        <th>#</th><th>Path File</th><th>MIME</th><th>Skor</th><th>Layer</th><th>Keterangan</th><th>Tindakan</th>
    </tr></thead><tbody>
    <?php if (empty($problematicResults)): ?>
        <tr><td colspan="7" style="text-align:center;padding:20px">Tidak ada temuan.</td></tr>
    <?php else: $i=1; foreach($problematicResults as $r): ?>
        <tr>
            <td><?= $i++ ?></td>
            <td><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></td>
            <td><small><?= htmlspecialchars($r['mime'] ?? '', ENT_QUOTES, 'UTF-8') ?></small></td>
            <td><span class="badge-danger"><?= (int)($r['score'] ?? 0) ?></span></td>
            <td><small><?= htmlspecialchars(implode(', ', $r['layers_triggered'] ?? []), ENT_QUOTES, 'UTF-8') ?></small></td>
            <td><small><?= htmlspecialchars(implode(' | ', $r['msgs'] ?? []), ENT_QUOTES, 'UTF-8') ?></small></td>
            <td><?= htmlspecialchars($r['action_done'] ?? '—', ENT_QUOTES, 'UTF-8') ?></td>
        </tr>
    <?php endforeach; endif; ?>
    </tbody></table>
    <script>window.onload=function(){window.print();}</script>
    </body></html>
    <?php
    exit;
}
