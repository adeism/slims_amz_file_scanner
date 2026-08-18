<?php
/**
 * AMZ File Scanner & Sanitizer - Scan View & Controller
 * 
 * Optimized for SLiMS 9: Memory-efficient session caching, pagination, and modern UI.
 */

defined('INDEX_AUTH') OR die('Direct access not allowed');
global $dbs, $sysconf;

// Load persistent settings
$settings      = amzscannerLoadSettings();
$targetDir     = $settings['target_dir'] ?? 'images/docs';
$extraPatterns = $settings['extra_patterns'] ?? '';

$findings = [];
$stats    = [
    'total'       => 0,
    'safe'        => 0,
    'danger'      => 0,
    'error'       => 0,
    'problematic' => 0
];
$scanned  = false;

// Handle Scan Trigger
if (isset($_POST['start_scan'])) {
    @set_time_limit(0);
    if (!amzscannerValidateCsrf()) {
        die('<div class="alert alert-danger">' . __('Invalid CSRF token!') . '</div>');
    }

    $targetDir     = trim($_POST['target_dir'] ?? 'images/docs');
    $extraPatterns = trim($_POST['extra_patterns'] ?? '');

    // Validate target_dir
    $allowed = amzscannerAllowedDirs();
    if (!in_array($targetDir, $allowed, true)) {
        $targetDir = 'images/docs';
    }

    // Save settings
    if ($can_write) {
        amzscannerSaveSetting('target_dir', $targetDir);
        amzscannerSaveSetting('extra_patterns', $extraPatterns);
    }

    $patterns    = amzscannerForbiddenPatterns($extraPatterns);
    $scanDirPath = SB . $targetDir;
    
    // Initial scan is always read-only (corrective is false)
    $scanResult = amzscannerScanDir($scanDirPath, $targetDir, $patterns, false);
    $findings   = $scanResult['findings'];
    $stats      = $scanResult['stats'];

    // Sort findings: danger first, then error
    usort($findings, function($a, $b) {
        $statusOrder = ['danger' => 1, 'error' => 2, 'safe' => 3];
        $orderA = $statusOrder[$a['status']] ?? 99;
        $orderB = $statusOrder[$b['status']] ?? 99;
        return $orderA <=> $orderB;
    });

    // Memory-Safe Session Storage (only store problematic findings & stats)
    $_SESSION['amzscanner_current_stats']    = $stats;
    $_SESSION['amzscanner_current_findings'] = $findings;
    $_SESSION['amzscanner_current_results']  = $findings; // backward compat
    $_SESSION['amzscanner_current_meta']     = [
        'target_dir'     => $targetDir,
        'extra_patterns' => $extraPatterns
    ];
    $scanned = true;
} elseif (isset($_SESSION['amzscanner_current_findings']) || isset($_SESSION['amzscanner_current_results'])) {
    $findings = $_SESSION['amzscanner_current_findings'] ?? $_SESSION['amzscanner_current_results'] ?? [];
    $stats    = $_SESSION['amzscanner_current_stats'] ?? [
        'total'       => count($findings),
        'safe'        => 0,
        'danger'      => count($findings),
        'error'       => 0,
        'problematic' => count($findings)
    ];

    if (isset($_SESSION['amzscanner_current_meta'])) {
        $targetDir     = $_SESSION['amzscanner_current_meta']['target_dir'];
        $extraPatterns = $_SESSION['amzscanner_current_meta']['extra_patterns'];
    }
    $scanned = true;
}

// Calculate Statistics
$totalFiles       = $stats['total'] ?? count($findings);
$dangerCount      = $stats['danger'] ?? 0;
$errorCount       = $stats['error'] ?? 0;
$safeCount        = $stats['safe'] ?? 0;
$problematicCount = count($findings);

$resolvedFindings   = array_filter($findings, fn($r) => !empty($r['action_done']));
$resolvedCount      = count($resolvedFindings);
$unresolvedCount    = $problematicCount - $resolvedCount;

// Pagination
$perPage    = 50;
$totalPages = (int)ceil($problematicCount / $perPage);
if ($totalPages < 1) $totalPages = 1;

$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) $page = 1;
if ($page > $totalPages) $page = $totalPages;

$offset           = ($page - 1) * $perPage;
$paginatedResults = array_slice($findings, $offset, $perPage);
?>

<!-- Scan Configuration Box -->
<div class="card mb-4 border-0 shadow-sm" style="border-radius: 8px; border: 1px solid #e2e8f0;">
    <div class="card-header bg-primary text-white py-3 d-flex align-items-center" style="border-top-left-radius: 8px; border-top-right-radius: 8px;">
        <h5 class="mb-0 font-weight-bold">⚙️ <?= __('Pengaturan &amp; Pemindaian Berkas') ?></h5>
    </div>
    <div class="card-body p-4">
        <form method="post" action="<?= amzscannerAdminUrl() ?>">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="start_scan" value="1">
            
            <div class="row">
                <div class="col-md-6 form-group mb-3">
                    <label class="font-weight-bold mb-1 text-dark">📁 <?= __('Folder Target Pemindaian') ?></label>
                    <select name="target_dir" class="form-control form-select">
                        <option value="images/docs" <?= $targetDir === 'images/docs' ? 'selected' : '' ?>>images/docs (Cover Buku / Bibliografi)</option>
                        <option value="images/persons" <?= $targetDir === 'images/persons' ? 'selected' : '' ?>>images/persons (Foto Anggota)</option>
                        <option value="repository" <?= $targetDir === 'repository' ? 'selected' : '' ?>>repository (Berkas Lampiran Dokumen / PDF)</option>
                        <option value="files" <?= $targetDir === 'files' ? 'selected' : '' ?>>files (Berkas Unggahan Sistem Lainnya)</option>
                    </select>
                    <small class="text-muted"><?= __('Pilih direktori upload SLiMS yang ingin dipindai secara mendalam.') ?></small>
                </div>
                
                <div class="col-md-6 form-group mb-3">
                    <label class="font-weight-bold mb-1 text-dark">🔍 <?= __('Pola Signature Tambahan (Opsional)') ?></label>
                    <input type="text" name="extra_patterns" class="form-control" value="<?= htmlspecialchars($extraPatterns, ENT_QUOTES, 'UTF-8') ?>" placeholder="Contoh: c99shell, r57shell, wso_version">
                    <small class="text-muted"><?= __('Pisahkan dengan koma. Pola standar seperti shell_exec, eval, system sudah aktif otomatis.') ?></small>
                </div>
            </div>
            
            <div class="d-flex mt-3">
                <button type="submit" class="btn btn-primary px-4 py-2 font-weight-bold shadow-sm">
                    ⚡ <?= __('Mulai Pindai Sekarang') ?>
                </button>
            </div>
        </form>
    </div>
</div>

<?php if ($scanned): ?>
    <!-- Statistics Summary Bar -->
    <div class="row mb-4">
        <div class="col-md-4 mb-3">
            <div class="card border-0 shadow-sm h-100" style="background: linear-gradient(135deg, #e0f2fe 0%, #bae6fd 100%); border-radius: 8px;">
                <div class="card-body text-center py-3">
                    <div class="text-secondary small font-weight-bold text-uppercase"><?= __('Total Berkas Dipindai') ?></div>
                    <div class="h2 font-weight-bold text-primary mb-0 mt-1"><?= number_format($totalFiles) ?></div>
                    <div class="small text-muted mt-1">Target: <code><?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></code></div>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card border-0 shadow-sm h-100" style="background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%); border-radius: 8px;">
                <div class="card-body text-center py-3">
                    <div class="text-secondary small font-weight-bold text-uppercase"><?= __('Berkas Bersih &amp; Aman') ?></div>
                    <div class="h2 font-weight-bold text-success mb-0 mt-1"><?= number_format($safeCount) ?></div>
                    <div class="small text-muted mt-1"><?= __('Bebas dari skrip berbahaya') ?></div>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card border-0 shadow-sm h-100" style="background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-radius: 8px;">
                <div class="card-body text-center py-3">
                    <div class="text-secondary small font-weight-bold text-uppercase"><?= __('Temuan Berbahaya / Anomali') ?></div>
                    <div class="h2 font-weight-bold text-danger mb-0 mt-1">
                        <?= number_format($problematicCount) ?>
                        <?php if ($resolvedCount > 0): ?>
                            <span class="small font-weight-normal text-success" style="font-size: 14px;">(<?= $resolvedCount ?> Ditindak)</span>
                        <?php endif; ?>
                    </div>
                    <div class="small text-muted mt-1"><?= $unresolvedCount > 0 ? __('Memerlukan tindakan korektif') : __('Semua ancaman telah diatasi') ?></div>
                </div>
            </div>
        </div>
    </div>
    
    <?php if ($problematicCount > 0): ?>
        <!-- Action Control Panel -->
        <div class="card mb-4 border-warning shadow-sm" style="border-radius: 8px; background-color: #fffdf5;">
            <div class="card-body p-4">
                <?php if ($unresolvedCount > 0): ?>
                    <div class="d-flex align-items-start mb-3">
                        <div class="mr-3" style="font-size: 32px; line-height: 1;">🚨</div>
                        <div>
                            <h5 class="text-danger mb-1 font-weight-bold">
                                <?= sprintf(__('Ditemukan %d berkas bermasalah / mencurigakan!'), $unresolvedCount) ?>
                            </h5>
                            <p class="text-dark mb-0 small">
                                <?= __('Sistem mendeteksi adanya berkas skrip terlarang, pola payload injeksi, atau ekstensi ilegal. Anda dapat menerapkan tindakan korektif untuk membersihkan gambar (GD Sanitizer) atau menghapus file berbahaya. Seluruh berkas akan secara otomatis <strong>dicadangkan ke folder karantina (files/quarantine/)</strong> sebelum tindakan diterapkan.') ?>
                            </p>
                        </div>
                    </div>
                    
                    <div class="d-flex align-items-center flex-wrap" style="gap: 8px;">
                        <?php if ($can_write): ?>
                            <form method="post" action="<?= amzscannerAdminUrl() ?>" class="mb-0 mr-2">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="apply_corrective" value="1">
                                <button type="submit" class="btn btn-danger py-2 px-3 font-weight-bold shadow-sm" onclick="return confirm('<?= __('Apakah Anda yakin ingin menerapkan tindakan korektif? Sistem akan mencadangkan file ke folder karantina lalu membersihkan/menghapus berkas berbahaya.') ?>');">
                                    🛠️ <?= __('Terapkan Tindakan Korektif (Backup &amp; Bersihkan)') ?>
                                </button>
                            </form>
                        <?php endif; ?>
                        
                        <a href="<?= amzscannerAdminUrl(['action' => 'print_logs']) ?>" target="_blank" class="btn btn-secondary py-2 px-3 font-weight-bold mr-2">
                            🖨️ <?= __('Cetak Laporan') ?>
                        </a>
                        <a href="<?= amzscannerAdminUrl(['action' => 'export_csv']) ?>" class="btn btn-success py-2 px-3 font-weight-bold">
                            📊 <?= __('Ekspor ke CSV (Excel)') ?>
                        </a>
                    </div>
                <?php else: ?>
                    <div class="d-flex align-items-start mb-3">
                        <div class="mr-3" style="font-size: 32px; line-height: 1;">✅</div>
                        <div>
                            <h5 class="text-success mb-1 font-weight-bold"><?= __('Semua temuan berbahaya telah berhasil ditangani!') ?></h5>
                            <p class="text-muted mb-0 small"><?= __('Seluruh ancaman berkas telah dibersihkan atau dipindahkan ke karantina server Anda.') ?></p>
                        </div>
                    </div>
                    
                    <div class="d-flex align-items-center flex-wrap" style="gap: 8px;">
                        <a href="<?= amzscannerAdminUrl(['action' => 'print_logs']) ?>" target="_blank" class="btn btn-secondary py-2 px-3 font-weight-bold mr-2">
                            🖨️ <?= __('Cetak Laporan') ?>
                        </a>
                        <a href="<?= amzscannerAdminUrl(['action' => 'export_csv']) ?>" class="btn btn-success py-2 px-3 font-weight-bold">
                            📊 <?= __('Ekspor ke CSV (Excel)') ?>
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="card border-0 shadow-sm mb-4" style="border-radius: 8px; border: 1px solid #e2e8f0;">
            <div class="card-header bg-dark text-white py-3 d-flex justify-content-between align-items-center" style="border-top-left-radius: 8px; border-top-right-radius: 8px;">
                <h5 class="mb-0 font-weight-bold">📋 <?= __('Rincian Berkas Bermasalah') ?></h5>
                <span class="badge badge-light bg-light text-dark font-weight-bold px-3 py-2" style="font-size: 13px;">
                    <?= sprintf(__('%d Temuan'), $problematicCount) ?>
                </span>
            </div>
            <div class="card-body p-0">
                <div class="p-3 text-muted small border-bottom bg-light">
                    <?= sprintf(__('Menampilkan data ke-%d sampai ke-%d dari total %d temuan.'), ($offset + 1), min($offset + $perPage, $problematicCount), $problematicCount) ?>
                </div>
                
                <div class="table-responsive">
                    <table class="table table-hover table-striped mb-0">
                        <thead class="thead-light">
                            <tr>
                                <th style="width: 5%" class="text-center">#</th>
                                <th style="width: 35%"><?= __('Lokasi Berkas (Relatif)') ?></th>
                                <th style="width: 15%"><?= __('Tipe MIME') ?></th>
                                <th style="width: 10%" class="text-center"><?= __('Status') ?></th>
                                <th style="width: 20%"><?= __('Keterangan / Anomali') ?></th>
                                <th style="width: 15%"><?= __('Status Pembersihan') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($paginatedResults as $i => $r): 
                                $badgeClass = $r['status'] === 'danger' ? 'badge-danger bg-danger' : 'badge-warning bg-warning text-dark';
                                $statusLabel = $r['status'] === 'danger' ? '🚨 Berbahaya' : '⚠️ Warning';
                            ?>
                                <tr>
                                    <td class="text-center text-muted"><?= $offset + $i + 1 ?></td>
                                    <td>
                                        <code class="text-dark bg-light p-1 border rounded" style="word-break: break-all; font-size: 12px;">
                                            <?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?>
                                        </code>
                                    </td>
                                    <td><small class="text-muted font-monospace"><?= htmlspecialchars($r['mime'] ?? '-', ENT_QUOTES, 'UTF-8') ?></small></td>
                                    <td class="text-center">
                                        <span class="badge <?= $badgeClass ?> px-2 py-1"><?= $statusLabel ?></span>
                                    </td>
                                    <td>
                                        <?php if (!empty($r['msgs'])): ?>
                                            <ul class="mb-0 pl-3 small">
                                                <?php foreach ($r['msgs'] as $msg): ?>
                                                    <li><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') ?></li>
                                                <?php endforeach; ?>
                                            </ul>
                                        <?php else: ?>
                                            <span class="text-muted">—</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if (!empty($r['action_done'])): 
                                            $actionBadge = strpos($r['action_done'], 'Gagal') === false ? 'badge-success bg-success' : 'badge-danger bg-danger';
                                        ?>
                                            <span class="badge <?= $actionBadge ?> px-2 py-1"><?= htmlspecialchars($r['action_done'], ENT_QUOTES, 'UTF-8') ?></span>
                                        <?php else: ?>
                                            <span class="text-muted small">⏳ Menunggu Tindakan</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- Pagination Controls -->
                <?php if ($totalPages > 1): ?>
                    <div class="p-3 border-top d-flex justify-content-center">
                        <nav>
                            <ul class="pagination mb-0">
                                <?php if ($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="<?= amzscannerAdminUrl(['page' => 1]) ?>">« <?= __('Awal') ?></a>
                                    </li>
                                    <li class="page-item">
                                        <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $page - 1]) ?>">‹ <?= __('Sblm') ?></a>
                                    </li>
                                <?php endif; ?>
                                
                                <?php
                                $startPage = max(1, $page - 2);
                                $endPage   = min($totalPages, $page + 2);
                                for ($p = $startPage; $p <= $endPage; $p++):
                                ?>
                                    <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                                        <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $p]) ?>"><?= $p ?></a>
                                    </li>
                                <?php endfor; ?>
                                
                                <?php if ($page < $totalPages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $page + 1]) ?>"><?= __('Lanjut') ?> ›</a>
                                    </li>
                                    <li class="page-item">
                                        <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $totalPages]) ?>"><?= __('Akhir') ?> »</a>
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php else: ?>
        <div class="alert alert-success border-success text-center py-4 my-4 shadow-sm" style="border-radius: 8px;" role="alert">
            <h4 class="alert-heading font-weight-bold mb-2">🎉 <?= __('Direktori Bersih &amp; Aman!') ?></h4>
            <p class="mb-0"><?= sprintf(__('Tidak ditemukan berkas mencurigakan atau berbahaya pada direktori <strong>%s</strong>.'), htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8')) ?></p>
        </div>
    <?php endif; ?>
<?php endif; ?>
