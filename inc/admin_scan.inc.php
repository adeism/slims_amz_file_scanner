<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');
global $dbs, $sysconf;

// Load settings
$settings = amzscannerLoadSettings();
$targetDir = $settings['target_dir'] ?? 'images/docs';
$extraPatterns = $settings['extra_patterns'] ?? '';

$results = [];
$scanned = false;

// If POST request to run the scan
if (isset($_POST['start_scan'])) {
    @set_time_limit(0);
    if (!amzscannerValidateCsrf()) {
        die('<div class="alert alert-danger">Invalid CSRF token!</div>');
    }

    $targetDir     = trim($_POST['target_dir'] ?? 'images/docs');
    $extraPatterns = trim($_POST['extra_patterns'] ?? '');

    // Validate target_dir
    $allowed = amzscannerAllowedDirs();
    if (!in_array($targetDir, $allowed, true)) {
        $targetDir = 'images/docs';
    }

    // Save settings (persistent configuration)
    if ($can_write) {
        amzscannerSaveSetting('target_dir', $targetDir);
        amzscannerSaveSetting('extra_patterns', $extraPatterns);
    }

    $patterns = amzscannerForbiddenPatterns($extraPatterns);
    $scanDirPath = SB . $targetDir;
    
    // Initial scan is always read-only (corrective is false)
    $results = amzscannerScanDir($scanDirPath, $targetDir, $patterns, false);

    // Sort results: danger first, then error, then safe
    usort($results, function($a, $b) {
        $statusOrder = ['danger' => 1, 'error' => 2, 'safe' => 3];
        $orderA = $statusOrder[$a['status']] ?? 99;
        $orderB = $statusOrder[$b['status']] ?? 99;
        return $orderA <=> $orderB;
    });

    // Cache the results and meta in session
    $_SESSION['amzscanner_current_results'] = $results;
    $_SESSION['amzscanner_current_meta'] = [
        'target_dir'     => $targetDir,
        'extra_patterns' => $extraPatterns
    ];
    $scanned = true;
} elseif (isset($_SESSION['amzscanner_current_results'])) {
    $results = $_SESSION['amzscanner_current_results'];
    if (isset($_SESSION['amzscanner_current_meta'])) {
        $targetDir     = $_SESSION['amzscanner_current_meta']['target_dir'];
        $extraPatterns = $_SESSION['amzscanner_current_meta']['extra_patterns'];
    }
    $scanned = true;
}

// Calculate statistics
$totalFiles = count($results);
$dangerCount = count(array_filter($results, fn($r) => $r['status'] === 'danger'));
$errorCount = count(array_filter($results, fn($r) => $r['status'] === 'error'));
$safeCount = $totalFiles - $dangerCount - $errorCount;

$problematicResults = array_filter($results, fn($r) => $r['status'] === 'danger' || $r['status'] === 'error');
$problematicCount = count($problematicResults);
$resolvedResults = array_filter($problematicResults, fn($r) => !empty($r['action_done']));
$resolvedCount = count($resolvedResults);
$unresolvedCount = $problematicCount - $resolvedCount;

// Pagination
$perPage = 100;
$totalPages = (int)ceil($problematicCount / $perPage);
if ($totalPages < 1) {
    $totalPages = 1;
}

$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) {
    $page = 1;
} elseif ($page > $totalPages) {
    $page = $totalPages;
}

$offset = ($page - 1) * $perPage;
$paginatedResults = array_slice($problematicResults, $offset, $perPage);
?>

<div class="card mb-4 border-light shadow-sm">
    <div class="card-header bg-primary text-white d-flex align-items-center">
        <h5 class="mb-0">⚙️ Pengaturan &amp; Mulai Pemindaian</h5>
    </div>
    <div class="card-body">
        <form method="post" action="<?= amzscannerAdminUrl() ?>" class="submitViaAJAX">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="start_scan" value="1">
            
            <div class="row">
                <div class="col-md-6 form-group mb-3">
                    <label class="font-weight-bold mb-1">📁 Folder Target Pemindaian</label>
                    <select name="target_dir" class="form-control form-select">
                        <option value="images/docs" <?= $targetDir === 'images/docs' ? 'selected' : '' ?>>images/docs (Default Upload/Cover Biblio)</option>
                        <option value="images/persons" <?= $targetDir === 'images/persons' ? 'selected' : '' ?>>images/persons (Foto Anggota)</option>
                        <option value="repository" <?= $targetDir === 'repository' ? 'selected' : '' ?>>repository (Berkas Lampiran / PDF)</option>
                    </select>
                </div>
                
                <div class="col-md-6 form-group mb-3">
                    <label class="font-weight-bold mb-1">🔍 Pola Tambahan (Pisahkan dengan koma)</label>
                    <input type="text" name="extra_patterns" class="form-control" value="<?= htmlspecialchars($extraPatterns, ENT_QUOTES, 'UTF-8') ?>" placeholder="Contoh: shell_exec, passthru, popen">
                </div>
            </div>
            
            <div class="d-flex mt-2">
                <button type="submit" class="btn btn-primary btn-block py-2 font-weight-bold">
                    ⚡ Mulai Pindai Sekarang
                </button>
            </div>
        </form>
    </div>
</div>

<?php if ($scanned): ?>
    <hr class="my-4">
    
    <!-- Stats Cards -->
    <div class="row mb-4">
        <div class="col-md-4 mb-3">
            <div class="card border-info bg-light h-100">
                <div class="card-body text-center d-flex flex-column justify-content-center py-3">
                    <h6 class="text-muted mb-1 text-uppercase small">Total Berkas Dipindai</h6>
                    <h3 class="font-weight-bold text-info mb-0"><?= $totalFiles ?></h3>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card border-success bg-light h-100">
                <div class="card-body text-center d-flex flex-column justify-content-center py-3">
                    <h6 class="text-muted mb-1 text-uppercase small">Berkas Aman</h6>
                    <h3 class="font-weight-bold text-success mb-0"><?= $safeCount ?></h3>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card border-danger bg-light h-100">
                <div class="card-body text-center d-flex flex-column justify-content-center py-3">
                    <h6 class="text-muted mb-1 text-uppercase small">Berkas Bermasalah</h6>
                    <h3 class="font-weight-bold text-danger mb-0">
                        <?= $problematicCount ?>
                        <?php if ($resolvedCount > 0): ?>
                            <span class="small text-success font-weight-normal">(<?= $resolvedCount ?> Bersih)</span>
                        <?php endif; ?>
                    </h3>
                </div>
            </div>
        </div>
    </div>
    
    <?php if ($problematicCount > 0): ?>
        <!-- Action Control Panel -->
        <div class="card mb-4 border-warning bg-light shadow-sm">
            <div class="card-body">
                <?php if ($unresolvedCount > 0): ?>
                    <div class="d-flex align-items-center mb-3">
                        <span class="mr-2" style="font-size: 24px;">🚨</span>
                        <div>
                            <h5 class="text-danger mb-0 font-weight-bold">Ditemukan <?= $unresolvedCount ?> masalah berkas berbahaya aktif!</h5>
                            <p class="text-muted mb-0 small">Sistem mendeteksi berkas skrip ilegal atau muatan kode tersembunyi. Silakan terapkan tindakan korektif untuk membersihkan atau menghapus berkas-berkas ini.</p>
                        </div>
                    </div>
                    
                    <div class="d-flex align-items-center flex-wrap gap-2">
                        <?php if ($can_write): ?>
                            <!-- Corrective Action Trigger Form -->
                            <form method="post" action="<?= amzscannerAdminUrl() ?>" class="submitViaAJAX mb-0 mr-2">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="apply_corrective" value="1">
                                <button type="submit" class="btn btn-danger py-2 px-3 font-weight-bold" onclick="return confirm('Apakah Anda yakin ingin menerapkan tindakan korektif? Sistem akan menghapus berkas ilegal atau mencoba membersihkan muatan payload dari gambar menggunakan GD library.');">
                                    🛠️ Terapkan Tindakan Korektif (Bersihkan Berkas)
                                </button>
                            </form>
                        <?php endif; ?>
                        
                        <a href="<?= amzscannerAdminUrl(['action' => 'print_logs']) ?>" target="_blank" class="btn btn-secondary mr-2 py-2 px-3 font-weight-bold">
                            🖨️ Cetak Laporan
                        </a>
                        <a href="<?= amzscannerAdminUrl(['action' => 'export_excel']) ?>" class="btn btn-success py-2 px-3 font-weight-bold">
                            📊 Ekspor ke Excel
                        </a>
                    </div>
                <?php else: ?>
                    <div class="d-flex align-items-center mb-3">
                        <span class="mr-2" style="font-size: 24px;">✅</span>
                        <div>
                            <h5 class="text-success mb-0 font-weight-bold">Semua berkas bermasalah telah berhasil ditindaklanjuti!</h5>
                            <p class="text-muted mb-0 small">Seluruh ancaman berkas berbahaya telah dibersihkan atau dihapus secara fisik dari server Anda.</p>
                        </div>
                    </div>
                    
                    <div class="d-flex align-items-center flex-wrap gap-2">
                        <a href="<?= amzscannerAdminUrl(['action' => 'print_logs']) ?>" target="_blank" class="btn btn-secondary mr-2 py-2 px-3 font-weight-bold">
                            🖨️ Cetak Laporan
                        </a>
                        <a href="<?= amzscannerAdminUrl(['action' => 'export_excel']) ?>" class="btn btn-success py-2 px-3 font-weight-bold">
                            📊 Ekspor ke Excel
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Findings Table Card -->
        <div class="card border-light shadow-sm">
            <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                <h5 class="mb-0">📋 Detail Temuan Masalah Keamanan</h5>
                <span class="badge badge-light bg-light text-dark font-weight-bold"><?= $problematicCount ?> Temuan</span>
            </div>
            <div class="card-body">
                <div class="mb-3 text-muted small">
                    Menampilkan data ke-<?= ($offset + 1) ?> sampai ke-<?= min($offset + $perPage, $problematicCount) ?> dari <?= $problematicCount ?> temuan bermasalah.
                </div>
                
                <div class="table-responsive">
                    <table class="table table-striped table-bordered table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th style="width: 5%">#</th>
                                <th style="width: 40%">Lokasi Berkas (Relatif)</th>
                                <th style="width: 15%">Tipe MIME</th>
                                <th style="width: 10%; text-align: center;">Status</th>
                                <th style="width: 15%">Keterangan</th>
                                <th style="width: 15%">Tindakan Pembersihan</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($paginatedResults as $i => $r): 
                                $badgeClass = $r['status'] === 'danger' ? 'badge-danger bg-danger' : 'badge-warning bg-warning text-dark';
                                $statusLabel = $r['status'] === 'danger' ? '🚨 Berbahaya' : '⚠️ Error';
                            ?>
                                <tr>
                                    <td><?= $offset + $i + 1 ?></td>
                                    <td><code class="text-dark bg-light p-1 border rounded" style="word-break: break-all;"><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></code></td>
                                    <td><small class="text-muted"><?= htmlspecialchars($r['mime'] ?? '-', ENT_QUOTES, 'UTF-8') ?></small></td>
                                    <td class="text-center">
                                        <span class="badge <?= $badgeClass ?>"><?= $statusLabel ?></span>
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
                                            <span class="badge <?= $actionBadge ?>"><?= htmlspecialchars($r['action_done'], ENT_QUOTES, 'UTF-8') ?></span>
                                        <?php else: ?>
                                            <span class="text-muted small">Terdeteksi (Menunggu Tindakan)</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                    <nav class="mt-3">
                        <ul class="pagination justify-content-center">
                            <?php if ($page > 1): ?>
                                <li class="page-item">
                                    <a class="page-link" href="<?= amzscannerAdminUrl(['page' => 1]) ?>">« Pertama</a>
                                </li>
                                <li class="page-item">
                                    <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $page - 1]) ?>">‹ Sblm</a>
                                </li>
                            <?php endif; ?>
                            
                            <?php
                            $startPage = max(1, $page - 2);
                            $endPage = min($totalPages, $page + 2);
                            for ($p = $startPage; $p <= $endPage; $p++):
                            ?>
                                <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                                    <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $p]) ?>"><?= $p ?></a>
                                </li>
                            <?php endfor; ?>
                            
                            <?php if ($page < $totalPages): ?>
                                <li class="page-item">
                                    <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $page + 1]) ?>">Next ›</a>
                                </li>
                                <li class="page-item">
                                    <a class="page-link" href="<?= amzscannerAdminUrl(['page' => $totalPages]) ?>">Terakhir »</a>
                                </li>
                            <?php endif; ?>
                        </ul>
                    </nav>
                <?php endif; ?>
            </div>
        </div>
    <?php else: ?>
        <div class="alert alert-success border-success text-center py-4 my-4" role="alert">
            <h4 class="alert-heading">🎉 Sistem Aman!</h4>
            <p class="mb-0">Tidak ditemukan berkas mencurigakan atau berbahaya pada direktori <strong><?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></strong>.</p>
        </div>
    <?php endif; ?>
<?php endif; ?>
