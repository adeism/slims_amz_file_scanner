<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');
global $dbs, $sysconf;

$settings   = amzscannerLoadSettings();
$targetDir  = $settings['target_dir'] ?? 'images/docs';

$results    = [];
$scanned    = false;

if (isset($_SESSION['amzscanner_current_results'])) {
    $results = $_SESSION['amzscanner_current_results'];
    if (isset($_SESSION['amzscanner_current_meta'])) {
        $targetDir = $_SESSION['amzscanner_current_meta']['target_dir'] ?? $targetDir;
    }
    $scanned = true;
}

$totalFiles     = count($results);
$safeCount      = count(array_filter($results, fn($r) => $r['status'] === 'safe'));
$noticeCount    = count(array_filter($results, fn($r) => $r['status'] === 'notice'));
$dangerCount    = count(array_filter($results, fn($r) => $r['status'] === 'danger'));
$problematic    = array_values(array_filter($results, fn($r) => $r['status'] !== 'safe'));
$problematicCount  = count($problematic);
$resolvedCount  = count(array_filter($problematic, fn($r) => !empty($r['action_done'])));
$unresolvedCount   = $problematicCount - $resolvedCount;

$perPage    = 100;
$totalPages = max(1, (int)ceil($problematicCount / $perPage));
$page       = max(1, min($totalPages, (int)($_GET['page'] ?? 1)));
$offset     = ($page - 1) * $perPage;
$paginated  = array_slice($problematic, $offset, $perPage);
?>

<!-- Scan Config Card -->
<div class="amz-card">
    <div class="card-header bg-primary">⚙️ Pengaturan &amp; Mulai Pemindaian</div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-5">
                <div class="form-group mb-2">
                    <label class="font-weight-bold mb-1">📁 Folder Target</label>
                    <select id="amz_target_dir" class="form-control">
                        <option value="images/docs"    <?= $targetDir === 'images/docs'    ? 'selected' : '' ?>>images/docs — Cover Bibliografi</option>
                        <option value="images/persons" <?= $targetDir === 'images/persons' ? 'selected' : '' ?>>images/persons — Foto Anggota</option>
                        <option value="repository"     <?= $targetDir === 'repository'     ? 'selected' : '' ?>>repository — Lampiran Dokumen</option>
                        <option value="images"         <?= $targetDir === 'images'         ? 'selected' : '' ?>>images — Semua Gambar</option>
                        <option value="files"          <?= $targetDir === 'files'          ? 'selected' : '' ?>>files — Berkas Umum</option>
                    </select>
                </div>
            </div>
            <div class="col-md-4">
                <div class="form-group mb-2">
                    <label class="font-weight-bold mb-1">🔍 Pola Kustom (pisah koma)</label>
                    <input type="text" id="amz_extra_patterns" class="form-control"
                        value="<?= htmlspecialchars($settings['extra_patterns'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                        placeholder="Contoh: c99, webshell">
                </div>
            </div>
            <div class="col-md-3 d-flex align-items-end">
                <button id="amz_start_scan" class="btn btn-primary btn-block font-weight-bold py-2">
                    ⚡ Mulai Pindai Sekarang
                </button>
            </div>
        </div>

        <!-- Active Layers -->
        <div class="mt-3">
            <small class="text-muted font-weight-bold mr-1">Layer Aktif:</small>
            <span class="badge badge-danger mr-1">Layer 1: Signature</span>
            <?php if ($settings['enable_obfuscation_detect'] === '1'): ?><span class="badge badge-warning mr-1">Layer 2: Obfuscation</span><?php endif; ?>
            <?php if ($settings['enable_entropy_analysis'] === '1'): ?><span class="badge badge-info mr-1">Layer 3: Entropy (≥<?= $settings['entropy_threshold'] ?>)</span><?php endif; ?>
            <?php if ($settings['enable_magic_bytes'] === '1'): ?><span class="badge badge-success mr-1">Layer 4: Magic Bytes</span><?php endif; ?>
            <?php if ($settings['enable_polyglot_detect'] === '1'): ?><span class="badge badge-primary mr-1">Layer 5: Polyglot</span><?php endif; ?>
            <?php if ($settings['enable_steganography_hint'] === '1'): ?><span class="badge badge-secondary mr-1">Layer 6: Steganography</span><?php endif; ?>
            <?php if ($settings['enable_heuristic'] === '1'): ?><span class="badge badge-dark mr-1">Layer 7: Heuristic</span><?php endif; ?>
        </div>
    </div>
</div>

<!-- Progress Bar -->
<div id="amz_progress_wrapper" style="display:none;">
    <div class="d-flex align-items-center mb-2">
        <strong id="amz_progress_label" class="mr-auto">Memulai pemindaian...</strong>
        <span id="amz_progress_count" class="text-muted small">0 / 0</span>
    </div>
    <div class="progress mb-2" style="height:20px;">
        <div id="amz_progress_bar" class="progress-bar progress-bar-striped progress-bar-animated"
            role="progressbar" style="width:0%" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
    </div>
    <p id="amz_progress_file" class="text-muted small mb-0">Menghitung berkas...</p>
</div>

<?php if ($scanned): ?>
    <hr>

    <!-- Stat Cards -->
    <div class="row mb-3">
        <div class="col-md-3 mb-2">
            <div class="amz-stat-card" style="border-left: 4px solid #17a2b8;">
                <div class="stat-label">Total Dipindai</div>
                <div class="stat-num text-info"><?= $totalFiles ?></div>
            </div>
        </div>
        <div class="col-md-3 mb-2">
            <div class="amz-stat-card" style="border-left: 4px solid #28a745;">
                <div class="stat-label">Aman</div>
                <div class="stat-num text-success"><?= $safeCount ?></div>
            </div>
        </div>
        <div class="col-md-3 mb-2">
            <div class="amz-stat-card" style="border-left: 4px solid #ffc107;">
                <div class="stat-label">Perhatian</div>
                <div class="stat-num text-warning"><?= $noticeCount ?></div>
            </div>
        </div>
        <div class="col-md-3 mb-2">
            <div class="amz-stat-card" style="border-left: 4px solid #dc3545;">
                <div class="stat-label">Bahaya / Kritis</div>
                <div class="stat-num text-danger"><?= $dangerCount ?></div>
            </div>
        </div>
    </div>

    <?php if ($problematicCount > 0): ?>
        <!-- Action Panel -->
        <div class="amz-card" style="border-left: 4px solid <?= $unresolvedCount > 0 ? '#dc3545' : '#28a745' ?>;">
            <div class="card-body">
                <?php if ($unresolvedCount > 0): ?>
                    <div class="d-flex align-items-center mb-3">
                        <span style="font-size:26px; margin-right:12px;">🚨</span>
                        <div>
                            <h5 class="text-danger font-weight-bold mb-0">Ditemukan <?= $unresolvedCount ?> masalah aktif!</h5>
                            <small class="text-muted">Terapkan tindakan korektif untuk membersihkan atau mengkarantina berkas berbahaya.</small>
                        </div>
                    </div>
                    <div>
                        <?php if ($can_write): ?>
                            <form method="post" action="<?= amzscannerAdminUrl(['tab' => 'scan']) ?>" class="d-inline mr-1">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                <input type="hidden" name="apply_corrective" value="1">
                                <button type="submit" class="btn btn-danger font-weight-bold"
                                    onclick="return confirm('Terapkan tindakan korektif ke <?= $unresolvedCount ?> berkas bermasalah?');">
                                    🛠️ Terapkan Tindakan Korektif
                                </button>
                            </form>
                        <?php endif; ?>
                        <a href="<?= amzscannerAdminUrl(['action' => 'print_logs']) ?>" target="_blank" class="btn btn-secondary mr-1">🖨️ Cetak</a>
                        <a href="<?= amzscannerAdminUrl(['action' => 'export_excel']) ?>" class="btn btn-success">📊 Export Excel</a>
                    </div>
                <?php else: ?>
                    <div class="d-flex align-items-center">
                        <span style="font-size:26px; margin-right:12px;">✅</span>
                        <div>
                            <h5 class="text-success font-weight-bold mb-0">Semua ancaman telah ditangani!</h5>
                            <small class="text-muted">Seluruh berkas berbahaya telah dibersihkan/dikarantina.</small>
                        </div>
                        <div class="ml-auto">
                            <a href="<?= amzscannerAdminUrl(['action' => 'print_logs']) ?>" target="_blank" class="btn btn-secondary mr-1">🖨️ Cetak</a>
                            <a href="<?= amzscannerAdminUrl(['action' => 'export_excel']) ?>" class="btn btn-success">📊 Excel</a>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="amz-card">
            <div class="card-header bg-dark d-flex justify-content-between align-items-center">
                <span>📋 Detail Temuan Bermasalah</span>
                <span class="badge badge-light" style="font-size:10pt;"><?= $problematicCount ?> Temuan</span>
            </div>
            <div class="card-body" style="padding:12px;">
                <p class="text-muted small mb-2">
                    Menampilkan ke-<?= $offset + 1 ?> sampai ke-<?= min($offset + $perPage, $problematicCount) ?> dari <?= $problematicCount ?> temuan.
                </p>
                <div class="table-responsive">
                    <table class="table table-striped table-bordered table-hover table-sm amz-table">
                        <thead class="thead-dark">
                            <tr>
                                <th width="4%">#</th>
                                <th width="35%">Lokasi Berkas</th>
                                <th width="13%">MIME Type</th>
                                <th width="6%" class="text-center">Skor</th>
                                <th width="10%" class="text-center">Level</th>
                                <th width="14%">Layer Terdeteksi</th>
                                <th width="11%">Keterangan</th>
                                <th width="7%">Tindakan</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($paginated as $i => $r):
                                $score = (int)($r['score'] ?? 0);
                                $scoreCls = $score === 0 ? 'score-0' : ($score <= 3 ? 'score-lo' : ($score <= 7 ? 'score-hi' : 'score-cr'));
                                $levelBadge = match(true) {
                                    $score >= 8 => '<span class="threat-badge threat-critical">💀 Kritis</span>',
                                    $score >= 4 => '<span class="threat-badge threat-danger">🚨 Bahaya</span>',
                                    $score >= 1 => '<span class="threat-badge threat-notice">⚠️ Perhatian</span>',
                                    default     => '<span class="threat-badge threat-safe">✅ Aman</span>',
                                };
                                $actionHtml = '<span class="text-muted small">Menunggu</span>';
                                if (!empty($r['action_done'])) {
                                    $isOk = strpos($r['action_done'], 'Gagal') === false;
                                    $cls  = $isOk ? 'badge-success' : 'badge-danger';
                                    $actionHtml = '<span class="badge ' . $cls . '">' . htmlspecialchars($r['action_done'], ENT_QUOTES, 'UTF-8') . '</span>';
                                }
                            ?>
                                <tr>
                                    <td><?= $offset + $i + 1 ?></td>
                                    <td><code class="small" style="word-break:break-all;font-size:8.5pt"><?= htmlspecialchars($r['file'], ENT_QUOTES, 'UTF-8') ?></code></td>
                                    <td><small class="text-muted"><?= htmlspecialchars($r['mime'] ?? '-', ENT_QUOTES, 'UTF-8') ?></small></td>
                                    <td class="text-center"><span class="score-circle <?= $scoreCls ?>"><?= $score ?></span></td>
                                    <td class="text-center"><?= $levelBadge ?></td>
                                    <td>
                                        <?php foreach ($r['layers_triggered'] ?? [] as $lyr): ?>
                                            <span class="layer-badge"><?= htmlspecialchars($lyr, ENT_QUOTES, 'UTF-8') ?></span>
                                        <?php endforeach; ?>
                                    </td>
                                    <td>
                                        <?php if (!empty($r['msgs'])): ?>
                                            <ul class="mb-0 pl-3 small" style="font-size:8.5pt">
                                                <?php foreach (array_slice(array_unique($r['msgs']), 0, 3) as $msg): ?>
                                                    <li><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') ?></li>
                                                <?php endforeach; ?>
                                            </ul>
                                        <?php else: ?><span class="text-muted">—</span><?php endif; ?>
                                    </td>
                                    <td><?= $actionHtml ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                    <nav class="mt-2">
                        <ul class="pagination pagination-sm justify-content-center">
                            <?php if ($page > 1): ?>
                                <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'scan', 'page' => 1]) ?>">«</a></li>
                                <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'scan', 'page' => $page - 1]) ?>">‹</a></li>
                            <?php endif; ?>
                            <?php for ($p = max(1, $page-2); $p <= min($totalPages, $page+2); $p++): ?>
                                <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                                    <a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'scan', 'page' => $p]) ?>"><?= $p ?></a>
                                </li>
                            <?php endfor; ?>
                            <?php if ($page < $totalPages): ?>
                                <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'scan', 'page' => $page + 1]) ?>">›</a></li>
                                <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'scan', 'page' => $totalPages]) ?>">»</a></li>
                            <?php endif; ?>
                        </ul>
                    </nav>
                <?php endif; ?>
            </div>
        </div>

    <?php else: ?>
        <div class="alert alert-success text-center py-4">
            <h4 class="alert-heading">🎉 Sistem Aman!</h4>
            <p class="mb-0">Tidak ditemukan berkas mencurigakan pada direktori <strong><?= htmlspecialchars($targetDir, ENT_QUOTES, 'UTF-8') ?></strong>.</p>
        </div>
    <?php endif; ?>

<?php endif; ?>

<!-- AJAX Chunked Scanner -->
<script>
(function() {
    var btn       = document.getElementById('amz_start_scan');
    var wrapper   = document.getElementById('amz_progress_wrapper');
    var progBar   = document.getElementById('amz_progress_bar');
    var progLabel = document.getElementById('amz_progress_label');
    var progCount = document.getElementById('amz_progress_count');
    var progFile  = document.getElementById('amz_progress_file');
    var baseUrl   = '<?= amzscannerAdminUrl(['action' => 'scan_chunk']) ?>';

    btn.addEventListener('click', function() {
        var targetDir     = document.getElementById('amz_target_dir').value;
        var extraPatterns = document.getElementById('amz_extra_patterns').value;

        btn.disabled = true;
        btn.textContent = '⏳ Memindai...';
        wrapper.style.display = 'block';

        var offset = 0;

        function runBatch() {
            var url = baseUrl + '&target_dir=' + encodeURIComponent(targetDir)
                + '&extra_patterns=' + encodeURIComponent(extraPatterns)
                + '&offset=' + offset;

            fetch(url)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.error) {
                        progLabel.textContent = '❌ Error: ' + data.error;
                        btn.disabled = false; btn.textContent = '⚡ Mulai Pindai Sekarang';
                        return;
                    }
                    var total     = data.total;
                    var processed = data.processed;
                    var pct = total > 0 ? Math.round((processed / total) * 100) : 100;

                    progBar.style.width = pct + '%';
                    progBar.textContent = pct + '%';
                    progBar.setAttribute('aria-valuenow', pct);
                    progCount.textContent = processed + ' / ' + total + ' berkas';
                    progLabel.textContent = 'Memindai... batch ' + Math.ceil(processed / data.batch_size);

                    if (!data.done) {
                        offset = processed;
                        runBatch();
                    } else {
                        progLabel.textContent = '✅ Selesai! Memuat hasil...';
                        progFile.textContent  = total + ' berkas telah dipindai.';
                        setTimeout(function() {
                            window.location.href = '<?= amzscannerAdminUrl(['tab' => 'scan']) ?>';
                        }, 1200);
                    }
                })
                .catch(function(err) {
                    progLabel.textContent = '❌ Kesalahan koneksi. Coba lagi.';
                    btn.disabled = false; btn.textContent = '⚡ Mulai Pindai Sekarang';
                });
        }

        runBatch();
    });
})();
</script>
