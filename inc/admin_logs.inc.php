<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

$logs = amzscannerLoadLogs();
$logTotal = count($logs);

$filterAction = $_GET['filter_action'] ?? '';
$filterDate   = $_GET['filter_date'] ?? '';

$filtered = $logs;
if ($filterAction !== '') {
    $filtered = array_filter($filtered, fn($e) => ($e['action'] ?? '') === $filterAction);
}
if ($filterDate !== '') {
    $filtered = array_filter($filtered, fn($e) => str_starts_with($e['timestamp'] ?? '', $filterDate));
}
$filtered = array_values($filtered);
$filteredTotal = count($filtered);

$perPage    = 50;
$totalPages = max(1, (int)ceil($filteredTotal / $perPage));
$page       = max(1, min($totalPages, (int)($_GET['page'] ?? 1)));
$offset     = ($page - 1) * $perPage;
$paginated  = array_slice($filtered, $offset, $perPage);

$actionLabels = [
    'upload_blocked'   => ['🚫 Upload Diblokir', 'danger'],
    'quarantine'       => ['🔒 Karantina', 'warning'],
    'clean'            => ['🧹 Dibersihkan', 'success'],
    'delete'           => ['🗑️ Dihapus', 'danger'],
    'delete_permanent' => ['💀 Hapus Permanen', 'dark'],
    'restore'          => ['♻️ Dipulihkan', 'primary'],
    'scan'             => ['🔍 Scan', 'info'],
];

$uploadBlocked = count(array_filter($logs, fn($e) => ($e['action'] ?? '') === 'upload_blocked'));
$quarantined   = count(array_filter($logs, fn($e) => ($e['action'] ?? '') === 'quarantine'));
$restored      = count(array_filter($logs, fn($e) => ($e['action'] ?? '') === 'restore'));
$deleted       = count(array_filter($logs, fn($e) => in_array($e['action'] ?? '', ['delete', 'delete_permanent'])));
$uniqueActions = array_unique(array_column($logs, 'action'));
?>

<!-- Header + Buttons -->
<div class="d-flex justify-content-between align-items-center mb-3">
    <h5 class="font-weight-bold mb-0">📋 Log Audit Keamanan</h5>
    <div>
        <a href="<?= amzscannerAdminUrl(['action' => 'export_log_csv']) ?>" class="btn btn-success btn-sm font-weight-bold mr-1">
            📥 Export CSV
        </a>
        <?php if ($can_write): ?>
            <button class="btn btn-outline-secondary btn-sm font-weight-bold" data-toggle="collapse" data-target="#pruneForm">
                🗑️ Bersihkan Log Lama
            </button>
        <?php endif; ?>
    </div>
</div>

<!-- Prune Form -->
<?php if ($can_write): ?>
    <div class="collapse mb-3" id="pruneForm">
        <div class="amz-card" style="border-left: 3px solid #ffc107;">
            <div class="card-body py-2">
                <form method="post" action="<?= amzscannerAdminUrl(['tab' => 'logs']) ?>" class="form-inline">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="prune_logs">
                    <label class="font-weight-bold mr-2 mb-0">Hapus log lebih dari:</label>
                    <select name="prune_days" class="form-control form-control-sm mr-2">
                        <option value="30">30 hari</option>
                        <option value="60">60 hari</option>
                        <option value="90" selected>90 hari</option>
                        <option value="180">180 hari</option>
                        <option value="365">1 tahun</option>
                    </select>
                    <button type="submit" class="btn btn-warning btn-sm font-weight-bold"
                        onclick="return confirm('Hapus semua log yang lebih lama dari pilihan? Tidak dapat dibatalkan.')">
                        Bersihkan Sekarang
                    </button>
                </form>
            </div>
        </div>
    </div>
<?php endif; ?>

<!-- Summary Stats -->
<div class="row mb-3">
    <div class="col-md-3 col-6 mb-2">
        <div class="amz-stat-card" style="border-left:4px solid #6c757d;">
            <div class="stat-label">Total Log</div>
            <div class="stat-num text-dark"><?= $logTotal ?></div>
        </div>
    </div>
    <div class="col-md-3 col-6 mb-2">
        <div class="amz-stat-card" style="border-left:4px solid #dc3545;">
            <div class="stat-label">Upload Diblokir</div>
            <div class="stat-num text-danger"><?= $uploadBlocked ?></div>
        </div>
    </div>
    <div class="col-md-3 col-6 mb-2">
        <div class="amz-stat-card" style="border-left:4px solid #ffc107;">
            <div class="stat-label">Dikarantina</div>
            <div class="stat-num text-warning"><?= $quarantined ?></div>
        </div>
    </div>
    <div class="col-md-3 col-6 mb-2">
        <div class="amz-stat-card" style="border-left:4px solid #28a745;">
            <div class="stat-label">Dipulihkan</div>
            <div class="stat-num text-success"><?= $restored ?></div>
        </div>
    </div>
</div>

<!-- Filter Bar -->
<div class="amz-card mb-3">
    <div class="card-body py-2 px-3">
        <form method="get" action="<?= amzscannerAdminUrl(['tab' => 'logs']) ?>" class="form-inline">
            <input type="hidden" name="mod" value="<?= htmlspecialchars($_GET['mod'] ?? 'system', ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="id"  value="<?= htmlspecialchars($_GET['id']  ?? '',       ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="tab" value="logs">
            <label class="font-weight-bold mr-2 mb-0">🔍 Filter:</label>
            <select name="filter_action" class="form-control form-control-sm mr-2">
                <option value="">— Semua Tindakan —</option>
                <?php foreach ($uniqueActions as $act): ?>
                    <option value="<?= htmlspecialchars($act, ENT_QUOTES, 'UTF-8') ?>" <?= $filterAction === $act ? 'selected' : '' ?>>
                        <?= htmlspecialchars($actionLabels[$act][0] ?? ucfirst($act), ENT_QUOTES, 'UTF-8') ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <input type="date" name="filter_date" class="form-control form-control-sm mr-2"
                value="<?= htmlspecialchars($filterDate, ENT_QUOTES, 'UTF-8') ?>">
            <button type="submit" class="btn btn-primary btn-sm font-weight-bold mr-1">Filter</button>
            <?php if ($filterAction || $filterDate): ?>
                <a href="<?= amzscannerAdminUrl(['tab' => 'logs']) ?>" class="btn btn-outline-secondary btn-sm">✕ Reset</a>
            <?php endif; ?>
            <span class="text-muted small ml-auto"><?= $filteredTotal ?> entri ditemukan</span>
        </form>
    </div>
</div>

<?php if (empty($paginated)): ?>
    <div class="alert alert-info text-center">Tidak ada entri log yang sesuai filter.</div>
<?php else: ?>

    <div class="amz-card">
        <div class="card-body" style="padding:12px;">
            <div class="table-responsive">
                <table class="table table-striped table-bordered table-hover table-sm amz-table">
                    <thead class="thead-dark">
                        <tr>
                            <th width="4%">#</th>
                            <th width="13%">Waktu</th>
                            <th width="11%">Tindakan</th>
                            <th width="18%">Nama Berkas</th>
                            <th width="6%" class="text-center">Skor</th>
                            <th width="16%">Layer Terdeteksi</th>
                            <th width="20%">Keterangan</th>
                            <th width="8%">Admin</th>
                            <th width="8%">IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($paginated as $i => $entry):
                            $action = $entry['action'] ?? '';
                            [$actionLabel, $actionColor] = $actionLabels[$action] ?? [ucfirst($action), 'secondary'];
                            $score = (int)($entry['score'] ?? 0);
                            $scoreCls = $score === 0 ? 'score-0' : ($score <= 3 ? 'score-lo' : ($score <= 7 ? 'score-hi' : 'score-cr'));
                        ?>
                            <tr>
                                <td><?= $offset + $i + 1 ?></td>
                                <td><small style="font-size:8.5pt;"><?= htmlspecialchars($entry['timestamp'] ?? '—', ENT_QUOTES, 'UTF-8') ?></small></td>
                                <td><span class="badge badge-<?= $actionColor ?>"><?= $actionLabel ?></span></td>
                                <td><code class="small" style="font-size:8.5pt;word-break:break-all;"><?= htmlspecialchars($entry['filename'] ?? '—', ENT_QUOTES, 'UTF-8') ?></code></td>
                                <td class="text-center">
                                    <?php if ($score > 0): ?>
                                        <span class="score-circle <?= $scoreCls ?>"><?= $score ?></span>
                                    <?php else: ?>
                                        <span class="text-muted">—</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php foreach ($entry['layers'] ?? [] as $lyr): ?>
                                        <span class="layer-badge"><?= htmlspecialchars($lyr, ENT_QUOTES, 'UTF-8') ?></span>
                                    <?php endforeach; ?>
                                </td>
                                <td><small class="text-muted" style="font-size:8.5pt;"><?= htmlspecialchars(implode(' | ', array_slice($entry['msgs'] ?? [], 0, 2)), ENT_QUOTES, 'UTF-8') ?></small></td>
                                <td><small class="text-muted"><?= htmlspecialchars($entry['actor'] ?? '—', ENT_QUOTES, 'UTF-8') ?></small></td>
                                <td><small class="text-muted"><?= htmlspecialchars($entry['ip'] ?? '—', ENT_QUOTES, 'UTF-8') ?></small></td>
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
                            <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'logs', 'page' => 1, 'filter_action' => $filterAction, 'filter_date' => $filterDate]) ?>">«</a></li>
                            <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'logs', 'page' => $page - 1, 'filter_action' => $filterAction, 'filter_date' => $filterDate]) ?>">‹</a></li>
                        <?php endif; ?>
                        <?php for ($p = max(1, $page-2); $p <= min($totalPages, $page+2); $p++): ?>
                            <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                                <a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'logs', 'page' => $p, 'filter_action' => $filterAction, 'filter_date' => $filterDate]) ?>"><?= $p ?></a>
                            </li>
                        <?php endfor; ?>
                        <?php if ($page < $totalPages): ?>
                            <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'logs', 'page' => $page + 1, 'filter_action' => $filterAction, 'filter_date' => $filterDate]) ?>">›</a></li>
                            <li class="page-item"><a class="page-link" href="<?= amzscannerAdminUrl(['tab' => 'logs', 'page' => $totalPages, 'filter_action' => $filterAction, 'filter_date' => $filterDate]) ?>">»</a></li>
                        <?php endif; ?>
                    </ul>
                </nav>
                <p class="text-muted small text-center mb-0">Halaman <?= $page ?> dari <?= $totalPages ?></p>
            <?php endif; ?>
        </div>
    </div>

<?php endif; ?>
