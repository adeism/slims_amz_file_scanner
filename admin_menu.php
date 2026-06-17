<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

global $dbs, $sysconf;
require SB . 'admin/default/session.inc.php';
require SB . 'admin/default/session_check.inc.php';

require_once __DIR__ . '/helper.php';

$can_read  = utility::havePrivilege('system', 'r');
$can_write = utility::havePrivilege('system', 'w');

if (!$can_read) {
    die('<div class="alert alert-danger">' . __('You do not have permission to access this module!') . '</div>');
}

// Handle AJAX / POST / GET actions early
require_once __DIR__ . '/inc/admin_actions.inc.php';

// Determine current tab
$activeTab = $_GET['tab'] ?? 'scan';
$allowedTabs = ['scan', 'settings', 'quarantine', 'logs'];
if (!in_array($activeTab, $allowedTabs, true)) $activeTab = 'scan';

// Flash messages
$success_msg = '';
$error_msg   = '';
$successMap  = [
    'settings_saved'  => 'Pengaturan berhasil disimpan.',
    'corrective_done' => 'Tindakan korektif berhasil diterapkan! Berkas bermasalah telah dibersihkan/dikarantina.',
    'restored'        => 'Berkas berhasil dipulihkan dari karantina.',
    'deleted'         => 'Berkas berhasil dihapus permanen dari karantina.',
    'log_pruned'      => 'Log lama berhasil dibersihkan.',
];
$errorMap = [
    'restore_failed'      => 'Gagal memulihkan berkas dari karantina.',
    'delete_failed'       => 'Gagal menghapus berkas karantina.',
    'invalid_delete_path' => 'Akses ditolak! Jalur berkas tidak valid atau di luar whitelist keamanan.',
    'csrf_error'          => 'Token keamanan tidak valid. Silakan muat ulang halaman dan coba lagi.',
];
if (!empty($_GET['success'])) $success_msg = $successMap[$_GET['success']] ?? '';
if (!empty($_GET['error']))   $error_msg   = $errorMap[$_GET['error']] ?? '';

function amzscannerTabUrl(string $tab): string {
    return amzscannerAdminUrl(['tab' => $tab]);
}
?>

<style>
/* ─── AMZ Scanner v2.0 Custom Styles (Bootstrap 4 Compatible) ─── */
.amz-header {
    background: linear-gradient(135deg, #004db6 0%, #0072ff 100%);
    color: #fff;
    padding: 18px 24px;
    border-radius: 6px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.amz-header h3 { margin: 0; font-weight: 700; font-size: 16pt; }
.amz-header .amz-version { font-size: 9pt; opacity: 0.8; margin-top: 3px; }
.amz-tabs .nav-link {
    color: #555;
    font-weight: bold;
    padding: 10px 18px;
    border-radius: 0;
    border-bottom: 3px solid transparent;
    transition: all .2s;
}
.amz-tabs .nav-link:hover { color: #004db6; background: #f0f5ff; }
.amz-tabs .nav-link.active {
    color: #004db6;
    border-bottom: 3px solid #004db6;
    background: #fff;
}
.amz-card { border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 20px; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.amz-card .card-header { padding: 12px 18px; border-bottom: 1px solid #e8e8e8; border-radius: 6px 6px 0 0; font-weight: bold; font-size: 11pt; }
.amz-card .card-body { padding: 18px; }
.amz-card .card-header.bg-primary { background: #004db6 !important; color: #fff; }
.amz-card .card-header.bg-dark { background: #222 !important; color: #fff; }
.amz-card .card-header.bg-secondary { background: #6c757d !important; color: #fff; }
.amz-stat-card { border-radius: 6px; padding: 18px; text-align: center; border: 1px solid #e0e0e0; }
.amz-stat-card .stat-num { font-size: 26pt; font-weight: 700; margin: 4px 0 0; line-height: 1; }
.amz-stat-card .stat-label { font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; color: #888; margin-bottom: 4px; }
.amz-toggle-row { border: 1px solid #e8e8e8; border-radius: 6px; padding: 14px 16px; margin-bottom: 10px; background: #fafafa; }
.amz-toggle-row.always-on { background: #f0fff4; border-color: #b7e4c7; }
.amz-toggle-row .toggle-title { font-weight: bold; font-size: 10.5pt; margin-bottom: 3px; }
.amz-toggle-row .toggle-desc { font-size: 9pt; color: #777; margin: 0; }
.form-check-input[type=checkbox] { cursor: pointer; }
/* Progress bar */
#amz_progress_wrapper { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 16px; margin-bottom: 18px; }
/* Table enhancements */
.amz-table th { font-size: 9pt; text-transform: uppercase; letter-spacing: .5px; }
.amz-table td { font-size: 9.5pt; vertical-align: middle; }
.threat-badge { display: inline-block; padding: 3px 8px; border-radius: 20px; font-size: 8.5pt; font-weight: bold; }
.threat-safe     { background: #d4edda; color: #155724; }
.threat-notice   { background: #fff3cd; color: #856404; }
.threat-danger   { background: #f8d7da; color: #721c24; }
.threat-critical { background: #222; color: #fff; }
/* Score circle */
.score-circle { display: inline-block; width: 32px; height: 32px; border-radius: 50%; text-align: center; line-height: 32px; font-weight: 700; font-size: 10pt; }
.score-0  { background: #d4edda; color: #155724; }
.score-lo { background: #fff3cd; color: #856404; }
.score-hi { background: #f8d7da; color: #721c24; }
.score-cr { background: #222; color: #fff; }
/* Quarantine table */
.q-row-critical td { background: #fff5f5 !important; }
.layer-badge { display: inline-block; background: #e9ecef; color: #444; border-radius: 3px; font-size: 8pt; padding: 2px 6px; margin: 1px; }
</style>

<div class="container-fluid" style="padding: 15px;">

    <!-- Plugin Header -->
    <div class="amz-header">
        <div>
            <h3>🛡️ AMZ File Scanner &amp; Sanitizer</h3>
            <div class="amz-version">v<?= AMZSCANNER_VERSION ?> — Mesin Keamanan Multi-Lapis (7 Layer)</div>
        </div>
        <div style="text-align:right; font-size:9pt; opacity:.85; line-height:1.6;">
            <?php $settings = amzscannerLoadSettings(); ?>
            <?php if ($settings['enable_realtime_scan'] === '1'): ?>
                <span style="background:rgba(255,255,255,.2); padding:4px 10px; border-radius:20px;">⚡ Real-time: AKTIF</span>
            <?php else: ?>
                <span style="background:rgba(0,0,0,.2); padding:4px 10px; border-radius:20px;">⚡ Real-time: Nonaktif</span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Flash Messages -->
    <?php if ($success_msg): ?>
        <div class="alert alert-success alert-dismissible" role="alert">
            <strong>✅ Berhasil!</strong> <?= htmlspecialchars($success_msg, ENT_QUOTES, 'UTF-8') ?>
            <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
        </div>
    <?php endif; ?>
    <?php if ($error_msg): ?>
        <div class="alert alert-danger alert-dismissible" role="alert">
            <strong>❌ Error!</strong> <?= htmlspecialchars($error_msg, ENT_QUOTES, 'UTF-8') ?>
            <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
        </div>
    <?php endif; ?>

    <!-- Tab Navigation -->
    <ul class="nav nav-tabs amz-tabs mb-3" style="border-bottom: 2px solid #e0e0e0;">
        <li class="nav-item">
            <a class="nav-link <?= $activeTab === 'scan' ? 'active' : '' ?>" href="<?= amzscannerTabUrl('scan') ?>">
                🔍 Pemindaian
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $activeTab === 'quarantine' ? 'active' : '' ?>" href="<?= amzscannerTabUrl('quarantine') ?>">
                🔒 Karantina
                <?php
                $qi = amzscannerLoadQuarantineIndex();
                if (count($qi) > 0): ?>
                    <span class="badge badge-warning ml-1"><?= count($qi) ?></span>
                <?php endif; ?>
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $activeTab === 'logs' ? 'active' : '' ?>" href="<?= amzscannerTabUrl('logs') ?>">
                📋 Log Audit
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $activeTab === 'settings' ? 'active' : '' ?>" href="<?= amzscannerTabUrl('settings') ?>">
                ⚙️ Pengaturan
            </a>
        </li>
    </ul>

    <!-- Tab Content -->
    <?php if ($activeTab === 'scan'): ?>
        <?php require __DIR__ . '/inc/admin_scan.inc.php'; ?>
    <?php elseif ($activeTab === 'quarantine'): ?>
        <?php require __DIR__ . '/inc/admin_quarantine.inc.php'; ?>
    <?php elseif ($activeTab === 'logs'): ?>
        <?php require __DIR__ . '/inc/admin_logs.inc.php'; ?>
    <?php elseif ($activeTab === 'settings'): ?>
        <?php require __DIR__ . '/inc/admin_settings.inc.php'; ?>
    <?php endif; ?>

</div>
