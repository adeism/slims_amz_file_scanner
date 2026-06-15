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

// Actions controller
require_once __DIR__ . '/inc/admin_actions.inc.php';

// Flash messages
$success_msg = '';
$error_msg   = '';

if (!empty($_GET['success'])) {
    $map = [
        'settings_saved'  => 'Pengaturan berhasil disimpan.',
        'corrective_done' => 'Tindakan korektif berhasil diterapkan! Berkas bermasalah telah dibersihkan atau dihapus dari server.',
    ];
    $success_msg = $map[$_GET['success']] ?? '';
}
if (!empty($_GET['error'])) {
    $map = [
        'file_delete_failed'  => 'Gagal menghapus berkas. Pastikan hak akses file (permission) di server mencukupi.',
        'invalid_delete_path' => 'Akses ditolak! Jalur berkas tidak valid atau di luar whitelist keamanan.',
    ];
    $error_msg = $map[$_GET['error']] ?? '';
}
?>

<div class="container-fluid py-2">
    <!-- Header Title -->
    <div class="d-flex align-items-center mb-3">
        <h3 class="text-dark mb-0">🛡️ AMZ File Scanner</h3>
    </div>

    <!-- Flash Messages -->
    <?php if ($success_msg): ?>
        <div class="alert alert-success" role="alert">
            <?= htmlspecialchars($success_msg, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>
    <?php if ($error_msg): ?>
        <div class="alert alert-danger" role="alert">
            <?= htmlspecialchars($error_msg, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <!-- Main Content Area (Single Page) -->
    <?php require __DIR__ . '/inc/admin_scan.inc.php'; ?>
</div>
