<?php
/**
 * AMZ File Scanner & Sanitizer - Admin Menu Controller
 * 
 * SLiMS 9 Bulian Integration
 */

defined('INDEX_AUTH') OR die('Direct access not allowed');

global $dbs, $sysconf;
require_once SB . 'admin/default/session.inc.php';
require_once SB . 'admin/default/session_check.inc.php';

require_once __DIR__ . '/helper.php';

$can_read  = utility::havePrivilege('system', 'r');
$can_write = utility::havePrivilege('system', 'w');

if (!$can_read) {
    die('<div class="alert alert-danger m-3">' . __('You do not have permission to access this module!') . '</div>');
}

// Process write actions & exports
require_once __DIR__ . '/inc/admin_actions.inc.php';

// Flash Messages
$success_msg = '';
$error_msg   = '';

if (!empty($_GET['success'])) {
    $map = [
        'settings_saved'  => __('Pengaturan berhasil disimpan.'),
        'corrective_done' => __('Tindakan korektif berhasil diterapkan! Berkas telah dicadangkan ke folder karantina dan dibersihkan/dihapus dari server.'),
    ];
    $success_msg = $map[$_GET['success']] ?? '';
}
if (!empty($_GET['error'])) {
    $map = [
        'file_delete_failed'  => __('Gagal memproses berkas. Pastikan izin akses file (file permissions) di server mencukupi.'),
        'invalid_delete_path' => __('Akses ditolak! Jalur berkas tidak valid atau berada di luar folder unggahan yang diizinkan.'),
    ];
    $error_msg = $map[$_GET['error']] ?? '';
}
?>

<div class="menuBox mb-3">
    <div class="menuBoxInner systemIcon">
        <div class="per_title">
            <h2>🛡️ <?= __('AMZ File Scanner &amp; Sanitizer') ?></h2>
        </div>
        <div class="sub_section">
            <div class="text-muted small">
                <?= __('Pindai dan bersihkan berkas-berkas berbahaya (web shell, malware, atau skrip ilegal) pada direktori unggahan SLiMS.') ?>
            </div>
        </div>
    </div>
</div>

<div class="container-fluid px-0 py-2">
    <!-- Flash Messages -->
    <?php if ($success_msg): ?>
        <div class="alert alert-success alert-dismissible fade show shadow-sm mb-4" role="alert">
            <strong>✅ <?= __('Berhasil:') ?></strong> <?= htmlspecialchars($success_msg, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>
    <?php if ($error_msg): ?>
        <div class="alert alert-danger alert-dismissible fade show shadow-sm mb-4" role="alert">
            <strong>❌ <?= __('Perhatian:') ?></strong> <?= htmlspecialchars($error_msg, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <!-- Main Scan Dashboard Area -->
    <?php require __DIR__ . '/inc/admin_scan.inc.php'; ?>
</div>
