<?php
/**
 * Plugin Name: AMZ File Scanner & Sanitizer
 * Plugin URI: https://github.com/adeism/slims_amz_file_scanner
 * Description: Mesin keamanan multi-lapis (7 Layer) untuk memindai, mendeteksi, dan membersihkan berkas berbahaya (PHP web shells, malware tersamar/obfuscated, polyglot files, dan skrip tersembunyi) dari folder unggahan SLiMS. Dilengkapi intersepsi upload real-time, sistem karantina aman, analisis entropi Shannon, deteksi magic bytes, dan log audit keamanan.
 * Version: 2.0.0
 * Author: Ade Ismail Siregar
 */

defined('INDEX_AUTH') OR die('Direct access not allowed');

require_once __DIR__ . '/helper.php';

$plugin = \SLiMS\Plugins::getInstance();

// Register main admin menu under System module
$plugin->registerMenu('system', '🛡️ AMZ File Scanner', __DIR__ . '/admin_menu.php');

// ── Real-time Upload Interception via SLiMS Hooks ──────────────────────────
// These hooks intercept file uploads BEFORE they are saved to the server.
// Only active when 'enable_realtime_scan' = '1' in settings.

$_amzSettings = amzscannerLoadSettings();

if ($_amzSettings['enable_realtime_scan'] === '1') {

    /**
     * Hook: bibliography_before_save
     * Fires before a new bibliography entry is saved.
     * Scans cover image and attached repository file.
     */
    $plugin->register(\SLiMS\Plugins::BIBLIOGRAPHY_BEFORE_SAVE, function() use ($_amzSettings) {
        amzscannerInterceptUploads($_amzSettings);
    });

    /**
     * Hook: bibliography_before_update
     * Fires before an existing bibliography entry is updated.
     */
    $plugin->register(\SLiMS\Plugins::BIBLIOGRAPHY_BEFORE_UPDATE, function() use ($_amzSettings) {
        amzscannerInterceptUploads($_amzSettings);
    });

    /**
     * Hook: membership_before_save
     * Fires before a new member is saved.
     * Scans member photo uploads.
     */
    $plugin->register(\SLiMS\Plugins::MEMBERSHIP_BEFORE_SAVE, function() use ($_amzSettings) {
        amzscannerInterceptUploads($_amzSettings);
    });

    /**
     * Hook: membership_before_update
     * Fires before an existing member is updated.
     */
    $plugin->register(\SLiMS\Plugins::MEMBERSHIP_BEFORE_UPDATE, function() use ($_amzSettings) {
        amzscannerInterceptUploads($_amzSettings);
    });
}

// ── Upload Interception Handler ────────────────────────────────────────────

/**
 * Scan all files in $_FILES using the multi-layer engine.
 * If any file is dangerous, terminate the request with an error message.
 *
 * @param array $settings Loaded plugin settings
 */
function amzscannerInterceptUploads(array $settings): void {
    if (empty($_FILES)) return;

    $blocked = [];

    foreach ($_FILES as $fieldName => $fileData) {
        // Handle both single and multiple file uploads
        $files = [];
        if (is_array($fileData['name'])) {
            foreach ($fileData['name'] as $i => $name) {
                if (!empty($name) && $fileData['error'][$i] === UPLOAD_ERR_OK) {
                    $files[] = ['name' => $name, 'tmp_name' => $fileData['tmp_name'][$i]];
                }
            }
        } else {
            if (!empty($fileData['name']) && $fileData['error'] === UPLOAD_ERR_OK) {
                $files[] = ['name' => $fileData['name'], 'tmp_name' => $fileData['tmp_name']];
            }
        }

        foreach ($files as $file) {
            if (!file_exists($file['tmp_name'])) continue;
            $scanResult = amzscannerScanUploadedFile($file['tmp_name'], $file['name'], $settings);
            if (!$scanResult['safe']) {
                $blocked[] = [
                    'name'   => htmlspecialchars($file['name'], ENT_QUOTES, 'UTF-8'),
                    'score'  => $scanResult['score'],
                    'msgs'   => $scanResult['msgs'],
                    'layers' => $scanResult['layers'],
                ];
                // Remove the dangerous tmp file immediately
                @unlink($file['tmp_name']);
            }
        }
    }

    if (!empty($blocked)) {
        // Build a human-readable error message
        $errorHtml = '<div class="alert alert-danger" style="border-left: 4px solid #dc3545; padding: 15px;">';
        $errorHtml .= '<h5>🛡️ AMZ File Scanner — Unggahan Diblokir!</h5>';
        $errorHtml .= '<p>Sistem mendeteksi berkas berbahaya dalam unggahan Anda. Proses penyimpanan dibatalkan.</p>';
        $errorHtml .= '<ul>';
        foreach ($blocked as $b) {
            $errorHtml .= '<li><strong>' . $b['name'] . '</strong> (Skor Bahaya: ' . $b['score'] . ')<br>';
            $errorHtml .= '<small>' . implode(', ', array_map(fn($m) => htmlspecialchars($m, ENT_QUOTES, 'UTF-8'), $b['msgs'])) . '</small></li>';
        }
        $errorHtml .= '</ul>';
        $errorHtml .= '<small>Log kejadian ini telah dicatat dalam AMZ Security Log.</small>';
        $errorHtml .= '</div>';

        // Terminate the request and display error
        die($errorHtml);
    }
}
