<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

define('AMZSCANNER_PLUGIN_DIR', __DIR__);

// ── CSRF Protection ────────────────────────────────────────────────────────
function amzscannerGetCsrfToken(): string {
    if (empty($_SESSION['amzscanner_csrf'])) {
        $_SESSION['amzscanner_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['amzscanner_csrf'];
}

function amzscannerValidateCsrf(): bool {
    $token = $_POST['csrf_token'] ?? '';
    return hash_equals($_SESSION['amzscanner_csrf'] ?? '', $token);
}

// ── Admin URL Helpers ──────────────────────────────────────────────────────
function amzscannerAdminUrl(array $params = []): string {
    $base = defined('AWB') ? AWB . 'plugin_container.php' : 'plugin_container.php';
    $defaults = [
        'mod' => $_GET['mod'] ?? 'system',
        'id'  => $_GET['id'] ?? ''
    ];
    return $base . '?' . http_build_query(array_merge($defaults, $params));
}

function amzscannerRedirect(string $view = '', array $extra = []): string {
    $params = [];
    if ($view !== '') {
        $params['view'] = $view;
    }
    return amzscannerAdminUrl(array_merge($params, $extra));
}

// ── Zero-Migration Settings (JSON Based) ───────────────────────────────────
function amzscannerLoadSettings(): array {
    $path = __DIR__ . '/settings.json';
    $defaults = [
        'target_dir'     => 'images/docs',
        'corrective'     => '0',
        'extra_patterns' => '',
    ];
    if (file_exists($path)) {
        $content = @file_get_contents($path);
        if ($content) {
            $data = json_decode($content, true);
            if (is_array($data)) {
                return array_merge($defaults, $data);
            }
        }
    }
    return $defaults;
}

function amzscannerSaveSetting(string $key, string $value): void {
    $path = __DIR__ . '/settings.json';
    $settings = amzscannerLoadSettings();
    $settings[$key] = $value;
    @file_put_contents($path, json_encode($settings, JSON_PRETTY_PRINT));
}


// ── Path Resolution & Whitelists ───────────────────────────────────────────
function amzscannerAllowedDirs(): array {
    return [
        'images/docs',
        'images/persons',
        'repository',
        'images',
        'files'
    ];
}

function amzscannerIsStrictImageDir(string $dir): bool {
    return in_array($dir, ['images/docs', 'images/persons', 'images'], true);
}

function amzscannerResolvePhysicalPath(string $filePath, string $targetDir): string {
    if ($targetDir === 'all') {
        return SB . $filePath;
    } else {
        return SB . $targetDir . DIRECTORY_SEPARATOR . $filePath;
    }
}

function amzscannerIsValidDeletePath(string $physicalPath): bool {
    $realPath = realpath($physicalPath);
    if ($realPath === false) {
        return false;
    }

    $docRoot = realpath(SB);
    if ($docRoot === false) {
        return false;
    }

    $allowedDirs = amzscannerAllowedDirs();
    $isValid = false;
    foreach ($allowedDirs as $dirKey) {
        $allowedRealPath = realpath(SB . $dirKey);
        if ($allowedRealPath !== false) {
            if (strpos($realPath, $allowedRealPath . DIRECTORY_SEPARATOR) === 0 || $realPath === $allowedRealPath) {
                $isValid = true;
                break;
            }
        }
    }

    return $isValid;
}

// ── Core Scanner Logics ────────────────────────────────────────────────────
function amzscannerAllowedTypes(): array {
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
}

function amzscannerForbiddenPatterns(string $extra = ''): array {
    $base = [
        '<?php', '<?=', '<script', 'eval(', 'base64_decode',
        'system(', 'shell_exec', 'passthru', 'exec(', 'popen(',
        'proc_open', 'assert(', 'preg_replace', '$_POST',
        '$_GET', '$_REQUEST', '$_COOKIE', '$_SERVER',
        'iframe', 'onload', 'onerror'
    ];
    if ($extra !== '') {
        foreach (explode(',', $extra) as $p) {
            $p = trim($p);
            if ($p !== '') {
                $base[] = $p;
            }
        }
    }
    return array_unique($base);
}

function amzscannerGetFilesRecursive(string $dirPath): array {
    $results = [];
    if (!is_dir($dirPath)) return [];
    
    $items = scandir($dirPath);
    if (!$items) return [];

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath = $dirPath . DIRECTORY_SEPARATOR . $item;
        if (is_dir($fullPath)) {
            $results = array_merge($results, amzscannerGetFilesRecursive($fullPath));
        } else {
            $results[] = $fullPath;
        }
    }
    return $results;
}

function amzscannerScanDir(string $dirPath, string $dirKey, array $forbiddenPatterns, bool $corrective): array {
    $allowedTypes  = amzscannerAllowedTypes();
    $excluded      = ['.', '..', 'index.php', 'index.html', '.htaccess'];
    $results       = [];

    if (!is_dir($dirPath)) {
        return [['file' => $dirPath, 'status' => 'error', 'msgs' => ['Direktori tidak ditemukan.']]];
    }

    $allFiles = amzscannerGetFilesRecursive($dirPath);
    $isStrict = amzscannerIsStrictImageDir($dirKey);

    foreach ($allFiles as $fullPath) {
        @set_time_limit(30);
        $filename = basename($fullPath);
        if (in_array($filename, $excluded, true)) continue;

        $relativePath = ltrim(str_replace($dirPath, '', $fullPath), DIRECTORY_SEPARATOR);
        $finfo        = new finfo(FILEINFO_MIME_TYPE);
        $mimeType     = $finfo->file($fullPath);
        $illegal      = false;
        $suspicious   = false;
        $msgs         = [];
        $action_done  = '';

        $ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
        $dangerousExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'sh', 'pl', 'py', 'htaccess'];
        $webXssExts    = ['html', 'htm', 'js'];

        if (in_array($ext, $dangerousExts, true)) {
            $suspicious = true;
            $msgs[]     = 'Berkas executable berbahaya (' . $ext . ')';
        } elseif (in_array($ext, $webXssExts, true)) {
            $suspicious = true;
            $msgs[]     = 'Berkas skrip web XSS (' . $ext . ')';
        }

        if ($isStrict) {
            if (in_array($mimeType, $allowedTypes, true)) {
                $contents = file_get_contents($fullPath);
                foreach ($forbiddenPatterns as $pattern) {
                    if (stripos($contents, $pattern) !== false) {
                        $suspicious = true;
                        $msgs[]     = 'Pola "' . htmlspecialchars($pattern, ENT_QUOTES, 'UTF-8') . '" terdeteksi';
                    }
                }
            } else {
                $illegal = true;
                $msgs[]  = 'Bukan gambar valid (MIME: ' . htmlspecialchars($mimeType, ENT_QUOTES, 'UTF-8') . ')';
            }
        } else {
            $scannableExts = array_merge($dangerousExts, $webXssExts, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt']);
            if (in_array($ext, $scannableExts, true)) {
                $contents = @file_get_contents($fullPath);
                if ($contents !== false) {
                    foreach ($forbiddenPatterns as $pattern) {
                        if (stripos($contents, $pattern) !== false) {
                            $suspicious = true;
                            $msgs[]     = 'Pola "' . htmlspecialchars($pattern, ENT_QUOTES, 'UTF-8') . '" terdeteksi';
                        }
                    }
                }
            }
        }

        $status = ($illegal || $suspicious) ? 'danger' : 'safe';

        if ($corrective && ($illegal || $suspicious)) {
            if ($illegal) {
                @unlink($fullPath);
                $action_done = 'File dihapus';
            } elseif ($suspicious) {
                $rewrote = false;
                if (in_array($mimeType, $allowedTypes, true)) {
                    if ($mimeType === 'image/jpeg') {
                        $img = @imagecreatefromjpeg($fullPath);
                        if ($img) { $rewrote = @imagejpeg($img, $fullPath, 90); imagedestroy($img); }
                    } elseif ($mimeType === 'image/png') {
                        $img = @imagecreatefrompng($fullPath);
                        if ($img) { $rewrote = @imagepng($img, $fullPath, 9); imagedestroy($img); }
                    } elseif ($mimeType === 'image/gif') {
                        $img = @imagecreatefromgif($fullPath);
                        if ($img) { $rewrote = @imagegif($img, $fullPath); imagedestroy($img); }
                    } elseif ($mimeType === 'image/webp') {
                        $img = @imagecreatefromwebp($fullPath);
                        if ($img) { $rewrote = @imagewebp($img, $fullPath, 80); imagedestroy($img); }
                    }
                }
                
                if ($rewrote) {
                    $action_done = 'Gambar dibersihkan';
                } else {
                    @unlink($fullPath);
                    $action_done = 'File dihapus';
                }
            }
        }

        $results[] = [
            'file'        => $relativePath,
            'mime'        => $mimeType,
            'status'      => $status,
            'msgs'        => $msgs,
            'action_done' => $action_done,
        ];
    }
    return $results;
}
