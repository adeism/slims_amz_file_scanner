<?php
/**
 * AMZ File Scanner & Sanitizer - Helper Functions
 * 
 * Hardened & Enhanced for SLiMS 9 Bulian
 */

defined('INDEX_AUTH') OR die('Direct access not allowed');

define('AMZSCANNER_PLUGIN_DIR', __DIR__);

// ── Path Normalization Helper ──────────────────────────────────────────────
function amzscannerNormalizePath(string $path): string {
    $path = str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $path);
    return rtrim($path, DIRECTORY_SEPARATOR);
}

// ── CSRF Protection ────────────────────────────────────────────────────────
function amzscannerGetCsrfToken(): string {
    if (empty($_SESSION['amzscanner_csrf'])) {
        $_SESSION['amzscanner_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['amzscanner_csrf'];
}

function amzscannerValidateCsrf(): bool {
    $token = $_POST['csrf_token'] ?? '';
    return !empty($token) && hash_equals($_SESSION['amzscanner_csrf'] ?? '', $token);
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

// ── Configuration Settings ─────────────────────────────────────────────────
function amzscannerLoadSettings(): array {
    $defaults = [
        'target_dir'     => 'images/docs',
        'quarantine'     => '1',
        'extra_patterns' => '',
    ];

    // Priority 1: Check from SLiMS setting if available
    if (class_exists('utility') && method_exists('utility', 'loadSettings')) {
        $dbSetting = @utility::loadSettings('amzscanner_config');
        if (!empty($dbSetting) && is_array($dbSetting)) {
            return array_merge($defaults, $dbSetting);
        }
    }

    // Priority 2: Fallback to local settings.json
    $path = __DIR__ . '/settings.json';
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
    $settings = amzscannerLoadSettings();
    $settings[$key] = $value;

    // Save to settings.json
    $path = __DIR__ . '/settings.json';
    @file_put_contents($path, json_encode($settings, JSON_PRETTY_PRINT));
}

// ── Whitelist & Path Validation ────────────────────────────────────────────
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

function amzscannerDangerousExtensions(): array {
    return [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'phar',
        'sh', 'pl', 'py', 'cgi', 'asp', 'aspx', 'jsp', 'jspx', 'exe', 'bat', 'cmd',
        'vbs', 'ps1', 'shtml', 'pht'
    ];
}

function amzscannerWebXssExtensions(): array {
    return ['html', 'htm', 'js', 'svg'];
}

function amzscannerAllowedTypes(): array {
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
}

function amzscannerResolvePhysicalPath(string $filePath, string $targetDir): string {
    $normTarget = amzscannerNormalizePath(SB . $targetDir);
    $normFile   = amzscannerNormalizePath($filePath);

    // If $filePath already contains $normTarget (due to absolute path formatting)
    if (strpos($normFile, $normTarget) === 0) {
        return $normFile;
    }
    return $normTarget . DIRECTORY_SEPARATOR . ltrim($normFile, DIRECTORY_SEPARATOR);
}

function amzscannerIsValidDeletePath(string $physicalPath): bool {
    $realPath = realpath($physicalPath);
    if ($realPath === false) {
        // In case file was already removed
        return false;
    }

    $docRoot = realpath(SB);
    if ($docRoot === false) {
        return false;
    }

    $allowedDirs = amzscannerAllowedDirs();
    foreach ($allowedDirs as $dirKey) {
        $allowedRealPath = realpath(SB . $dirKey);
        if ($allowedRealPath !== false) {
            $allowedWithSep = rtrim($allowedRealPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($realPath, $allowedWithSep) === 0 || $realPath === $allowedRealPath) {
                return true;
            }
        }
    }

    return false;
}

// ── Quarantine Backup System ───────────────────────────────────────────────
function amzscannerGetQuarantineDir(): string {
    $dir = amzscannerNormalizePath(SB . 'files' . DIRECTORY_SEPARATOR . 'quarantine');
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    // Secure quarantine directory with .htaccess and index.html
    $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "<IfModule !authz_core_module>\n  Order allow,deny\n  Deny from all\n</IfModule>\n<IfModule authz_core_module>\n  Require all denied\n</IfModule>\n");
    }
    $indexHtml = $dir . DIRECTORY_SEPARATOR . 'index.html';
    if (!file_exists($indexHtml)) {
        @file_put_contents($indexHtml, '<!-- Access Denied -->');
    }
    return $dir;
}

function amzscannerQuarantineFile(string $sourcePath): bool {
    if (!file_exists($sourcePath)) return false;
    
    $quarantineDir = amzscannerGetQuarantineDir();
    $subDir = $quarantineDir . DIRECTORY_SEPARATOR . date('Ymd');
    if (!is_dir($subDir)) {
        @mkdir($subDir, 0755, true);
    }

    $filename = basename($sourcePath);
    $dest = $subDir . DIRECTORY_SEPARATOR . date('His') . '_' . $filename . '.bak';
    return @copy($sourcePath, $dest);
}

// ── Core Image Sanitizer (GD) ──────────────────────────────────────────────
function amzscannerSanitizeImage(string $filePath, string $mimeType): bool {
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    $dangerousExts = amzscannerDangerousExtensions();

    // If extension is dangerous executable, NEVER rewrite as image, treat as malicious
    if (in_array($ext, $dangerousExts, true)) {
        return false;
    }

    $rewrote = false;
    if ($mimeType === 'image/jpeg') {
        $img = @imagecreatefromjpeg($filePath);
        if ($img) {
            $rewrote = @imagejpeg($img, $filePath, 90);
            imagedestroy($img);
        }
    } elseif ($mimeType === 'image/png') {
        $img = @imagecreatefrompng($filePath);
        if ($img) {
            // Preserve alpha channel transparency
            imagealphablending($img, false);
            imagesavealpha($img, true);
            $rewrote = @imagepng($img, $filePath, 6);
            imagedestroy($img);
        }
    } elseif ($mimeType === 'image/gif') {
        $img = @imagecreatefromgif($filePath);
        if ($img) {
            $rewrote = @imagegif($img, $filePath);
            imagedestroy($img);
        }
    } elseif ($mimeType === 'image/webp' && function_exists('imagecreatefromwebp')) {
        $img = @imagecreatefromwebp($filePath);
        if ($img) {
            imagealphablending($img, false);
            imagesavealpha($img, true);
            $rewrote = @imagewebp($img, $filePath, 85);
            imagedestroy($img);
        }
    }

    return $rewrote;
}

// ── Malware Signatures & Pattern Detection ─────────────────────────────────
function amzscannerForbiddenPatterns(string $extra = ''): array {
    $base = [
        '<?php', '<?=', '<script', 'eval(', 'base64_decode',
        'system(', 'shell_exec', 'passthru', 'exec(', 'popen(',
        'proc_open', 'assert(', 'preg_replace', '$_POST',
        '$_GET', '$_REQUEST', '$_COOKIE', '$_SERVER',
        'iframe', 'onload=', 'onerror=', 'document.cookie',
        'phpinfo()', 'curl_exec', 'fsockopen', 'pfsockopen',
        'gzinflate', 'str_rot13', 'eval(gzinflate', 'eval(base64_decode'
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

// Memory-safe stream reader for scanning pattern in file
function amzscannerFileContainsPattern(string $filePath, array $patterns, int $maxBytes = 2097152): array {
    $matched = [];
    $handle = @fopen($filePath, 'rb');
    if (!$handle) {
        return [];
    }

    $buffer = '';
    $bytesRead = 0;
    $chunkSize = 65536; // 64KB chunks

    while (!feof($handle) && $bytesRead < $maxBytes) {
        $chunk = fread($handle, $chunkSize);
        if ($chunk === false) break;
        $bytesRead += strlen($chunk);
        $searchBuffer = $buffer . $chunk;

        foreach ($patterns as $p) {
            if (!in_array($p, $matched, true) && stripos($searchBuffer, $p) !== false) {
                $matched[] = $p;
            }
        }

        // Keep last 512 bytes for overlapping patterns
        $buffer = substr($chunk, -512);
    }
    fclose($handle);
    return $matched;
}

// Inspect .htaccess files for malicious override directives
function amzscannerInspectHtaccess(string $filePath): array {
    $dangerousDirectives = [
        'addtype', 'sethandler', 'php_value', 'php_flag',
        'auto_prepend_file', 'auto_append_file', 'allow from all'
    ];
    $findings = [];
    $content = @file_get_contents($filePath);
    if ($content !== false) {
        foreach ($dangerousDirectives as $directive) {
            if (stripos($content, $directive) !== false) {
                $findings[] = 'Direktif berbahaya .htaccess (' . htmlspecialchars($directive, ENT_QUOTES, 'UTF-8') . ')';
            }
        }
    }
    return $findings;
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

// ── Directory Scanner Engine ───────────────────────────────────────────────
function amzscannerScanDir(string $dirPath, string $dirKey, array $forbiddenPatterns, bool $corrective = false): array {
    $allowedTypes  = amzscannerAllowedTypes();
    $dangerousExts = amzscannerDangerousExtensions();
    $webXssExts    = amzscannerWebXssExtensions();
    
    $normDirPath = amzscannerNormalizePath($dirPath);
    
    if (!is_dir($normDirPath)) {
        return [
            'stats' => ['total' => 0, 'safe' => 0, 'danger' => 1, 'error' => 1],
            'findings' => [[
                'file'        => $dirKey,
                'mime'        => 'N/A',
                'status'      => 'error',
                'msgs'        => ['Direktori tidak ditemukan atau tidak dapat diakses.'],
                'action_done' => ''
            ]]
        ];
    }

    $allFiles = amzscannerGetFilesRecursive($normDirPath);
    $isStrict = amzscannerIsStrictImageDir($dirKey);

    $totalCount  = 0;
    $dangerCount = 0;
    $errorCount  = 0;
    $findings    = [];

    foreach ($allFiles as $fullPath) {
        @set_time_limit(30);
        $filename = basename($fullPath);
        $totalCount++;

        // Calculate clean relative path
        $normFullPath = amzscannerNormalizePath($fullPath);
        $relativePath = ltrim(substr($normFullPath, strlen($normDirPath)), DIRECTORY_SEPARATOR);

        // Special check for .htaccess
        if ($filename === '.htaccess') {
            $htaccessIssues = amzscannerInspectHtaccess($normFullPath);
            if (!empty($htaccessIssues)) {
                $dangerCount++;
                $findings[] = [
                    'file'        => $relativePath,
                    'mime'        => 'text/plain',
                    'status'      => 'danger',
                    'msgs'        => $htaccessIssues,
                    'action_done' => ''
                ];
            }
            continue;
        }

        // Standard index files in upload root can be skipped if clean
        if (in_array($filename, ['index.php', 'index.html'], true)) {
            $fsize = filesize($normFullPath);
            if ($fsize < 500) {
                continue; // Safe empty index placeholder
            }
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($normFullPath) ?: 'application/octet-stream';
        
        $illegal    = false;
        $suspicious = false;
        $msgs       = [];
        $actionDone = '';

        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // 1. Check for dangerous executable extensions
        if (in_array($ext, $dangerousExts, true)) {
            $illegal = true;
            $msgs[]  = 'Berkas skrip/executable terlarang (' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')';
        } elseif (in_array($ext, $webXssExts, true)) {
            $suspicious = true;
            $msgs[]     = 'Berkas skrip web/HTML/SVG (' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')';
        }

        // 2. Check for double extension patterns (e.g. evil.php.jpg, photo.jpg.exe)
        $parts = explode('.', $filename);
        if (count($parts) > 2) {
            $secondLastExt = strtolower($parts[count($parts) - 2]);
            if (in_array($secondLastExt, $dangerousExts, true)) {
                $suspicious = true;
                $msgs[]     = 'Pola ekstensi ganda mencurigakan (*.' . htmlspecialchars($secondLastExt, ENT_QUOTES, 'UTF-8') . '.' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')';
            }
        }

        // 3. Strict Image Directory Verifications
        if ($isStrict) {
            if (in_array($mimeType, $allowedTypes, true)) {
                // Scan for embedded PHP or script signatures in image header/metadata
                $matchedPatterns = amzscannerFileContainsPattern($normFullPath, $forbiddenPatterns, 1048576);
                if (!empty($matchedPatterns)) {
                    $suspicious = true;
                    foreach ($matchedPatterns as $mp) {
                        $msgs[] = 'Pola payload "' . htmlspecialchars($mp, ENT_QUOTES, 'UTF-8') . '" terdeteksi';
                    }
                }
            } else {
                // Not a valid image in strict image folder
                $illegal = true;
                $msgs[]  = 'Tipe MIME tidak valid untuk folder gambar (' . htmlspecialchars($mimeType, ENT_QUOTES, 'UTF-8') . ')';
            }
        } else {
            // Repository / files directory: check scannable text or script files
            $scannableExts = array_merge($dangerousExts, $webXssExts, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'csv', 'xml']);
            if (in_array($ext, $scannableExts, true)) {
                $matchedPatterns = amzscannerFileContainsPattern($normFullPath, $forbiddenPatterns, 2097152);
                if (!empty($matchedPatterns)) {
                    $suspicious = true;
                    foreach ($matchedPatterns as $mp) {
                        $msgs[] = 'Pola "' . htmlspecialchars($mp, ENT_QUOTES, 'UTF-8') . '" terdeteksi';
                    }
                }
            }
        }

        if ($illegal || $suspicious) {
            $status = 'danger';
            $dangerCount++;

            // Auto-corrective handling during scan if requested
            if ($corrective) {
                amzscannerQuarantineFile($normFullPath);
                if ($illegal) {
                    if (@unlink($normFullPath)) {
                        $actionDone = 'File dihapus (Dikarantina)';
                    } else {
                        $actionDone = 'Gagal dihapus (Izin berkas)';
                    }
                } elseif ($suspicious) {
                    $sanitized = false;
                    if (in_array($mimeType, $allowedTypes, true)) {
                        $sanitized = amzscannerSanitizeImage($normFullPath, $mimeType);
                    }
                    if ($sanitized) {
                        $actionDone = 'Gambar dibersihkan';
                    } else {
                        if (@unlink($normFullPath)) {
                            $actionDone = 'File dihapus (Dikarantina)';
                        } else {
                            $actionDone = 'Gagal dibersihkan/dihapus';
                        }
                    }
                }
            }

            $findings[] = [
                'file'        => $relativePath,
                'mime'        => $mimeType,
                'status'      => $status,
                'msgs'        => $msgs,
                'action_done' => $actionDone,
            ];
        }
    }

    $safeCount = max(0, $totalCount - $dangerCount - $errorCount);

    return [
        'stats' => [
            'total'       => $totalCount,
            'safe'        => $safeCount,
            'danger'      => $dangerCount,
            'error'       => $errorCount,
            'problematic' => count($findings)
        ],
        'findings' => $findings
    ];
}
