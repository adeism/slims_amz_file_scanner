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
    $self  = $_SERVER['PHP_SELF'] ?? 'plugin_container.php';
    $query = array_merge($_GET, $params);
    return $self . '?' . http_build_query($query);
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
        'images'
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
    return ['html', 'htm', 'js'];
}

function amzscannerAllowedTypes(): array {
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
}

function amzscannerResolvePhysicalPath(string $filePath, string $targetDir): string {
    $normTarget = amzscannerNormalizePath(SB . $targetDir);
    $normFile   = amzscannerNormalizePath($filePath);

    // If $filePath already contains $normTarget (case-insensitive for Windows)
    if (stripos($normFile, $normTarget) === 0) {
        return $normFile;
    }
    return $normTarget . DIRECTORY_SEPARATOR . ltrim($normFile, DIRECTORY_SEPARATOR);
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
    foreach ($allowedDirs as $dirKey) {
        $allowedRealPath = realpath(SB . $dirKey);
        if ($allowedRealPath !== false) {
            $allowedWithSep = rtrim($allowedRealPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (stripos($realPath, $allowedWithSep) === 0 || strcasecmp($realPath, $allowedRealPath) === 0) {
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

// Inspect .htaccess files accurately (ignores safe php_flag engine off, flags handler overrides)
function amzscannerInspectHtaccess(string $filePath): array {
    $findings = [];
    $content = @file_get_contents($filePath);
    if ($content === false) return [];

    // Strip comments to inspect active directives only
    $lines = explode("\n", $content);
    $cleanLines = [];
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l === '' || strpos($l, '#') === 0) continue;
        $cleanLines[] = $l;
    }
    $cleanContent = implode("\n", $cleanLines);

    // 1. Handler override to execute PHP on uploaded image files
    if (preg_match('/(AddType|AddHandler|SetHandler)\s+.*php/i', $cleanContent, $m)) {
        $findings[] = 'Manipulasi eksekusi PHP pada .htaccess (' . htmlspecialchars(trim($m[0]), ENT_QUOTES, 'UTF-8') . ')';
    }

    // 2. Auto prepend/append backdoor injection
    if (preg_match('/(auto_prepend_file|auto_append_file)/i', $cleanContent, $m)) {
        $findings[] = 'Injeksi backdoor auto_prepend/append pada .htaccess (' . htmlspecialchars(trim($m[0]), ENT_QUOTES, 'UTF-8') . ')';
    }

    // 3. php_flag engine on (re-enabling PHP execution in upload directory)
    if (preg_match('/php_flag\s+engine\s+(on|1|true)/i', $cleanContent, $m)) {
        $findings[] = 'Mengaktifkan kembali engine PHP pada folder upload (' . htmlspecialchars(trim($m[0]), ENT_QUOTES, 'UTF-8') . ')';
    }

    return $findings;
}

function amzscannerGetFilesRecursive(string $dirPath): array {
    $results = [];
    if (!is_dir($dirPath)) return [];
    
    $items = scandir($dirPath);
    if (!$items) return [];

    // Skip internal SLiMS system directories if scanning root
    $excludedDirs = ['.', '..', 'quarantine', 'backup', 'cache', 'tntsearch', 'membercard', 'reports', 'swfs', 'chat', 'akses_layanan'];

    foreach ($items as $item) {
        if (in_array($item, $excludedDirs, true)) continue;
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

        // Calculate clean relative path with forward slashes for clean UI display
        $normFullPath = amzscannerNormalizePath($fullPath);
        $rawRelative  = ltrim(substr($normFullPath, strlen($normDirPath)), DIRECTORY_SEPARATOR);
        $relativePath = str_replace('\\', '/', $rawRelative);

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
            $msgs[]     = 'Berkas skrip web/HTML (' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')';
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
            // Repository directory: check scannable text or script files
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
