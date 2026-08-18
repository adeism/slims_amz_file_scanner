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
        'images',
        'files'
    ];
}

function amzscannerIsStrictImageDir(string $dir): bool {
    return in_array($dir, ['images/docs', 'images/persons'], true);
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
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/x-icon', 'image/vnd.microsoft.icon'];
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

    foreach ($items as $item) {
        if ($item === '.' || $item === '..' || $item === 'quarantine') continue;
        $fullPath = $dirPath . DIRECTORY_SEPARATOR . $item;
        if (is_dir($fullPath)) {
            $results = array_merge($results, amzscannerGetFilesRecursive($fullPath));
        } else {
            $results[] = $fullPath;
        }
    }
    return $results;
}

// ── Smart Context-Aware File Inspector ─────────────────────────────────────
function amzscannerInspectFile(string $fullPath, string $relativePath, bool $isStrict, array $forbiddenPatterns): ?array {
    $filename = basename($fullPath);
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $normRel = str_replace('\\', '/', $relativePath);

    // Standard index files in upload root (< 500 bytes) are safe placeholders
    if (in_array($filename, ['index.php', 'index.html'], true) && filesize($fullPath) < 500) {
        return null;
    }

    // Special check for .htaccess
    if ($filename === '.htaccess') {
        $htaccessIssues = amzscannerInspectHtaccess($fullPath);
        if (!empty($htaccessIssues)) {
            return [
                'file'   => $normRel,
                'mime'   => 'text/plain',
                'status' => 'danger',
                'msgs'   => $htaccessIssues,
                'action_done' => ''
            ];
        }
        return null;
    }

    // Standard font binary extensions
    if (in_array($ext, ['ttf', 'woff', 'woff2', 'eot', 'otf'], true)) {
        return null;
    }

    // SVG Files: Check for active XSS payloads (only flag if malicious scripts present)
    if ($ext === 'svg') {
        $svgXssPatterns = ['<script', 'onload=', 'onerror=', 'onclick=', 'javascript:', 'xlink:href="javascript', 'eval('];
        $matchedXss = amzscannerFileContainsPattern($fullPath, $svgXssPatterns, 1048576);
        if (!empty($matchedXss)) {
            return [
                'file'   => $normRel,
                'mime'   => 'image/svg+xml',
                'status' => 'danger',
                'msgs'   => array_map(fn($p) => 'Payload XSS "' . htmlspecialchars($p, ENT_QUOTES, 'UTF-8') . '" pada berkas SVG', $matchedXss),
                'action_done' => ''
            ];
        }
        return null; // Clean vector graphic/font
    }

    // Check for double extension patterns (e.g. photo.php.jpg, doc.pdf.exe)
    $dangerousExts = amzscannerDangerousExtensions();
    $parts = explode('.', $filename);
    if (count($parts) > 2) {
        $secondLastExt = strtolower($parts[count($parts) - 2]);
        if (in_array($secondLastExt, $dangerousExts, true)) {
            return [
                'file'   => $normRel,
                'mime'   => 'application/octet-stream',
                'status' => 'danger',
                'msgs'   => ['Pola ekstensi ganda mencurigakan (*.' . htmlspecialchars($secondLastExt, ENT_QUOTES, 'UTF-8') . '.' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')'],
                'action_done' => ''
            ];
        }
    }

    // Recognized SLiMS Membercard Templates (files/membercard/**)
    if (strpos($normRel, 'membercard/') !== false) {
        $legitimateMembercardFiles = ['membercard.php', 'tinfo.inc.php', 'individual-membercard.php'];
        if (in_array($filename, $legitimateMembercardFiles, true)) {
            // Check for actual backdoor / web shell execution injection
            $backdoorSignatures = [
                'shell_exec', 'passthru', 'system(', 'popen(', 'proc_open(',
                'eval(base64_decode', 'eval(gzinflate', 'eval($_POST', 'eval($_GET', 'eval($_REQUEST',
                'assert($_POST', 'assert($_GET', 'c99shell', 'r57shell', 'wso_version'
            ];
            $matchedBackdoors = amzscannerFileContainsPattern($fullPath, $backdoorSignatures, 1048576);
            if (!empty($matchedBackdoors)) {
                return [
                    'file'   => $normRel,
                    'mime'   => 'text/x-php',
                    'status' => 'danger',
                    'msgs'   => array_map(fn($p) => 'Injeksi backdoor "' . htmlspecialchars($p, ENT_QUOTES, 'UTF-8') . '" pada template kartu anggota', $matchedBackdoors),
                    'action_done' => ''
                ];
            }
            return null; // Legitimate SLiMS member card template
        }
        // Unknown/unauthorized PHP script inside membercard folder
        if (in_array($ext, $dangerousExts, true)) {
            return [
                'file'   => $normRel,
                'mime'   => 'text/x-php',
                'status' => 'danger',
                'msgs'   => ['Berkas PHP tidak dikenal di folder template (' . htmlspecialchars($filename, ENT_QUOTES, 'UTF-8') . ')'],
                'action_done' => ''
            ];
        }
    }

    // Recognized SLiMS Report Static HTML Files (files/reports/**)
    if (strpos($normRel, 'reports/') !== false) {
        if (in_array($ext, ['html', 'htm', 'csv', 'txt'], true)) {
            // Check for malicious XSS/phishing/eval (ignore safe self.print())
            $maliciousReportPatterns = [
                'eval(', 'document.cookie', '<iframe', 'window.location.replace',
                'phpinfo()', 'shell_exec', 'system(', 'base64_decode'
            ];
            $matched = amzscannerFileContainsPattern($fullPath, $maliciousReportPatterns, 1048576);
            if (!empty($matched)) {
                return [
                    'file'   => $normRel,
                    'mime'   => 'text/html',
                    'status' => 'danger',
                    'msgs'   => array_map(fn($p) => 'Pola berbahaya "' . htmlspecialchars($p, ENT_QUOTES, 'UTF-8') . '" pada berkas laporan', $matched),
                    'action_done' => ''
                ];
            }
            return null; // Safe SLiMS generated print report
        }
    }

    // Check for dangerous executable extensions anywhere else in upload directories
    if (in_array($ext, $dangerousExts, true)) {
        return [
            'file'   => $normRel,
            'mime'   => 'text/x-php',
            'status' => 'danger',
            'msgs'   => ['Berkas skrip/executable terlarang (' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')'],
            'action_done' => ''
        ];
    }

    // Check Web Script / HTML extensions in strict upload folders (images/docs, images/persons, repository)
    $webXssExts = amzscannerWebXssExtensions();
    if (in_array($ext, $webXssExts, true) && strpos($normRel, 'reports/') === false) {
        return [
            'file'   => $normRel,
            'mime'   => 'text/html',
            'status' => 'danger',
            'msgs'   => ['Berkas skrip web/HTML di folder unggahan (' . htmlspecialchars($ext, ENT_QUOTES, 'UTF-8') . ')'],
            'action_done' => ''
        ];
    }

    $finfo    = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($fullPath) ?: 'application/octet-stream';
    $allowedTypes = amzscannerAllowedTypes();

    // Strict Image Folders (images/docs, images/persons)
    if ($isStrict) {
        if (in_array($mimeType, $allowedTypes, true)) {
            // Check for embedded PHP open tag or shell payloads
            $matchedPatterns = amzscannerFileContainsPattern($fullPath, $forbiddenPatterns, 1048576);
            if (!empty($matchedPatterns)) {
                return [
                    'file'   => $normRel,
                    'mime'   => $mimeType,
                    'status' => 'danger',
                    'msgs'   => array_map(fn($p) => 'Pola payload "' . htmlspecialchars($p, ENT_QUOTES, 'UTF-8') . '" terdeteksi pada gambar', $matchedPatterns),
                    'action_done' => ''
                ];
            }
            return null; // Safe image
        } else {
            return [
                'file'   => $normRel,
                'mime'   => $mimeType,
                'status' => 'danger',
                'msgs'   => ['Tipe MIME tidak valid untuk folder gambar (' . htmlspecialchars($mimeType, ENT_QUOTES, 'UTF-8') . ')'],
                'action_done' => ''
            ];
        }
    } else {
        // General folders: Check scannable files for shell payloads
        $scannableExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'csv', 'xml'];
        if (in_array($ext, $scannableExts, true)) {
            $matchedPatterns = amzscannerFileContainsPattern($fullPath, $forbiddenPatterns, 2097152);
            if (!empty($matchedPatterns)) {
                return [
                    'file'   => $normRel,
                    'mime'   => $mimeType,
                    'status' => 'danger',
                    'msgs'   => array_map(fn($p) => 'Pola payload "' . htmlspecialchars($p, ENT_QUOTES, 'UTF-8') . '" terdeteksi', $matchedPatterns),
                    'action_done' => ''
                ];
            }
        }
    }

    return null; // Safe
}

// ── Directory Scanner Engine ───────────────────────────────────────────────
function amzscannerScanDir(string $dirPath, string $dirKey, array $forbiddenPatterns, bool $corrective = false): array {
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
        $totalCount++;

        // Calculate clean relative path with forward slashes
        $normFullPath = amzscannerNormalizePath($fullPath);
        $rawRelative  = ltrim(substr($normFullPath, strlen($normDirPath)), DIRECTORY_SEPARATOR);
        $relativePath = str_replace('\\', '/', $rawRelative);

        $threat = amzscannerInspectFile($normFullPath, $relativePath, $isStrict, $forbiddenPatterns);
        if ($threat !== null) {
            $dangerCount++;

            if ($corrective) {
                amzscannerQuarantineFile($normFullPath);
                $ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
                $dangerousExts = amzscannerDangerousExtensions();
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mimeType = $finfo->file($normFullPath) ?: 'application/octet-stream';
                $allowedTypes = amzscannerAllowedTypes();

                if (in_array($ext, $dangerousExts, true) || !in_array($mimeType, $allowedTypes, true)) {
                    if (@unlink($normFullPath)) {
                        $threat['action_done'] = 'File dihapus (Dikarantina)';
                    } else {
                        $threat['action_done'] = 'Gagal dihapus (Izin berkas)';
                    }
                } else {
                    $sanitized = amzscannerSanitizeImage($normFullPath, $mimeType);
                    if ($sanitized) {
                        $threat['action_done'] = 'Gambar dibersihkan';
                    } else {
                        if (@unlink($normFullPath)) {
                            $threat['action_done'] = 'File dihapus (Dikarantina)';
                        } else {
                            $threat['action_done'] = 'Gagal dibersihkan/dihapus';
                        }
                    }
                }
            }

            $findings[] = $threat;
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
