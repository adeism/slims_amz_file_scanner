<?php
defined('INDEX_AUTH') OR die('Direct access not allowed');

$settings = amzscannerLoadSettings();

if ($can_write && isset($_POST['save_amz_settings'])) {
    if (!amzscannerValidateCsrf()) {
        header('Location: ' . amzscannerAdminUrl(['tab' => 'settings', 'error' => 'csrf_error'])); exit;
    }
    $newSettings = [
        'enable_realtime_scan'      => isset($_POST['enable_realtime_scan']) ? '1' : '0',
        'enable_obfuscation_detect' => isset($_POST['enable_obfuscation_detect']) ? '1' : '0',
        'enable_entropy_analysis'   => isset($_POST['enable_entropy_analysis']) ? '1' : '0',
        'entropy_threshold'         => (string)min(8.0, max(3.0, (float)($_POST['entropy_threshold'] ?? 6.5))),
        'enable_magic_bytes'        => isset($_POST['enable_magic_bytes']) ? '1' : '0',
        'enable_polyglot_detect'    => isset($_POST['enable_polyglot_detect']) ? '1' : '0',
        'enable_steganography_hint' => isset($_POST['enable_steganography_hint']) ? '1' : '0',
        'enable_heuristic'          => isset($_POST['enable_heuristic']) ? '1' : '0',
        'corrective_mode'           => in_array($_POST['corrective_mode'] ?? '', ['quarantine', 'delete', 'report_only'], true) ? $_POST['corrective_mode'] : 'quarantine',
        'notify_email'              => filter_var(trim($_POST['notify_email'] ?? ''), FILTER_SANITIZE_EMAIL),
        'extra_patterns'            => htmlspecialchars(trim($_POST['extra_patterns'] ?? ''), ENT_QUOTES, 'UTF-8'),
    ];
    amzscannerSaveAllSettings($newSettings);
    header('Location: ' . amzscannerAdminUrl(['tab' => 'settings', 'success' => 'settings_saved'])); exit;
}

/**
 * Render a toggle row for Bootstrap 4
 */
function amzscannerToggleRow(string $name, bool $checked, string $icon, string $layerTag, string $title, string $desc, string $accentColor = '#004db6', bool $alwaysOn = false): void {
    $id  = 'toggle_' . $name;
    $chk = $checked || $alwaysOn ? 'checked' : '';
    $dis = $alwaysOn ? 'disabled' : '';
    $borderStyle = "border-left: 3px solid {$accentColor};";
    echo '<div class="amz-toggle-row mb-2" style="' . $borderStyle . ($alwaysOn ? 'background:#f0fff4;' : '') . '">';
    echo '<div class="d-flex align-items-start">';
    if ($alwaysOn) {
        echo '<span class="badge badge-success mr-3 mt-1" style="min-width:48px;font-size:9pt;padding:6px;">✓ Aktif</span>';
    } else {
        echo '<div class="custom-control custom-switch mr-3 mt-1">';
        echo "<input type=\"checkbox\" class=\"custom-control-input\" id=\"{$id}\" name=\"{$name}\" {$chk} {$dis}>";
        echo "<label class=\"custom-control-label\" for=\"{$id}\"></label>";
        echo '</div>';
    }
    echo '<div class="flex-grow-1">';
    echo "<div class=\"toggle-title\">{$icon} <span class=\"badge badge-secondary mr-1\" style=\"font-size:8pt;\">{$layerTag}</span> {$title}</div>";
    echo "<p class=\"toggle-desc\">{$desc}</p>";
    echo '</div></div></div>';
}
?>

<form method="post" action="<?= amzscannerAdminUrl(['tab' => 'settings']) ?>">
<input type="hidden" name="csrf_token" value="<?= htmlspecialchars(amzscannerGetCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
<input type="hidden" name="save_amz_settings" value="1">

<div class="row">
    <!-- LEFT: Detection Layers -->
    <div class="col-lg-8">
        <div class="amz-card">
            <div class="card-header bg-dark">🔬 Lapisan Deteksi (Detection Layers)</div>
            <div class="card-body" style="padding:14px;">
                <p class="text-muted small mb-3">Aktifkan atau nonaktifkan setiap lapisan deteksi secara independen. Semakin banyak lapisan aktif, semakin tinggi akurasi namun semakin lambat proses scan.</p>

                <!-- Realtime Toggle (Special) -->
                <div class="amz-toggle-row mb-2" style="border-left:3px solid #dc3545; background:#fff5f5;">
                    <div class="d-flex align-items-start">
                        <div class="custom-control custom-switch mr-3 mt-1">
                            <input type="checkbox" class="custom-control-input" id="toggle_realtime" name="enable_realtime_scan"
                                <?= $settings['enable_realtime_scan'] === '1' ? 'checked' : '' ?>>
                            <label class="custom-control-label" for="toggle_realtime"></label>
                        </div>
                        <div class="flex-grow-1">
                            <div class="toggle-title">⚡ <span class="badge badge-danger mr-1" style="font-size:8pt;">PENTING</span> Intersepsi Upload Real-time</div>
                            <p class="toggle-desc">Memblokir file berbahaya <strong>sebelum</strong> berhasil disimpan di server saat admin mengunggah cover bibliografi atau foto anggota. Terintegrasi via SLiMS Hooks.</p>
                        </div>
                    </div>
                </div>

                <?php amzscannerToggleRow('', false, '🔴', 'Layer 1', 'Pattern Signature', '40+ pola tanda tangan bahaya: web shell (c99, r57), eksekusi perintah, injeksi SQL, XSS. Selalu aktif.', '#dc3545', true); ?>
                <?php amzscannerToggleRow('enable_obfuscation_detect', $settings['enable_obfuscation_detect'] === '1', '🟠', 'Layer 2', 'Deteksi Obfuscation &amp; Encoding', 'Mendeteksi kode PHP tersamar: eval(base64_decode), hex encoding, str_rot13, gzinflate, variabel dinamis ($$), dan teknik obfuscation lainnya.', '#fd7e14'); ?>
                
                <!-- Layer 3: Entropy with slider -->
                <div class="amz-toggle-row mb-2" style="border-left:3px solid #ffc107;">
                    <div class="d-flex align-items-start">
                        <div class="custom-control custom-switch mr-3 mt-1">
                            <input type="checkbox" class="custom-control-input" id="toggle_entropy" name="enable_entropy_analysis"
                                <?= $settings['enable_entropy_analysis'] === '1' ? 'checked' : '' ?>>
                            <label class="custom-control-label" for="toggle_entropy"></label>
                        </div>
                        <div class="flex-grow-1">
                            <div class="toggle-title">🟡 <span class="badge badge-secondary mr-1" style="font-size:8pt;">Layer 3</span> Analisis Entropi Shannon</div>
                            <p class="toggle-desc mb-2">Mendeteksi kode terenkripsi atau di-pack menggunakan kalkulasi matematis. File dengan entropi tinggi kemungkinan besar dikompres/dienkripsi.</p>
                            <div class="d-flex align-items-center">
                                <label class="small font-weight-bold text-muted mr-2 mb-0" style="white-space:nowrap;">Threshold:</label>
                                <input type="range" class="custom-range flex-grow-1 mr-2" name="entropy_threshold"
                                    min="3.0" max="8.0" step="0.1"
                                    value="<?= htmlspecialchars($settings['entropy_threshold'], ENT_QUOTES, 'UTF-8') ?>"
                                    oninput="document.getElementById('entropy_val').textContent=parseFloat(this.value).toFixed(1)">
                                <span class="badge badge-warning" id="entropy_val" style="min-width:38px;font-size:10pt;">
                                    <?= htmlspecialchars($settings['entropy_threshold'], ENT_QUOTES, 'UTF-8') ?>
                                </span>
                            </div>
                            <small class="text-muted"><em>3.0 = sangat sensitif | 8.0 = longgar. Default: 6.5</em></small>
                        </div>
                    </div>
                </div>

                <?php amzscannerToggleRow('enable_magic_bytes', $settings['enable_magic_bytes'] === '1', '🟢', 'Layer 4', 'Validasi Magic Bytes', 'Memverifikasi "sidik jari" byte pertama file. Mendeteksi PHP yang disamarkan sebagai .jpg/.png, binary executable Linux (ELF), dan ZIP tersembunyi.', '#28a745'); ?>
                <?php amzscannerToggleRow('enable_polyglot_detect', $settings['enable_polyglot_detect'] === '1', '🔵', 'Layer 5', 'Deteksi Polyglot File', 'Mendeteksi file yang valid sebagai 2 format sekaligus — JPEG valid yang juga mengandung kode PHP. Teknik bypass scanner paling licik.', '#007bff'); ?>
                <?php amzscannerToggleRow('enable_steganography_hint', $settings['enable_steganography_hint'] === '1', '🟣', 'Layer 6', 'Deteksi Steganografi', 'Mendeteksi data tersembunyi: metadata EXIF mencurigakan dan ukuran file tidak wajar dibanding dimensi gambar. Lebih lambat.', '#6f42c1'); ?>
                <?php amzscannerToggleRow('enable_heuristic', $settings['enable_heuristic'] === '1', '⚫', 'Layer 7', 'Heuristik &amp; Skor Bahaya', 'Deteksi kombinasi pola berbahaya dan skor kumulatif 0–10+. Mendeteksi kombinasi $_POST + eval() = web shell klasik.', '#343a40'); ?>
            </div>
        </div>
    </div>

    <!-- RIGHT: General Settings -->
    <div class="col-lg-4">
        <div class="amz-card mb-3">
            <div class="card-header bg-secondary">⚙️ Pengaturan Umum</div>
            <div class="card-body">

                <!-- Corrective Mode -->
                <div class="mb-4">
                    <label class="font-weight-bold d-block mb-1">🛠️ Mode Tindakan Korektif</label>
                    <small class="text-muted d-block mb-2">Apa yang dilakukan ketika file berbahaya ditemukan?</small>
                    <?php
                    $modes = [
                        'quarantine'  => ['🔒 Karantina', 'Pindahkan ke folder karantina. Dapat dipulihkan.', 'success'],
                        'delete'      => ['🗑️ Hapus Permanen', 'Hapus langsung. Tidak dapat dipulihkan!', 'danger'],
                        'report_only' => ['📋 Laporkan Saja', 'Hanya catat di log. Tidak ada tindakan.', 'info'],
                    ];
                    foreach ($modes as $val => [$label, $desc, $color]):
                        $checked = ($settings['corrective_mode'] ?? 'quarantine') === $val ? 'checked' : '';
                    ?>
                        <div class="custom-control custom-radio mb-2">
                            <input class="custom-control-input" type="radio" name="corrective_mode" id="mode_<?= $val ?>" value="<?= $val ?>" <?= $checked ?>>
                            <label class="custom-control-label" for="mode_<?= $val ?>">
                                <strong><?= $label ?></strong>
                                <br><small class="text-muted"><?= $desc ?></small>
                            </label>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Extra Patterns -->
                <div class="form-group mb-3">
                    <label class="font-weight-bold mb-1">🔍 Pola Kustom Tambahan</label>
                    <input type="text" name="extra_patterns" class="form-control form-control-sm"
                        value="<?= htmlspecialchars($settings['extra_patterns'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                        placeholder="misal: c99, r57, backdoor">
                    <small class="text-muted">Pisahkan dengan koma (,)</small>
                </div>

                <!-- Notify Email -->
                <div class="form-group mb-0">
                    <label class="font-weight-bold mb-1">📧 Email Notifikasi Kritis</label>
                    <input type="email" name="notify_email" class="form-control form-control-sm"
                        value="<?= htmlspecialchars($settings['notify_email'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                        placeholder="admin@perpustakaan.id">
                    <small class="text-muted">Notifikasi saat skor ancaman ≥ 8</small>
                </div>
            </div>
        </div>

        <!-- Threat Level Reference -->
        <div class="amz-card">
            <div class="card-header" style="background:#f8f9fa; font-weight:bold; font-size:10pt;">📊 Referensi Tingkat Ancaman</div>
            <div class="card-body" style="padding:12px;">
                <table class="table table-sm table-borderless mb-0" style="font-size:9.5pt;">
                    <tr><td><span class="threat-badge threat-safe">✅ Aman</span></td><td class="text-muted">Skor = 0</td></tr>
                    <tr><td><span class="threat-badge threat-notice">⚠️ Perhatian</span></td><td class="text-muted">Skor 1–3</td></tr>
                    <tr><td><span class="threat-badge threat-danger">🚨 Bahaya</span></td><td class="text-muted">Skor 4–7</td></tr>
                    <tr><td><span class="threat-badge threat-critical">💀 Kritis</span></td><td class="text-muted">Skor ≥ 8</td></tr>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Save Button -->
<?php if ($can_write): ?>
    <div class="text-right mt-3">
        <button type="submit" class="btn btn-primary btn-lg font-weight-bold px-5">
            💾 Simpan Semua Pengaturan
        </button>
    </div>
<?php endif; ?>
</form>
