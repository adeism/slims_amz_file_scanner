# 🛡️ AMZ File Scanner & Sanitizer for SLiMS

Plugin keamanan yang dirancang khusus untuk memindai, mendeteksi, mengkarantina, dan membersihkan berkas-berkas berbahaya (seperti PHP web shells, payload malware tersembunyi, skrip XSS, atau berkas executable ilegal) yang terselip di dalam folder unggahan Senayan Library Management System (SLiMS).

Terinspirasi dari konsep pembersihan gambar oleh **Pak Hendro Wicaksono** (*slims-clean-image*).

<img width="1067" height="834" alt="AMZ File Scanner Preview" src="https://github.com/user-attachments/assets/5df3b16e-c74d-47cb-9429-9e155f8845d6" />

---

## ✨ Fitur Utama

- **🔍 Pemindaian Berkas Mendalam (Deep Scanner):**
  - Mendeteksi ekstensi terlarang (`.php`, `.phtml`, `.phar`, `.sh`, `.exe`, `.py`, `.cgi`, dll.).
  - Mendeteksi teknik manipulasi ekstensi ganda (contoh: `cover.php.jpg`, `dokumen.pdf.exe`).
  - Memindai berkas `.htaccess` di folder upload dari manipulasi direktif jahat (seperti `AddType application/x-httpd-php`).
  - Memeriksa ketidakcocokan antara ekstensi berkas dengan *MIME Type* aslinya.
  - Memindai signature kode berbahaya dan fungsi eksekusi shell (`eval`, `base64_decode`, `shell_exec`, `system`, `passthru`, `$_POST`, dll.).

- **🖼️ Sanitasi Gambar Cerdas (GD Image Sanitizer):**
  - Membersihkan metadata EXIF dan payload tersembunyi pada berkas JPEG, PNG, GIF, dan WebP.
  - **Preservasi Alpha Channel:** Mempertahankan transparansi pada gambar PNG dan WebP tanpa merubah latar belakang menjadi hitam.

- **📦 Karantina Otomatis (Quarantine Backup):**
  - Sebelum berkas diubah atau dihapus, salinan berkas asli secara otomatis dicadangkan ke `files/quarantine/[tanggal]/` yang terlindungi oleh `.htaccess` (*Deny from all*).
  - Melindungi perpustakaan dari risiko kehilangan data (*false positive*).

- **⚡ Performa Ringan & Bebas OOM (Memory-Safe):**
  - Menggunakan *stream chunk reading* untuk berkas berukuran besar di folder `repository/` sehingga tidak membebani RAM server (*Memory Exhaustion*).
  - Mengoptimalkan penyimpanan sesi admin sehingga tetap cepat bahkan dengan ratusan ribu koleksi gambar.

- **📊 Ekspor & Laporan:**
  - Ekspor temuan ke format **CSV Standar (RFC 4180)** ber-BOM UTF-8 yang langsung rapi dibuka di Microsoft Excel / LibreOffice tanpa peringatan keamanan.
  - Tampilan **Cetak Laporan** responsif siap cetak (A4/F4).

- **💻 Kompatibilitas Lintas OS:**
  - Berjalan mulus di server **Linux**, **macOS**, maupun **Windows (Laragon / XAMPP)**.

---

## 📁 Direktori Target Pemindaian

Plugin ini berfokus pada area tempat berkas diunggah oleh pengguna dan staf:
1. `images/docs` — Sampul Bibliografi / Cover Buku.
2. `images/persons` — Foto Anggota / Member.
3. `repository` — Berkas Lampiran Dokumen (PDF, DOCX, E-Book, Jurnal).
4. `files` — Berkas Unggahan Sistem Lainnya.

---

## 🚀 Cara Instalasi & Aktivasi

### Opsi 1: Menggunakan Git (Direkomendasikan)
Buka terminal di dalam folder instalasi SLiMS Anda:
```bash
cd plugins
git clone https://github.com/adeism/slims_amz_file_scanner.git amz_file_scanner
```

### Opsi 2: Unduh Berkas ZIP
1. Unduh repositori ini sebagai ZIP atau dari halaman Release.
2. Ekstrak ke dalam direktori plugin SLiMS Anda:
   ```
   slims/plugins/amz_file_scanner/
   ```
3. Pastikan struktur folder berisi `amz-file-scanner.plugin.php`, `helper.php`, `admin_menu.php`, dan folder `inc/`.

### Aktivasi di Admin SLiMS
1. Masuk ke halaman **Admin SLiMS** (`http://localhost/slims/admin/`).
2. Buka menu **System** (Sistem) ➔ **Plugins** (Plugin).
3. Cari **AMZ File Scanner** lalu klik tombol **Aktifkan**.
4. Menu **🛡️ AMZ File Scanner** akan muncul pada submenu modul **System**.

---

## 🛡️ Cara Kerja Karantina (Quarantine)

Setiap kali Anda menekan tombol **🛠️ Terapkan Tindakan Korektif**, sistem akan:
1. Membuat salinan cadangan berkas asli ke folder:
   `files/quarantine/YYYYMMDD/HHMMSS_namafile.bak`
2. Memastikan folder karantina tidak dapat diakses langsung oleh publik melalui browser via `.htaccess`.
3. Menghapus berkas executable ilegal atau membersihkan gambar menggunakan GD Library.

---

## 📋 Catatan Rilis & Pembaruan

### Versi 1.1.0
- ✨ Menambahkan normalisasi path lintas OS (perbaikan error path di Windows).
- ✨ Menambahkan fitur pencadangan otomatis ke folder karantina (`files/quarantine/`).
- ✨ Memperbaiki retensi transparansi (*alpha channel*) pada gambar PNG dan WebP.
- ✨ Menambahkan deteksi ekstensi ganda dan inspeksi berkas `.htaccess` di folder upload.
- ✨ Memperbaiki konsumsi memori (*memory leak / session bloat*) saat memindai repositori berkas besar.
- ✨ Mengganti format ekspor laporan ke CSV standar (RFC 4180) UTF-8.
- ✨ Menambahkan lokalisasi bahasa SLiMS `__('...')`.

---

## ⚠️ Disclaimer
Plugin ini memproses pembersihan berkas gambar menggunakan GD Library dan penghapusan berkas ilegal. Meskipun sistem telah dilengkapi mekanisme pencadangan karantina otomatis, pastikan Anda **selalu melakukan backup berkas dan database SLiMS secara berkala**.

---

## 👨‍💻 Kontributor & Kredit
- **Ade Ismail Siregar** — Pengembang Utama ([GitHub](https://github.com/adeism))
- **Hendro Wicaksono** — Konsep dan Inspirasi Pembersihan Gambar (*slims-clean-image*)
- Komunitas **SLiMS (Senayan Open Source Library Management System)**
