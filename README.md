# 🛡️ AMZ File Scanner & Sanitizer

Plugin keamanan yang dirancang khusus untuk memindai, mendeteksi, dan membersihkan berkas-berkas berbahaya (seperti PHP web shells, payload malware tersembunyi, atau file executable ilegal) yang terselip di dalam folder unggahan SLiMS Anda.

<img width="1067" height="834" alt="msedge_GjDLxNuJbP" src="https://github.com/user-attachments/assets/5df3b16e-c74d-47cb-9429-9e155f8845d6" />


---

## 📁 Folder Target Pemindaian

Plugin ini berfokus secara ketat pada area rentan tempat pengguna mengunggah berkas:
1.  `images/docs` - Sampul Bibliografi / Cover Buku.
2.  `images/persons` - Foto Anggota / Member.
3.  `repository` - Berkas Lampiran Dokumen (PDF, DOCX, dll).

---

## 🚀 Cara Instalasi & Aktivasi

1.  Unduh/salin folder `amz_file_scanner` ke direktori plugin SLiMS Anda:
    ```
    slims/plugins/amz_file_scanner/
    ```
2.  Masuk ke halaman Admin SLiMS Anda.
3.  Buka menu **System** ➔ **Plugins** ➔ klik **Aktifkan** pada **AMZ File Scanner**.
4.  Menu **🛡️ AMZ File Scanner** akan muncul di samping modul System Anda!

---


## ⚠️ Disclaimer
Plugin ini memproses pembersihan berkas gambar menggunakan GD Library. Meskipun proses penulisan ulang gambar dirancang seaman mungkin, pastikan Anda **selalu melakukan backup berkas secara berkala**. Kami tidak bertanggung jawab jika gambar profil anggota Anda yang tadinya disisipi script PHP jahat berubah menjadi putih polos.
