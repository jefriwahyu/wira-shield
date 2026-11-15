# WIRA-SHIELD: MASTER SPECIFICATION & AI EXECUTION BLUEPRINT

Nama Proyek: WIRA-SHIELD (Waspada Intersepsi Runtime & Automated Shield)
Kompetisi: Kartika Cyber Hackathon 2026 (PUSSIBERAD TNI AD & CODEPOLITAN)
Kategori: 02 - Defensive Shield (Penangkalan)
Lingkungan Pengembangan: Windows (Lokal) & Linux (Streamlit Community Cloud)

---

## 0. INSTRUKSI MUTLAK UNTUK AI (BACA SEBELUM MENULIS KODE)

Anda adalah Senior Cybersecurity Engineer yang sedang membangun prototipe hackathon WIRA-SHIELD menggunakan metode estafet (multi-AI stateless relay). Patuhi 6 aturan operasi ini tanpa pengecualian:

1. Kerjakan Hanya Modul yang Diminta: Cek bagian Checklist Progres Estafet (Bagian 1). Jangan membuat atau mengubah file di luar modul yang sedang diinstruksikan oleh pengguna.
2. Kepatuhan Kontrak Teknis 100%: Gunakan nama file, konstanta path, nama fungsi, parameter, dan struktur return dictionary persis seperti yang tertulis di Bagian 4 & 5. Dilarang mengubah nama variabel atau fungsi agar kode Anda tidak merusak modul yang dibuat oleh AI lain.
3. Aturan Keamanan Sandbox Mutlak (Sandbox Guardrail): Program ini menyimulasikan penghapusan malware (os.remove) dan enkripsi dokumen (cryptography.fernet). Seluruh operasi manipulasi file WAJIB dikunci hanya di dalam folder ./sandbox_device_prajurit/. Setiap fungsi penghapusan atau enkripsi wajib memvalidasi path menggunakan is_safe_path() terlebih dahulu.
4. Gunakan Konteks Eksplisit di UI & Dokumentasi: Saat membangun app.py (Modul 4) dan README.md (Modul 5), Anda wajib memasukkan narasi skenario serangan (pembobolan Linux VPS pada tombol web, Clickjacking, Malvertising, Silent Auto-Install, dan pencegatan 0% Installed di ruang transit) sesuai Bagian 2.
5. Prinsip KISS (Keep It Simple, Stupid): Tulis kode Python yang bersih, modular, tahan error (try-except), kompatibel lintas OS (Windows & Linux menggunakan os.path), dan tanpa ketergantungan database eksternal.
6. Dilarang Menjalankan Git Otomatis: Anda DILARANG KERAS mengeksekusi perintah git add, git commit, atau git push. Setelah selesai mengerjakan dan menguji satu modul, perbarui tanda [ ] menjadi [x] pada Bagian 1 di file ini, lalu tampilkan perintah Git berformat Conventional Commits (sesuai Bagian 6) agar dijalankan secara manual oleh developer.

---

## 1. CHECKLIST PROGRES ESTAFET
(AI wajib mengubah [ ] menjadi [x] pada modul yang telah selesai dikerjakan)

- [ ] Modul 1: Fondasi & Lingkungan Sandbox (.gitignore, requirements.txt, sandbox_setup.py)
- [ ] Modul 2: Mesin Pertahanan 2 Lapis (wira_engine.py)
- [ ] Modul 3: Simulator 4 Skenario Serangan (attack_simulator.py)
- [ ] Modul 4: Dashboard Komando Interaktif (app.py)
- [ ] Modul 5: Dokumentasi Teknis & Panduan Penjurian (README.md)

---

## 2. KONSEP & KONTEKS EKSPLISIT PROYEK (ACUAN NARASI & LOGIKA SISTEM)

### A. Akar Masalah: Celah Manusia (Social Engineering) & Silent Auto-Install
1. Kelemahan Faktor Manusia: Pintu masuk paling rentan dalam institusi militer bukanlah firewall server pusat, melainkan perangkat prajurit yang dimanipulasi melalui teknik Social Engineering saat mengakses situs berita populer atau portal informasi publik.
2. Mekanisme Silent Auto-Install (Drive-By Compromise - MITRE ATT&CK T1189): Ketika prajurit tidak sengaja mengklik elemen berbahaya di sebuah situs web, browser mengeksekusi pengunduhan dan pemasangan aplikasi mata-mata (Remote Access Trojan / Spyware) secara diam-diam di latar belakang tanpa memunculkan notifikasi izin instalasi. Tujuannya adalah memberikan akses penuh (full access) kepada peretas untuk mengintip dan mencuri dokumen rahasia TNI AD.
3. Mengapa Firewall & Antivirus Biasa Gagal: TNI AD tidak memiliki kendali atas keamanan server website publik di luar jaringan militer. Jika situs resmi/terkenal telah disusupi dari sisi servernya, Firewall URL Blacklisting akan tetap meloloskan trafik tersebut karena menganggap domain situs itu sah dan aman.

### B. 4 Vektor Serangan yang Disimulasikan Secara Eksplisit
1. Watering Hole via Pembobolan Linux VPS (watering_hole):
   Peretas berhasil menjebol server Linux VPS milik sebuah website instansi/publik, mencari folder proyek di dalam VPS, lalu menyuntikkan kode jahat ke dalam fungsi klik (onClick) pada tombol fitur resmi (misalnya tombol "Unduh Pengumuman Resmi") dan menjalankan ulang layanan server. Saat prajurit mengklik tombol resmi tersebut, bibit backdoor (silent_rat_vps_exploit.pkg) otomatis meluncur ke perangkat prajurit.
2. Clickjacking / UI Redressing (clickjacking):
   Peretas menyisipkan lapisan transparan tak kasat mata tepat di atas menu navigasi website populer. Saat prajurit mengklik menu tersebut, sistem diam-diam mengunduh paket mata-mata (transparent_menu_spyware.apk).
3. Malvertising pada Jaringan Iklan (malvertising):
   Peretas menyelundupkan exploit ke dalam banner iklan di portal berita nasional. Saat iklan tidak sengaja terklik, payload pencuri data (ad_banner_infostealer.exe) otomatis masuk ke ruang transit browser.
4. Zero-Day Post-Exploitation / Akses Dokumen Rahasia (zeroday_honeyfile):
   Simulasi kondisi darurat di mana terdapat serangan Zero-Day tingkat tinggi yang mencoba memindai dan mencuri isi folder dokumen rahasia TNI AD di dalam perangkat prajurit.

### C. Solusi WIRA-SHIELD: Arsitektur Pertahanan 2 Lapis (Defense-in-Depth)
1. Lapis 1 — Pre-Install Staging Interceptor (Cegat pada Status 0% Ter-install):
   Setiap aplikasi yang ter-install otomatis dari browser wajib melewati folder transit sementara (browser_temp_staging/) sebelum dipasang ke sistem utama (installed_system_apps/). WIRA-SHIELD mengawasi ruang transit ini secara real-time. Begitu muncul bibit installer gelap dari hasil klik di browser, sistem langsung memutus proses instalasi pada posisi 0% Installed (Blocked at Staging) dan menghapus bersih file bibit tersebut dalam hitungan milidetik. Sistem utama perangkat prajurit terbukti tetap 100% bersih.
2. Lapis 2 — Honey-File Trap & Auto-Vault Lock (Enkripsi Darurat Dokumen Rahasia):
   Di dalam folder penyimpanan dokumen rahasia (dokumen_rahasia_tni/), ditanam satu file umpan bernama _HONEYFILE_SANDI_OPERASI.txt. Manusia normal tidak akan menyentuh file umpan ini, namun program pencuri data milik peretas yang menyapu seluruh isi folder pasti akan membacanya. Begitu file umpan tersentuh, WIRA-SHIELD otomatis mengenkripsi seluruh dokumen rahasia asli menggunakan algoritma Fernet (AES-128-CBC + HMAC) menjadi file terkunci (.locked) sehingga peretas tidak dapat membaca isinya. Brankas hanya bisa dibuka kembali menggunakan PIN Otorisasi Komandan (TNIAD2026).

### D. Cakupan Multi-Device Endpoint (Kesesuaian Teknis OS & IT/OT TNI AD)
- Laptop & PC Dinas (Windows/Linux): Agen bekerja penuh mengawasi proses staging browser, mencegah eksekusi silent installer, dan mengunci brankas dokumen rahasia.
- Smartphone Prajurit (Android/iOS): Memperhitungkan batasan OS Sandboxing pada sistem operasi mobile, agen bekerja sebagai Mobile Download & Staging Buffer Guard yang menyapu bersih paket .apk/script eksploitasi di ruang transit sebelum sempat diproses oleh package installer HP.
- Perangkat OT / Sensor Markas (Linux Embedded): Menjaga integritas direktori operasional dan konfigurasi sistem kontrol satuan dari penyusupan script otomatis.

---

## 3. STRUKTUR DIREKTORI PROYEK

    wira-shield/
    |-- WIRA_SHIELD_SPEC.md               # Dokumen spesifikasi & kontrak utama (file ini)
    |-- .gitignore                        # [Modul 1] Konfigurasi pengabaian file Git
    |-- requirements.txt                  # [Modul 1] Daftar dependensi Python
    |-- sandbox_setup.py                  # [Modul 1] Inisialisasi folder & validasi path sandbox
    |-- wira_engine.py                    # [Modul 2] Mesin Pre-Install Interceptor 0% & Fernet Vault
    |-- attack_simulator.py               # [Modul 3] Simulator 4 skenario serangan
    |-- app.py                            # [Modul 4] Dashboard Web Interaktif Streamlit
    |-- README.md                         # [Modul 5] Dokumentasi Teknis & Panduan Penjurian
    +-- sandbox_device_prajurit/          # [Otomatis dibuat oleh sandbox_setup.py - Diabaikan Git]
        |-- browser_temp_staging/         # Ruang transit bibit malware dari klik browser
        |-- installed_system_apps/        # Folder aplikasi sistem (Harus selalu 0% malware)
        |-- dokumen_rahasia_tni/          # Brankas dokumen rahasia + 1 file umpan (Honey-File)
        |-- security_logs.json            # Catatan log insiden & waktu respons (ms)
        +-- vault.key                     # Kunci enkripsi Fernet

---

## 4. KONSTANTA PATH TERKUNCI (WAJIB IDENTIK DI SEMUA MODUL)

Seluruh file Python wajib mendefinisikan atau mengimpor konstanta di bawah ini tanpa perubahan ejaan:

    BASE_SANDBOX = "./sandbox_device_prajurit"
    STAGING_DIR = "./sandbox_device_prajurit/browser_temp_staging"
    SYSTEM_APPS_DIR = "./sandbox_device_prajurit/installed_system_apps"
    VAULT_DIR = "./sandbox_device_prajurit/dokumen_rahasia_tni"
    HONEYFILE_PATH = "./sandbox_device_prajurit/dokumen_rahasia_tni/_HONEYFILE_SANDI_OPERASI.txt"
    LOG_FILE = "./sandbox_device_prajurit/security_logs.json"
    KEY_FILE = "./sandbox_device_prajurit/vault.key"
    COMMANDER_PIN = "TNIAD2026"

---

## 5. SPESIFIKASI TEKNIS & KONTRAK FUNGSI TIAP MODUL

### MODUL 1: .gitignore, requirements.txt, & sandbox_setup.py

1. File .gitignore:
   Wajib mengabaikan: __pycache__/, *.py[cod], .venv/, venv/, .env, dan sandbox_device_prajurit/

2. File requirements.txt:
   Berisi daftar paket:
   - streamlit>=1.32.0
   - watchdog>=4.0.0
   - cryptography>=42.0.0
   - psutil>=5.9.0

3. File sandbox_setup.py:
   - Fungsi is_safe_path(target_path: str) -> bool:
     Menggunakan os.path.abspath dan os.path.commonpath untuk memastikan target_path benar-benar berada di dalam BASE_SANDBOX. Mengembalikan True jika aman, False jika di luar sandbox.
   - Fungsi init_sandbox() -> dict:
     * Membuat direktori BASE_SANDBOX, STAGING_DIR, SYSTEM_APPS_DIR, dan VAULT_DIR (os.makedirs(..., exist_ok=True)).
     * Mengosongkan sisa file di STAGING_DIR dan VAULT_DIR (setelah lulus cek is_safe_path) agar fungsi ini juga bisa dipakai sebagai tombol Reset Sandbox.
     * Membuat 2 file aplikasi resmi dummy di dalam SYSTEM_APPS_DIR:
       1. aplikasi_dinas_tni.sys (isi teks: "Binary Resmi Sistem Informasi TNI AD - Terverifikasi").
       2. komunikasi_taktis.apk (isi teks: "Paket Aplikasi Komunikasi Taktis Resmi - Terverifikasi").
     * Membuat 3 file teks di dalam VAULT_DIR:
       1. Strategi_Pertahanan_Siber_2026.txt (isi teks: "DOKUMEN RAHASIA: Konfigurasi Pertahanan Jaringan Satuan & Titik Koordinat Komando.").
       2. Data_Logistik_Alutsista.txt (isi teks: "DOKUMEN RAHASIA: Daftar Inventaris Perangkat Komunikasi dan Sensor Markas.").
       3. _HONEYFILE_SANDI_OPERASI.txt (isi teks: "UMPAN JEBAKAN (HONEY-FILE): Akses ke file ini memicu penguncian brankas otomatis.").
     * Membuat kunci enkripsi Fernet.generate_key() baru dan menyimpannya ke KEY_FILE.
     * Menginisialisasi LOG_FILE dengan array JSON kosong [].
     * Mengembalikan dictionary: {"status": "ready", "message": "Lingkungan Sandbox Perangkat Prajurit siap."}
   - Blok if __name__ == "__main__": memanggil init_sandbox() dan mencetak hasilnya ke terminal.

---

### MODUL 2: wira_engine.py

Mengimpor konstanta dan is_safe_path, init_sandbox dari sandbox_setup.py. Wajib menyediakan 4 fungsi utama berikut:

1. Fungsi intercept_staging(device_profile: str, attack_source: str) -> dict:
   - Memindai seluruh file di dalam STAGING_DIR.
   - Mendeteksi file installer/payload mencurigakan dengan ekstensi .pkg, .apk, .exe, .bat, .sh, .py, atau .bin.
   - Untuk setiap file mencurigakan yang ditemukan:
     * Pastikan is_safe_path(file_path) bernilai True.
     * Gagalkan upaya penyalinan ke SYSTEM_APPS_DIR (tidak ada file yang masuk ke folder sistem utama).
     * Hapus file tersebut secara permanen dari STAGING_DIR menggunakan os.remove().
   - Catat entri log baru ke bagian paling atas (insert(0, ...)) di LOG_FILE dengan struktur:
     {"timestamp": "YYYY-MM-DD HH:MM:SS", "device": device_profile, "vector": attack_source, "payload": nama_file, "action": "Pre-Install Intercepted & Purged", "install_status": "0% Installed (Blocked at Staging)", "latency_ms": 12}
   - Mengembalikan dictionary:
     {"intercepted": True, "files_removed": list_nama_file, "install_progress": "0%", "latency_ms": 12, "status": "BLOCKED_AT_STAGING", "attack_source": attack_source, "device_profile": device_profile}

2. Fungsi lock_vault(reason: str, device_profile: str = "Laptop Dinas (Windows/Linux)") -> dict:
   - Membaca kunci Fernet dari KEY_FILE.
   - Mencari semua file berekstensi .txt di dalam VAULT_DIR.
   - Mengenkripsi isi setiap file .txt, menyimpannya sebagai file baru dengan nama <nama_file_asli>.locked, lalu menghapus file .txt aslinya (wajib cek is_safe_path).
   - Mencatat insiden darurat ke LOG_FILE dengan install_status: "VAULT LOCKED (Fernet AES-128)".
   - Mengembalikan dictionary:
     {"vault_locked": True, "locked_count": jumlah_file_terkunci, "reason": reason, "status": "EMERGENCY_VAULT_LOCKED"}

3. Fungsi unlock_vault(pin: str) -> dict:
   - Memeriksa apakah pin == COMMANDER_PIN ("TNIAD2026"). Jika salah, kembalikan {"success": False, "message": "Otorisasi Gagal: PIN Komandan tidak valid!"}.
   - Jika benar, baca kunci Fernet dari KEY_FILE, dekripsi seluruh file .locked di VAULT_DIR kembali menjadi file .txt asli, hapus file .locked (cek is_safe_path), catat pemulihan ke LOG_FILE, dan kembalikan:
     {"success": True, "message": "Otorisasi Komandan Diterima: Seluruh dokumen rahasia berhasil dipulihkan."}

4. Fungsi get_system_status() -> dict:
   - Jika BASE_SANDBOX belum ada, panggil init_sandbox() secara otomatis.
   - Membaca daftar nama file di STAGING_DIR, SYSTEM_APPS_DIR, dan VAULT_DIR.
   - Membaca isi teks dari setiap file di VAULT_DIR (maksimal 120 karakter pertama sebagai preview agar juri bisa melihat perbedaan teks asli vs ciphertext saat terkunci).
   - Menentukan is_vault_locked (bernilai True jika ada file berakhiran .locked di VAULT_DIR).
   - Membaca daftar riwayat insiden dari LOG_FILE.
   - Mengembalikan dictionary:
     {"staging_files": list_file_staging, "installed_apps": list_file_system_apps, "vault_files": list_nama_file_vault, "vault_previews": dict_nama_file_ke_preview_isi, "is_vault_locked": bool, "logs": list_log_insiden}

---

### MODUL 3: attack_simulator.py

Mengimpor init_sandbox, is_safe_path, STAGING_DIR, HONEYFILE_PATH, BASE_SANDBOX dari sandbox_setup.py, serta intercept_staging dan lock_vault dari wira_engine.py.

1. Fungsi trigger_attack(scenario: str, device_profile: str) -> dict:
   - Jika folder BASE_SANDBOX belum ada, panggil init_sandbox().
   - Eksekusi berdasarkan parameter scenario:
     * "watering_hole":
       Tulis file simulasi payload silent_rat_vps_exploit.pkg ke dalam STAGING_DIR (berisi teks simulasi script backdoor dari tombol web yang server Linux VPS-nya telah dijebol). Kemudian langsung panggil dan kembalikan hasil intercept_staging(device_profile, "Watering Hole (Tombol Web VPS Terinfeksi)").
     * "clickjacking":
       Tulis file simulasi transparent_menu_spyware.apk ke dalam STAGING_DIR (simulasi klik pada menu transparan). Panggil dan kembalikan hasil intercept_staging(device_profile, "Clickjacking (Jebakan Menu Transparan)").
     * "malvertising":
       Tulis file simulasi ad_banner_infostealer.exe ke dalam STAGING_DIR (simulasi klik banner iklan jahat). Panggil dan kembalikan hasil intercept_staging(device_profile, "Malvertising (Banner Iklan Beracun)").
     * "zeroday_honeyfile":
       Simulasikan proses hacker yang mencoba membaca HONEYFILE_PATH, lalu langsung panggil dan kembalikan hasil lock_vault("Akses Ilegal ke Honey-File (_HONEYFILE_SANDI_OPERASI.txt) Terdeteksi!", device_profile).

---

### MODUL 4: app.py (Dashboard Web Interaktif Streamlit)

Bangun antarmuka pengguna menggunakan streamlit (st.set_page_config(page_title="WIRA-SHIELD Command Center", layout="wide")) dengan susunan sebagai berikut:

1. Bagian Header & Pemilih Perangkat (Sidebar atau Top Bar):
   - Judul Utama: "WIRA-SHIELD // Command & Endpoint Protection Center"
   - Sub-judul: "Sistem Proteksi Perangkat Prajurit: Pre-Install Malware Interceptor (0% Installed) & Automated Document Vault Lock — Kategori 02: Defensive Shield"
   - Pilihan Profil Perangkat (st.selectbox):
     1. "Laptop Dinas Prajurit (Windows/Linux) - Full Process & Staging Guard"
     2. "Smartphone Prajurit (Android/iOS) - Mobile Staging & APK Buffer Guard"
     3. "Perangkat OT / Sensor Markas (Linux Embedded) - Config Integrity Guard"
   - Tombol "Reset Sandbox ke Kondisi Awal" yang memanggil init_sandbox().

2. Baris Metrik Utama (4 Kolom st.metric):
   - Status Perangkat: "AMAN (TERLINDUNGI)" atau "DARURAT (VAULT TERKUNCI)".
   - Malware Ter-install di Sistem: Selalu "0%" (dengan delta "100% Blocked at Staging").
   - Status Brankas Dokumen TNI: "TERBUKA (AKTIF)" atau "TERKUNCI (AES-FERNET)".
   - Total Insiden Digagalkan: Jumlah log di security_logs.json.

3. Area Utama 2 Kolom (col_left, col_right = st.columns(2)):
   - Kolom Kiri — Simulasi Layar Aktivitas Prajurit (Portal Web Publik/Instansi):
     Buat tampilan kartu simulasi portal berita/instansi tempat prajurit beraktivitas, lengkap dengan penjelasan singkat di setiap tombol:
     * Tombol 1: "Klik Unduh Pengumuman Resmi (Simulasi Watering Hole / Server Linux VPS Web Jebol)" -> Memanggil trigger_attack("watering_hole", device_profile).
     * Tombol 2: "Klik Menu Navigasi Portal (Simulasi Clickjacking / Lapisan Iframe Transparan)" -> Memanggil trigger_attack("clickjacking", device_profile).
     * Tombol 3: "Klik Banner Iklan Promo (Simulasi Malvertising / Drive-By Download)" -> Memanggil trigger_attack("malvertising", device_profile).
     * Tombol 4 (Darurat): "Simulasikan Akses Paksa Zero-Day ke Folder Dokumen Rahasia (Trigger Honey-File)" -> Memanggil trigger_attack("zeroday_honeyfile", device_profile).
   - Kolom Kanan — Radar Intersepsi Real-Time WIRA-SHIELD:
     Setiap kali tombol di Kolom Kiri ditekan, tampilkan alur telemetri pencegatan secara visual dan jelas:
     * [01 ms] Klik pengguna terdeteksi pada elemen web; browser menginisiasi silent background download.
     * [05 ms] Bibit installer mendarat di ruang transit (browser_temp_staging/).
     * [09 ms] WIRA-SHIELD Pre-Install Interceptor mendeteksi anomali unauthorized installer sebelum menyentuh sistem utama.
     * [12 ms] PROSES INSTALASI DIPUTUS PADA POSISI 0%! File bibit dihapus permanen dari ruang transit.

4. Panel Pembuktian Forensik & Brankas Dokumen (Bagian Bawah):
   - Kolom 1 — Bukti Direktori Sistem (installed_system_apps/): Tampilkan daftar file di dalam folder sistem utama untuk membuktikan kepada juri bahwa silent_rat_vps_exploit.pkg, .apk, atau .exe tidak pernah berhasil masuk ke sistem perangkat prajurit.
   - Kolom 2 — Isi Brankas Dokumen Rahasia (dokumen_rahasia_tni/): Tampilkan daftar file beserta preview isinya secara live. Saat normal, teks dokumen rahasia terbaca jelas. Saat Tombol 4 ditekan, tunjukkan bahwa seluruh file berubah menjadi .locked dan isinya berubah menjadi ciphertext acak Fernet yang mustahil dibaca hacker.
   - Form Otorisasi Komandan: Sediakan input password (st.text_input("Masukkan PIN Komandan (Default: TNIAD2026)", type="password")) dan tombol "Buka Kunci Brankas" yang memanggil unlock_vault(pin).
   - Tabel Log Forensik: Tampilkan riwayat dari security_logs.json menggunakan st.dataframe atau st.table.

---

### MODUL 5: README.md (Dokumentasi Teknis Standar Penjurian)

Susun README.md yang profesional dan terstruktur untuk dinilai oleh dewan juri PUSSIBERAD & CODEPOLITAN, mencakup:
1. Judul, Tagline, & Kategori Kompetisi (02 - Defensive Shield).
2. Latar Belakang Masalah: Penjelasan tajam tentang Social Engineering, pembobolan Linux VPS (Watering Hole), Clickjacking, Malvertising, dan bahaya Silent Auto-Install.
3. Inovasi Teknis WIRA-SHIELD: Diagram alur teks (ASCII/Mermaid) yang menjelaskan Lapis 1 (Pre-Install Interceptor 0% di Staging) dan Lapis 2 (Honey-File & Fernet Auto-Vault Lock) beserta cakupan Multi-Device Endpoint (IT/OT & Mobile Sandboxing).
4. Panduan Menjalankan Purwarupa (Lokal & Cloud) serta kredensial pengujian (PIN Komandan: TNIAD2026).
5. Skenario Pengujian untuk Dewan Juri (4 Langkah Uji Klik).

---

## 6. DAFTAR PERINTAH GIT MANUAL (UNTUK DEVELOPER)

(Catatan untuk AI: Tampilkan HANYA perintah Git yang sesuai dengan modul yang baru saja selesai Anda kerjakan agar disalin oleh developer ke terminal Windows)

- Saat Pertama Kali Menyimpan Spesifikasi Ini:
  git add WIRA_SHIELD_SPEC.md
  git commit -m "docs(spec): add master specification and stateless AI relay blueprint"
  git push -u origin main

- Setelah Selesai Modul 1:
  git add .gitignore requirements.txt sandbox_setup.py WIRA_SHIELD_SPEC.md
  git commit -m "chore(sandbox): initialize safe sandbox directory and project dependencies"
  git push

- Setelah Selesai Modul 2:
  git add wira_engine.py WIRA_SHIELD_SPEC.md
  git commit -m "feat(engine): implement zero-install staging interceptor and fernet vault lock"
  git push

- Setelah Selesai Modul 3:
  git add attack_simulator.py WIRA_SHIELD_SPEC.md
  git commit -m "feat(simulator): add watering hole, clickjacking, malvertising, and honeyfile scenarios"
  git push

- Setelah Selesai Modul 4:
  git add app.py WIRA_SHIELD_SPEC.md
  git commit -m "feat(ui): build interactive streamlit command center and multi-device simulator"
  git push

- Setelah Selesai Modul 5:
  git add README.md WIRA_SHIELD_SPEC.md
  git commit -m "docs(readme): add comprehensive technical documentation and judge testing guide"
  git push