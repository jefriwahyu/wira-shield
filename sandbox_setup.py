"""
WIRA-SHIELD — Modul 1: Fondasi & Lingkungan Sandbox
====================================================

sandbox_setup.py mengurus:
1. Konstanta path terkunci (WAJIB identik di semua modul — Spec Bagian 4).
2. Sandbox Guardrail: is_safe_path() memastikan setiap operasi file
   hanya terjadi di dalam ./sandbox_device_prajurit.
3. init_sandbox(): inisialisasi / Reset Sandbox (folder staging,
   aplikasi sistem dummy, brankas dokumen + honeyfile, kunci Fernet,
   dan log insiden kosong).

Kontrak teknis: WIRA_SHIELD_SPEC.md Bagian 4 & 5 (Modul 1).
Lingkungan: Windows (lokal) & Linux (Streamlit Community Cloud),
hanya memakai os.path — tanpa database eksternal.
"""

import json
import os

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# KONSTANTA PATH TERKUNCI (WAJIB IDENTIK DI SEMUA MODUL)
# ---------------------------------------------------------------------------
BASE_SANDBOX = "./sandbox_device_prajurit"
STAGING_DIR = "./sandbox_device_prajurit/browser_temp_staging"
SYSTEM_APPS_DIR = "./sandbox_device_prajurit/installed_system_apps"
VAULT_DIR = "./sandbox_device_prajurit/dokumen_rahasia_tni"
HONEYFILE_PATH = "./sandbox_device_prajurit/dokumen_rahasia_tni/_HONEYFILE_SANDI_OPERASI.txt"
LOG_FILE = "./sandbox_device_prajurit/security_logs.json"
KEY_FILE = "./sandbox_device_prajurit/vault.key"
COMMANDER_PIN = "TNIAD2026"

# Isi file bawaan sesuai kontrak Modul 1 (Spec Bagian 5)
_OFFICIAL_APPS = {
    "aplikasi_dinas_tni.sys": (
        "Binary Resmi Sistem Informasi TNI AD - Terverifikasi"
    ),
    "komunikasi_taktis.apk": (
        "Paket Aplikasi Komunikasi Taktis Resmi - Terverifikasi"
    ),
}

_VAULT_DOCUMENTS = {
    "Strategi_Pertahanan_Siber_2026.txt": (
        "DOKUMEN RAHASIA: Konfigurasi Pertahanan Jaringan Satuan & Titik Koordinat Komando."
    ),
    "Data_Logistik_Alutsista.txt": (
        "DOKUMEN RAHASIA: Daftar Inventaris Perangkat Komunikasi dan Sensor Markas."
    ),
    "_HONEYFILE_SANDI_OPERASI.txt": (
        "UMPAN JEBAKAN (HONEY-FILE): Akses ke file ini memicu penguncian brankas otomatis."
    ),
}


def is_safe_path(target_path: str) -> bool:
    """
    Sandbox Guardrail: True hanya jika target_path berada di dalam BASE_SANDBOX.

    Memakai os.path.abspath + os.path.commonpath sehingga tahan terhadap
    path traversal (mis. "../"), absolute path di luar sandbox, dan
    drive berbeda pada Windows (ValueError -> False).

    :param target_path: path file/direktori yang akan divalidasi.
    :return: True jika aman (di dalam sandbox), False jika di luar sandbox.
    """
    try:
        sandbox_abs = os.path.abspath(BASE_SANDBOX)
        target_abs = os.path.abspath(target_path)
        common_path = os.path.commonpath([sandbox_abs, target_abs])
        return common_path == sandbox_abs
    except (ValueError, TypeError, OSError):
        # Drive berbeda (Windows) atau input tidak valid -> tolak.
        return False


def _purge_directory_files(directory: str) -> None:
    """
    Hapus seluruh file langsung di dalam `directory` (untuk Reset Sandbox).

    Setiap kandidat file wajib lolos is_safe_path() sebelum os.remove().
    Error per-file ditelan agar satu file macet tidak menggagalkan reset.
    """
    if not is_safe_path(directory):
        return
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        file_path = os.path.join(directory, name)
        if os.path.isfile(file_path) and is_safe_path(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass


def _write_text_file(file_path: str, content: str) -> None:
    """Tulis file teks UTF-8 hanya jika file_path berada di dalam sandbox."""
    if not is_safe_path(file_path):
        return
    parent_dir = os.path.dirname(file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(content)


def init_sandbox() -> dict:
    """
    Inisialisasi (atau Reset) lingkungan sandbox perangkat prajurit.

    Langkah:
    1. Buat BASE_SANDBOX, STAGING_DIR, SYSTEM_APPS_DIR, VAULT_DIR.
    2. Kosongkan sisa file di STAGING_DIR dan VAULT_DIR (Reset Sandbox),
       setelah lolos is_safe_path().
    3. Buat 2 file aplikasi resmi dummy di SYSTEM_APPS_DIR.
    4. Buat 3 file teks di VAULT_DIR (2 dokumen rahasia + 1 honeyfile).
    5. Generate kunci Fernet baru ke KEY_FILE.
    6. Inisialisasi LOG_FILE dengan array JSON kosong [].

    :return: {"status": "ready", "message": "Lingkungan Sandbox Perangkat Prajurit siap."}
    """
    # 1. Struktur direktori
    os.makedirs(BASE_SANDBOX, exist_ok=True)
    os.makedirs(STAGING_DIR, exist_ok=True)
    os.makedirs(SYSTEM_APPS_DIR, exist_ok=True)
    os.makedirs(VAULT_DIR, exist_ok=True)

    # 2. Reset isi ruang transit dan brankas (aman setelah is_safe_path)
    _purge_directory_files(STAGING_DIR)
    _purge_directory_files(VAULT_DIR)

    # 3. Aplikasi resmi dummy (harus selalu bersih dari malware)
    for filename, content in _OFFICIAL_APPS.items():
        _write_text_file(os.path.join(SYSTEM_APPS_DIR, filename), content)

    # 4. Dokumen rahasia + honeyfile
    for filename, content in _VAULT_DOCUMENTS.items():
        _write_text_file(os.path.join(VAULT_DIR, filename), content)

    # 5. Kunci enkripsi Fernet baru
    key = Fernet.generate_key()
    if is_safe_path(KEY_FILE):
        with open(KEY_FILE, "wb") as handle:
            handle.write(key)

    # 6. Log insiden kosong
    if is_safe_path(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as handle:
            json.dump([], handle)

    return {
        "status": "ready",
        "message": "Lingkungan Sandbox Perangkat Prajurit siap.",
    }


if __name__ == "__main__":
    hasil = init_sandbox()
    print(hasil)
