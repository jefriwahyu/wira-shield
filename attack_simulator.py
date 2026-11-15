"""
WIRA-SHIELD — Modul 3: Simulator 4 Skenario Serangan
=====================================================

attack_simulator.py memicu 4 vektor serangan eksplisit (Spec Bagian 2B)
terhadap sandbox perangkat prajurit, lalu menyerahkan penanganannya ke
mesin pertahanan WIRA-SHIELD (wira_engine.py):

1. watering_hole      — pembobolan Linux VPS + injeksi onClick tombol web
                        -> silent_rat_vps_exploit.pkg
2. clickjacking       — iframe transparan di atas menu navigasi
                        -> transparent_menu_spyware.apk
3. malvertising       — banner iklan beracun / drive-by download
                        -> ad_banner_infostealer.exe
4. zeroday_honeyfile  — akses ilegal ke _HONEYFILE_SANDI_OPERASI.txt
                        -> Auto-Vault Lock (Fernet)

Kontrak teknis: WIRA_SHIELD_SPEC.md Bagian 5 (Modul 3).
Simulasi ini HANYA menulis file teks payload di dalam STAGING_DIR
(sandbox guardrail: is_safe_path) — tidak ada eksekusi biner nyata.
"""

import os

from sandbox_setup import (
    BASE_SANDBOX,
    HONEYFILE_PATH,
    STAGING_DIR,
    init_sandbox,
    is_safe_path,
)
from wira_engine import intercept_staging, lock_vault

# Sumber serangan (attack_source) WAJIB identik dengan kontrak Modul 3.
_SOURCE_WATERING_HOLE = "Watering Hole (Tombol Web VPS Terinfeksi)"
_SOURCE_CLICKJACKING = "Clickjacking (Jebakan Menu Transparan)"
_SOURCE_MALVERTISING = "Malvertising (Banner Iklan Beracun)"

# Alasan lock vault WAJIB identik dengan kontrak Modul 3.
_HONEYFILE_REASON = (
    "Akses Ilegal ke Honey-File (_HONEYFILE_SANDI_OPERASI.txt) Terdeteksi!"
)

# Isi teks simulasi payload (bukan biner nyata — KISS & aman untuk juri).
_PAYLOAD_WATERING_HOLE = (
    "# SIMULASI PAYLOAD WIRA-SHIELD (bukan malware nyata)\n"
    "# Vektor: Watering Hole via pembobolan Linux VPS website instansi.\n"
    "# Peretas menyuntikkan kode jahat ke onClick tombol "
    "'Unduh Pengumuman Resmi' lalu me-restart layanan server.\n"
    "# Saat prajurit mengklik tombol resmi tersebut, bibit backdoor "
    "silent_rat_vps_exploit.pkg meluncur diam-diam ke browser_temp_staging/ "
    "tanpa notifikasi izin instalasi (Silent Auto-Install / T1189).\n"
)

_PAYLOAD_CLICKJACKING = (
    "# SIMULASI PAYLOAD WIRA-SHIELD (bukan malware nyata)\n"
    "# Vektor: Clickjacking / UI Redressing.\n"
    "# Lapisan iframe transparan tak kasat mata ditempel di atas menu "
    "navigasi website populer. Klik prajurit pada menu seolah sah "
    "justru mengunduh transparent_menu_spyware.apk ke ruang transit.\n"
)

_PAYLOAD_MALVERTISING = (
    "# SIMULASI PAYLOAD WIRA-SHIELD (bukan malware nyata)\n"
    "# Vektor: Malvertising pada jaringan iklan portal berita nasional.\n"
    "# Banner iklan beracun terklik tidak sengaja; payload pencuri data "
    "ad_banner_infostealer.exe otomatis masuk ke ruang transit browser.\n"
)


def _write_staging_payload(filename: str, content: str) -> bool:
    """
    Tulis file payload simulasi ke STAGING_DIR (hanya jika path aman).

    :return: True jika file tertulis, False jika gagal / di luar sandbox.
    """
    payload_path = os.path.join(STAGING_DIR, filename)
    if not is_safe_path(payload_path) or not is_safe_path(STAGING_DIR):
        return False
    try:
        os.makedirs(STAGING_DIR, exist_ok=True)
        with open(payload_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return True
    except OSError:
        return False


def trigger_attack(scenario: str, device_profile: str) -> dict:
    """
    Jalankan satu skenario serangan lalu kembalikan hasil mesin pertahanan.

    :param scenario: "watering_hole" | "clickjacking" | "malvertising" |
                     "zeroday_honeyfile".
    :param device_profile: profil perangkat prajurit yang dipilih di dashboard.
    :return: dictionary hasil intercept_staging() / lock_vault() persis
             seperti kontrak Modul 2 (tanpa pembungkus tambahan).
    """
    # Auto-init: sandbox belum ada -> siapkan lingkungan prajurit dulu.
    if not os.path.isdir(BASE_SANDBOX):
        init_sandbox()

    if scenario == "watering_hole":
        _write_staging_payload(
            "silent_rat_vps_exploit.pkg",
            _PAYLOAD_WATERING_HOLE,
        )
        return intercept_staging(device_profile, _SOURCE_WATERING_HOLE)

    if scenario == "clickjacking":
        _write_staging_payload(
            "transparent_menu_spyware.apk",
            _PAYLOAD_CLICKJACKING,
        )
        return intercept_staging(device_profile, _SOURCE_CLICKJACKING)

    if scenario == "malvertising":
        _write_staging_payload(
            "ad_banner_infostealer.exe",
            _PAYLOAD_MALVERTISING,
        )
        return intercept_staging(device_profile, _SOURCE_MALVERTISING)

    if scenario == "zeroday_honeyfile":
        # Simulasikan hacker menyapu folder rahasia dan membaca honeyfile.
        # Kegagalan baca (mis. brankas sudah terkunci) tidak menggagalkan lock.
        try:
            if is_safe_path(HONEYFILE_PATH) and os.path.isfile(HONEYFILE_PATH):
                with open(HONEYFILE_PATH, "r", encoding="utf-8") as handle:
                    handle.read()
        except OSError:
            pass
        return lock_vault(_HONEYFILE_REASON, device_profile)

    # Skenario tidak dikenal — jangan crash (prinsip tahan error).
    return {
        "status": "UNKNOWN_SCENARIO",
        "scenario": scenario,
        "device_profile": device_profile,
        "message": (
            "Skenario tidak dikenal. Gunakan salah satu dari: "
            "watering_hole, clickjacking, malvertising, zeroday_honeyfile."
        ),
    }
