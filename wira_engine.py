"""
WIRA-SHIELD — Modul 2: Mesin Pertahanan 2 Lapis
=================================================

wira_engine.py menyediakan mesin pertahanan inti:

Lapis 1 — Pre-Install Staging Interceptor:
    intercept_staging() memindai ruang transit browser_temp_staging/,
    menggagalkan penyalinan payload mencurigakan ke installed_system_apps/,
    dan menghapus bibit malware pada posisi 0% Installed.

Lapis 2 — Honey-File Trap & Auto-Vault Lock:
    lock_vault() mengenkripsi seluruh .txt di dokumen_rahasia_tni/ menjadi
    .locked (Fernet AES-128-CBC + HMAC). unlock_vault() memulihkannya
    hanya jika PIN Komandan (COMMANDER_PIN) valid.

Kontrak teknis: WIRA_SHIELD_SPEC.md Bagian 4 & 5 (Modul 2).
Konstanta path & is_safe_path() diimpor dari sandbox_setup.py agar
identik di semua modul. Semua operasi file wajib lolos is_safe_path().
"""

import json
import os
import time

from cryptography.fernet import Fernet, InvalidToken

from sandbox_setup import (
    BASE_SANDBOX,
    COMMANDER_PIN,
    KEY_FILE,
    LOG_FILE,
    STAGING_DIR,
    SYSTEM_APPS_DIR,
    VAULT_DIR,
    init_sandbox,
    is_safe_path,
)

# Ekstensi installer/payload mencurigakan (kontrak Modul 2).
SUSPICIOUS_EXTENSIONS = {".pkg", ".apk", ".exe", ".bat", ".sh", ".py", ".bin"}

# Panjang maksimal preview isi brankas (kontrak get_system_status).
VAULT_PREVIEW_LIMIT = 120

# Latensi simulasi intersepsi (ms) — kontrak log & return intercept_staging.
INTERCEPT_LATENCY_MS = 12


# ---------------------------------------------------------------------------
# Helper internal
# ---------------------------------------------------------------------------
def _now_timestamp() -> str:
    """Timestamp log dengan format kontrak: YYYY-MM-DD HH:MM:SS."""
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _read_logs() -> list:
    """Baca security_logs.json; kembalikan [] jika hilang/korup. Terkunci hanya di sandbox."""
    if not is_safe_path(LOG_FILE) or not os.path.isfile(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError, ValueError):
        return []


def _prepend_log(entry: dict) -> None:
    """Catat entri log baru ke bagian paling atas LOG_FILE (insert(0, ...))."""
    if not is_safe_path(LOG_FILE):
        return
    logs = _read_logs()
    logs.insert(0, entry)
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as handle:
            json.dump(logs, handle, ensure_ascii=False, indent=2)
    except (OSError, TypeError):
        pass


def _list_filenames(directory: str) -> list:
    """Daftar nama file (bukan folder) di dalam directory, terurut stabil."""
    if not is_safe_path(directory):
        return []
    try:
        return sorted(
            name
            for name in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, name))
        )
    except OSError:
        return []


def _read_preview(file_path: str, limit: int = VAULT_PREVIEW_LIMIT) -> str:
    """Baca maksimal `limit` karakter pertama isi file sebagai preview juri."""
    if not is_safe_path(file_path):
        return ""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _load_fernet(allow_create: bool = False) -> Fernet:
    """
    Muat kunci Fernet dari KEY_FILE.

    :param allow_create: True -> generate kunci baru jika KEY_FILE belum ada
                         (dipakai lock_vault). False -> jangan buat kunci baru
                         (dipakai unlock_vault agar kunci lama tidak tertimpa).
    """
    if not is_safe_path(KEY_FILE):
        raise RuntimeError("KEY_FILE berada di luar sandbox.")
    if os.path.isfile(KEY_FILE):
        with open(KEY_FILE, "rb") as handle:
            key = handle.read()
        return Fernet(key)
    if not allow_create:
        raise RuntimeError("Kunci brankas (vault.key) tidak ditemukan.")
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as handle:
        handle.write(key)
    return Fernet(key)


# ---------------------------------------------------------------------------
# LAPIS 1 — Pre-Install Staging Interceptor (0% Installed)
# ---------------------------------------------------------------------------
def intercept_staging(device_profile: str, attack_source: str) -> dict:
    """
    Pindai STAGING_DIR, gagalkan instalasi payload mencurigakan, lalu purge.

    - File ber-ekstensi .pkg/.apk/.exe/.bat/.sh/.py/.bin dianggap mencurigakan.
    - Penyalinan ke SYSTEM_APPS_DIR SELALU digagalkan (tidak ada file yang
      masuk ke folder sistem utama — bukti 0% Installed).
    - File bibit dihapus permanen dari STAGING_DIR via os.remove()
      setelah is_safe_path() lolos.
    - Setiap payload yang dihapus dicatat di paling atas LOG_FILE.

    :param device_profile: profil perangkat prajurit yang sedang disimulasikan.
    :param attack_source: vektor serangan (watering hole / clickjacking / dll).
    :return: dictionary kontrak Modul 2.
    """
    files_removed: list = []

    try:
        if os.path.isdir(STAGING_DIR):
            for name in sorted(os.listdir(STAGING_DIR)):
                file_path = os.path.join(STAGING_DIR, name)
                if not os.path.isfile(file_path):
                    continue
                extension = os.path.splitext(name)[1].lower()
                if extension not in SUSPICIOUS_EXTENSIONS:
                    continue
                # Sandbox Guardrail: jangan sentuh apa pun di luar sandbox.
                if not is_safe_path(file_path):
                    continue

                # Lapis 1: instalasi ke sistem utama DIPUTUS di 0%.
                # Sengaja TIDAK ada operasi salin ke SYSTEM_APPS_DIR.
                try:
                    os.remove(file_path)
                    files_removed.append(name)
                    _prepend_log({
                        "timestamp": _now_timestamp(),
                        "device": device_profile,
                        "vector": attack_source,
                        "payload": name,
                        "action": "Pre-Install Intercepted & Purged",
                        "install_status": "0% Installed (Blocked at Staging)",
                        "latency_ms": INTERCEPT_LATENCY_MS,
                    })
                except OSError:
                    continue
    except OSError:
        pass

    return {
        "intercepted": len(files_removed) > 0,
        "files_removed": files_removed,
        "install_progress": "0%",
        "latency_ms": INTERCEPT_LATENCY_MS,
        "status": "BLOCKED_AT_STAGING",
        "attack_source": attack_source,
        "device_profile": device_profile,
    }


# ---------------------------------------------------------------------------
# LAPIS 2 — Honey-File Trap & Fernet Auto-Vault Lock
# ---------------------------------------------------------------------------
def lock_vault(
    reason: str,
    device_profile: str = "Laptop Dinas (Windows/Linux)",
) -> dict:
    """
    Enkripsi darurat seluruh file .txt di VAULT_DIR menjadi <nama_asli>.locked.

    Honeyfile ikut terkunci karena ber-ekstensi .txt. File asli dihapus
    setelah ciphertext tersimpan (wajib is_safe_path pada kedua path).

    :param reason: alasan penguncian (mis. akses ilegal ke honeyfile).
    :param device_profile: profil perangkat tempat insiden terjadi.
    :return: dictionary kontrak Modul 2.
    """
    locked_names: list = []

    try:
        fernet = _load_fernet(allow_create=True)

        if os.path.isdir(VAULT_DIR):
            for name in sorted(os.listdir(VAULT_DIR)):
                file_path = os.path.join(VAULT_DIR, name)
                if not os.path.isfile(file_path):
                    continue
                if os.path.splitext(name)[1].lower() != ".txt":
                    continue
                locked_path = file_path + ".locked"
                # Sandbox Guardrail: file asli DAN file .locked harus di dalam sandbox.
                if not is_safe_path(file_path) or not is_safe_path(locked_path):
                    continue

                try:
                    with open(file_path, "rb") as handle:
                        plaintext = handle.read()
                    ciphertext = fernet.encrypt(plaintext)
                    with open(locked_path, "wb") as handle:
                        handle.write(ciphertext)
                    os.remove(file_path)
                    locked_names.append(name)
                except (OSError, ValueError):
                    continue

        _prepend_log({
            "timestamp": _now_timestamp(),
            "device": device_profile,
            "vector": reason,
            "payload": ", ".join(locked_names) if locked_names else "-",
            "action": "Emergency Vault Lock",
            "install_status": "VAULT LOCKED (Fernet AES-128)",
            "latency_ms": INTERCEPT_LATENCY_MS,
        })

        return {
            "vault_locked": True,
            "locked_count": len(locked_names),
            "reason": reason,
            "status": "EMERGENCY_VAULT_LOCKED",
        }
    except (OSError, RuntimeError, ValueError):
        return {
            "vault_locked": False,
            "locked_count": len(locked_names),
            "reason": reason,
            "status": "EMERGENCY_VAULT_LOCKED",
        }


def unlock_vault(pin: str) -> dict:
    """
    Pulihkan seluruh file .locked di VAULT_DIR setelah verifikasi PIN Komandan.

    PIN salah  -> {"success": False, "message": "Otorisasi Gagal: PIN Komandan tidak valid!"}
    PIN benar  -> dekripsi .locked ke .txt asli, hapus .locked, catat log pemulihan.

    :param pin: PIN Otorisasi Komandan.
    :return: dictionary kontrak Modul 2.
    """
    if pin != COMMANDER_PIN:
        return {
            "success": False,
            "message": "Otorisasi Gagal: PIN Komandan tidak valid!",
        }

    restored_names: list = []

    try:
        fernet = _load_fernet(allow_create=False)

        if os.path.isdir(VAULT_DIR):
            for name in sorted(os.listdir(VAULT_DIR)):
                if not name.endswith(".locked"):
                    continue
                locked_path = os.path.join(VAULT_DIR, name)
                original_path = locked_path[: -len(".locked")]
                # Sandbox Guardrail pada file terkunci DAN file pemulihan.
                if not is_safe_path(locked_path) or not is_safe_path(original_path):
                    continue

                try:
                    with open(locked_path, "rb") as handle:
                        token = handle.read()
                    plaintext = fernet.decrypt(token)
                    with open(original_path, "wb") as handle:
                        handle.write(plaintext)
                    os.remove(locked_path)
                    restored_names.append(os.path.basename(original_path))
                except (OSError, InvalidToken, ValueError):
                    continue

        _prepend_log({
            "timestamp": _now_timestamp(),
            "device": "Otorisasi Komandan",
            "vector": "PIN Komandan diterima",
            "payload": ", ".join(restored_names) if restored_names else "-",
            "action": "Vault Unlock & Restore",
            "install_status": "VAULT UNLOCKED (Dokumen Dipulihkan)",
            "latency_ms": INTERCEPT_LATENCY_MS,
        })

        return {
            "success": True,
            "message": "Otorisasi Komandan Diterima: Seluruh dokumen rahasia berhasil dipulihkan.",
        }
    except (OSError, RuntimeError, ValueError) as exc:
        # PIN sudah tervalidasi benar; kegagalan di sini berasal dari kunci/IO,
        # bukan PIN salah. Jangan menuduh PIN tidak valid.
        return {
            "success": False,
            "message": "Pemulihan brankas gagal: " + str(exc),
        }


# ---------------------------------------------------------------------------
# Telemetri status sistem (untuk dashboard Modul 4)
# ---------------------------------------------------------------------------
def get_system_status() -> dict:
    """
    Kumpulkan status live sandbox untuk dashboard komando.

    - Auto-init: jika BASE_SANDBOX belum ada, panggil init_sandbox().
    - Preview isi VAULT_DIR maksimal 120 karakter (asli vs ciphertext).
    - is_vault_locked True jika ada file berakhiran .locked.

    :return: dictionary kontrak Modul 2.
    """
    if not os.path.isdir(BASE_SANDBOX):
        init_sandbox()

    staging_files = _list_filenames(STAGING_DIR)
    installed_apps = _list_filenames(SYSTEM_APPS_DIR)
    vault_files = _list_filenames(VAULT_DIR)

    vault_previews: dict = {}
    for name in vault_files:
        file_path = os.path.join(VAULT_DIR, name)
        vault_previews[name] = _read_preview(file_path) if is_safe_path(file_path) else ""

    is_vault_locked = any(name.endswith(".locked") for name in vault_files)

    return {
        "staging_files": staging_files,
        "installed_apps": installed_apps,
        "vault_files": vault_files,
        "vault_previews": vault_previews,
        "is_vault_locked": is_vault_locked,
        "logs": _read_logs(),
    }
