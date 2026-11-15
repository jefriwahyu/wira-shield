"""
WIRA-SHIELD — Modul 4: Dashboard Komando Interaktif (Streamlit)
================================================================

app.py adalah Command & Endpoint Protection Center untuk juri dan operator:
- Simulasi layar aktivitas prajurit (portal web publik/instansi).
- Radar intersepsi real-time (telemetri 01/05/09/12 ms).
- Panel pembuktian forensik: installed_system_apps, brankas dokumen,
  otorisasi PIN Komandan, dan tabel log security_logs.json.

Kontrak teknis: WIRA_SHIELD_SPEC.md Bagian 2 & 5 (Modul 4).
Jalankan: streamlit run app.py
"""

import os
import sys

# Pastikan modul proyek (sandbox_setup, wira_engine, attack_simulator)
# selalu dapat diimpor, baik dari lokal Windows/Linux maupun Streamlit Cloud.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from attack_simulator import trigger_attack
from sandbox_setup import init_sandbox
from wira_engine import get_system_status, unlock_vault

# ---------------------------------------------------------------------------
# Konstanta UI (label WAJIB identik dengan kontrak Modul 4)
# ---------------------------------------------------------------------------
DEVICE_PROFILES = [
    "Laptop Dinas Prajurit (Windows/Linux) - Full Process & Staging Guard",
    "Smartphone Prajurit (Android/iOS) - Mobile Staging & APK Buffer Guard",
    "Perangkat OT / Sensor Markas (Linux Embedded) - Config Integrity Guard",
]

DEVICE_NOTES = {
    DEVICE_PROFILES[0]: (
        "Agen bekerja penuh: mengawasi staging browser, mencegah eksekusi "
        "silent installer, dan mengunci brankas dokumen rahasia."
    ),
    DEVICE_PROFILES[1]: (
        "Mobile Download & Staging Buffer Guard: paket .apk / script "
        "eksploitasi disapu di ruang transit sebelum package installer HP memprosesnya."
    ),
    DEVICE_PROFILES[2]: (
        "Config Integrity Guard: menjaga integritas direktori operasional "
        "dan konfigurasi sistem kontrol satuan dari script otomatis penyusup."
    ),
}

# Label tombol portal WAJIB identik dengan kontrak Modul 4.
BTN_WATERING_HOLE = (
    "Klik Unduh Pengumuman Resmi (Simulasi Watering Hole / Server Linux VPS Web Jebol)"
)
BTN_CLICKJACKING = (
    "Klik Menu Navigasi Portal (Simulasi Clickjacking / Lapisan Iframe Transparan)"
)
BTN_MALVERTISING = (
    "Klik Banner Iklan Promo (Simulasi Malvertising / Drive-By Download)"
)
BTN_ZERODAY = (
    "Simulasikan Akses Paksa Zero-Day ke Folder Dokumen Rahasia (Trigger Honey-File)"
)

# Alur telemetri staging WAJIB identik dengan kontrak Modul 4.
TELEMETRY_STAGING = [
    "[01 ms] Klik pengguna terdeteksi pada elemen web; browser menginisiasi silent background download.",
    "[05 ms] Bibit installer mendarat di ruang transit (browser_temp_staging/).",
    "[09 ms] WIRA-SHIELD Pre-Install Interceptor mendeteksi anomali unauthorized installer sebelum menyentuh sistem utama.",
    "[12 ms] PROSES INSTALASI DIPUTUS PADA POSISI 0%! File bibit dihapus permanen dari ruang transit.",
]

TELEMETRY_HONEYFILE = [
    "[01 ms] Proses asing (zero-day) memindai folder dokumen_rahasia_tni/ di perangkat prajurit.",
    "[05 ms] Honey-File _HONEYFILE_SANDI_OPERASI.txt tersentuh oleh pencuri data.",
    "[09 ms] WIRA-SHIELD Auto-Vault Lock aktif — enkripsi Fernet (AES-128-CBC + HMAC).",
    "[12 ms] SELURUH DOKUMEN RAHASIA TERKUNCI (.locked). Ciphertext tidak dapat dibaca peretas.",
]


# ---------------------------------------------------------------------------
# Helper aplikasi
# ---------------------------------------------------------------------------
def _init_session_state() -> None:
    """Siapkan session state default (tahan error jika atribut hilang)."""
    st.session_state.setdefault("last_result", None)
    st.session_state.setdefault("last_scenario", None)
    st.session_state.setdefault("radar", None)
    st.session_state.setdefault("flash", None)  # (kind, text) -> success|error|info
    st.session_state.setdefault("app_error", None)


def _pop_flash() -> None:
    """Tampilkan satu pesan flash lalu hapus agar tidak muncul dua kali."""
    flash = st.session_state.pop("flash", None)
    if not flash:
        return
    kind, text = flash
    if kind == "success":
        st.success(text)
    elif kind == "error":
        st.error(text)
    else:
        st.info(text)


def _telemetry_for(scenario: str) -> list:
    """Pilih alur telemetri sesuai vektor serangan."""
    return TELEMETRY_HONEYFILE if scenario == "zeroday_honeyfile" else TELEMETRY_STAGING


def _run_attack(scenario: str, device_profile: str) -> None:
    """Jalankan trigger_attack, simpan hasil + radar, lalu refresh halaman."""
    try:
        result = trigger_attack(scenario, device_profile)
        st.session_state["last_result"] = result
        st.session_state["last_scenario"] = scenario
        st.session_state["radar"] = _telemetry_for(scenario)
        st.session_state["app_error"] = None
    except Exception as exc:  # pragma: no cover - jaga UI tetap hidup
        st.session_state["app_error"] = str(exc)
    st.rerun()


def _reset_sandbox() -> None:
    """Reset sandbox ke kondisi pabrik dan bersihkan radar."""
    try:
        init_sandbox()
        st.session_state["last_result"] = None
        st.session_state["last_scenario"] = None
        st.session_state["radar"] = None
        st.session_state["app_error"] = None
        st.session_state["flash"] = (
            "success",
            "Sandbox Perangkat Prajurit berhasil direset ke kondisi awal.",
        )
    except Exception as exc:  # pragma: no cover
        st.session_state["flash"] = ("error", f"Reset sandbox gagal: {exc}")
    st.rerun()


def _unlock_vault(pin: str) -> None:
    """Otorisasi Komandan: buka kunci brankas jika PIN valid."""
    try:
        result = unlock_vault(pin)
        if result.get("success"):
            st.session_state["flash"] = ("success", result.get("message", "Brankas dibuka."))
        else:
            st.session_state["flash"] = ("error", result.get("message", "Otorisasi gagal."))
        st.session_state["app_error"] = None
    except Exception as exc:  # pragma: no cover
        st.session_state["flash"] = ("error", f"Pemulihan brankas gagal: {exc}")
    st.rerun()


def _render_radar() -> None:
    """Kolom kanan: alur telemetri pencegatan 01/05/09/12 ms."""
    st.subheader("📡 Radar Intersepsi Real-Time WIRA-SHIELD")
    st.caption("Telemetri waktu respons sejak klik prajurit (simulasi milidetik).")

    radar = st.session_state.get("radar")
    result = st.session_state.get("last_result")
    if not radar or not result:
        st.info(
            "Belum ada aktivitas. Klik salah satu aksi di Kolom Kiri "
            "(portal web publik) untuk melihat intersepsi live."
        )
        return

    for line in radar:
        if line.startswith("[12 ms]"):
            st.markdown(f"**🚫 {line}**")
        else:
            st.markdown(f"`{line}`")

    st.divider()
    status = result.get("status")
    if status == "BLOCKED_AT_STAGING":
        files = ", ".join(result.get("files_removed", [])) or "-"
        st.success(
            f"**LAPIS 1 AKTIF — BLOCKED AT STAGING.** "
            f"Payload `{files}` dihapus permanen. Instalasi diputus pada "
            f"**{result.get('install_progress', '0%')} Installed** "
            f"({result.get('latency_ms', 12)} ms). Sistem utama tetap bersih."
        )
        st.caption(f"Vektor: {result.get('attack_source', '-')} • Perangkat: {result.get('device_profile', '-')}")
    elif status == "EMERGENCY_VAULT_LOCKED":
        locked_count = result.get("locked_count", 0)
        if locked_count:
            st.error(
                f"**LAPIS 2 AKTIF — EMERGENCY VAULT LOCKED.** "
                f"{locked_count} dokumen rahasia dienkripsi Fernet (AES-128). "
                f"Alasan: {result.get('reason', '-')}"
            )
        else:
            st.warning(
                "**Brankas sudah terkunci.** Tidak ada file .txt baru yang terkunci "
                "(honeyfile sebelumnya telah memicu Auto-Vault Lock). "
                "Gunakan PIN Komandan untuk memulihkan dokumen."
            )
    else:
        st.warning(f"Status tidak dikenal: {status}")


def _render_portal(device_profile: str) -> None:
    """Kolom kiri: simulasi layar aktivitas prajurit di portal web publik."""
    st.subheader("🖥️ Simulasi Layar Aktivitas Prajurit")
    st.caption("Portal Web Publik / Instansi — di luar kendali jaringan militer TNI AD.")

    with st.container(border=True):
        st.markdown("#### 🏛️ Portal Informasi Publik & Pengumuman Instansi")
        st.markdown(
            "Selamat datang di portal layanan publik. "
            "Silakan akses pengumuman, menu navigasi, dan promo di bawah ini."
        )
        st.caption(
            "Domain ini dianggap **sah** oleh URL blacklisting — padahal server "
            "Linux VPS-nya dapat dijebol. Inilah celah Social Engineering."
        )

        st.markdown("**1. Unduh Pengumuman Resmi**")
        st.caption(
            "Watering Hole: peretas menjebol Linux VPS, menyuntikkan onClick "
            "pada tombol resmi, lalu me-restart layanan. Bibit "
            "`silent_rat_vps_exploit.pkg` meluncur diam-diam (Silent Auto-Install / T1189)."
        )
        if st.button(BTN_WATERING_HOLE, key="btn_watering_hole"):
            _run_attack("watering_hole", device_profile)

        st.markdown("**2. Menu Navigasi Portal**")
        st.caption(
            "Clickjacking / UI Redressing: iframe transparan menempel di atas "
            "menu navigasi. Klik yang tampak sah mengunduh `transparent_menu_spyware.apk`."
        )
        if st.button(BTN_CLICKJACKING, key="btn_clickjacking"):
            _run_attack("clickjacking", device_profile)

        st.markdown("**3. Banner Iklan Promo**")
        st.caption(
            "Malvertising: exploit diselundupkan lewat jaringan iklan portal berita. "
            "Klik tidak sengaja menjatuhkan `ad_banner_infostealer.exe` ke ruang transit."
        )
        if st.button(BTN_MALVERTISING, key="btn_malvertising"):
            _run_attack("malvertising", device_profile)

        st.markdown("**4. Darurat — Zero-Day ke Folder Rahasia**")
        st.caption(
            "Post-Exploitation: malware yang sudah berada di perangkat memindai "
            "dokumen_rahasia_tni/ dan membaca honeyfile, memicu Auto-Vault Lock."
        )
        if st.button(BTN_ZERODAY, key="btn_zeroday"):
            _run_attack("zeroday_honeyfile", device_profile)


def _render_system_apps(installed_apps: list) -> None:
    """Panel forensik kiri: bukti sistem utama tetap 0% malware."""
    st.markdown("##### 🧬 Bukti Direktori Sistem — `installed_system_apps/`")
    st.caption(
        "Pembuktian untuk juri: `silent_rat_vps_exploit.pkg`, `transparent_menu_spyware.apk`, "
        "dan `ad_banner_infostealer.exe` TIDAK PERNAH masuk ke sistem perangkat prajurit."
    )
    if not installed_apps:
        st.warning("Folder sistem kosong.")
        return
    for name in installed_apps:
        st.markdown(f"✅ **`{name}`** — aplikasi resmi terverifikasi")
    st.success("Malware ter-install di sistem: **0%** (100% diblokir di staging).")


def _render_vault(vault_files: list, vault_previews: dict, is_vault_locked: bool) -> None:
    """Panel forensik kanan: isi brankas live (teks asli vs ciphertext)."""
    st.markdown("##### 🗄️ Isi Brankas Dokumen Rahasia — `dokumen_rahasia_tni/`")
    if is_vault_locked:
        st.error("Status: **TERKUNCI (AES-FERNET)** — hacker hanya melihat ciphertext acak.")
    else:
        st.success("Status: **TERBUKA (AKTIF)** — teks asli terbaca jelas.")

    if not vault_files:
        st.warning("Brankas kosong. Lakukan Reset Sandbox.")
        return

    for name in vault_files:
        preview = vault_previews.get(name, "")
        if name.endswith(".locked"):
            st.markdown(f"🔒 **`{name}`** (ciphertext Fernet)")
        elif name == "_HONEYFILE_SANDI_OPERASI.txt":
            st.markdown(f"🍯 **`{name}`** (honeyfile — umpan jebakan)")
        else:
            st.markdown(f"📄 **`{name}`**")
        st.code(preview if preview else "(kosong / tidak terbaca)", language="text")


def _render_narrative() -> None:
    """Konteks eksplisit Bagian 2 — wajib tampil di UI (aturan Modul 4 / Bagian 0.4)."""
    with st.expander("📖 Konteks Operasi — Mengapa Firewall & Antivirus Biasa Gagal", expanded=False):
        st.markdown(
            """
**Akar masalah: faktor manusia (Social Engineering).**  
Pintu masuk paling rentan bukan firewall server pusat, melainkan perangkat prajurit
yang dimanipulasi saat mengakses situs berita populer atau portal informasi publik.

**Silent Auto-Install (Drive-By Compromise — MITRE ATT&CK T1189).**  
Ketika prajurit mengklik elemen berbahaya, browser mengeksekusi pengunduhan dan
pemasangan RAT/spyware **diam-diam tanpa notifikasi izin instalasi**, memberi
peretas akses penuh untuk mencuri dokumen rahasia TNI AD.

**Mengapa firewall & antivirus biasa gagal.**  
TNI AD tidak memiliki kendali atas keamanan server website publik di luar jaringan
militer. Jika situs resmi/terkenal disusupi dari sisi server, URL blacklisting tetap
meloloskan trafik karena menganggap domain tersebut sah.

**4 vektor yang disimulasikan:**  
1. **Watering Hole** — pembobolan Linux VPS + injeksi `onClick` tombol "Unduh Pengumuman Resmi".  
2. **Clickjacking** — iframe transparan di atas menu navigasi.  
3. **Malvertising** — banner iklan beracun di portal berita nasional.  
4. **Zero-Day Honeyfile** — pemindaian folder rahasia yang menyentuh `_HONEYFILE_SANDI_OPERASI.txt`.

**Solusi WIRA-SHIELD (Defense-in-Depth 2 Lapis):**  
- **Lapis 1 — Pre-Install Staging Interceptor:** setiap installer dari browser wajib
  melewati `browser_temp_staging/`. Bibit gelap diputus pada **0% Installed** dan
  dihapus permanen dalam hitungan milidetik.  
- **Lapis 2 — Honey-File Trap & Auto-Vault Lock:** sentuhan pada honeyfile otomatis
  mengenkripsi seluruh dokumen rahasia (Fernet AES-128-CBC + HMAC) menjadi `.locked`.
  Brankas hanya terbuka dengan PIN Komandan.
            """
        )


def _render_logs(logs: list) -> None:
    """Tabel riwayat insiden dari security_logs.json."""
    st.markdown("##### 🧾 Tabel Log Forensik — `security_logs.json`")
    if not logs:
        st.info("Belum ada insiden tercatat. Klik salah satu skenario serangan.")
        return
    try:
        st.dataframe(logs, hide_index=True)
    except TypeError:
        # Versi Streamlit lama tidak mendukung hide_index
        st.dataframe(logs)
    except Exception:
        st.table(logs)
    st.caption(f"Total {len(logs)} entri. Entri terbaru berada di baris pertama.")


# ---------------------------------------------------------------------------
# Halaman utama
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="WIRA-SHIELD Command Center",
    layout="wide",
    page_icon="🛡️",
)

_init_session_state()

# --- Sidebar: pemilih perangkat & reset (kontrak poin 1) ---
with st.sidebar:
    st.markdown("## 🛡️ WIRA-SHIELD")
    st.caption("Kartika Cyber Hackathon 2026 • Kategori 02 — Defensive Shield")
    st.divider()

    device_profile = st.selectbox("Profil Perangkat Prajurit", DEVICE_PROFILES)
    st.caption(DEVICE_NOTES.get(device_profile, ""))
    st.divider()

    if st.button("♻️ Reset Sandbox ke Kondisi Awal"):
        _reset_sandbox()
    st.caption(
        "Reset mengosongkan staging & brankas, memulihkan 2 aplikasi resmi, "
        "3 dokumen rahasia + honeyfile, kunci Fernet baru, dan log kosong."
    )
    st.divider()
    st.markdown("**Kredensial Uji Juri**")
    st.code("PIN Komandan: TNIAD2026", language="text")
    st.caption("Gunakan PIN ini pada form Otorisasi Komandan setelah Tombol 4 (Zero-Day).")

# --- Header utama (kontrak poin 1) ---
st.title("WIRA-SHIELD // Command & Endpoint Protection Center")
st.subheader(
    "Sistem Proteksi Perangkat Prajurit: Pre-Install Malware Interceptor "
    "(0% Installed) & Automated Document Vault Lock — Kategori 02: Defensive Shield"
)
_pop_flash()

app_error = st.session_state.pop("app_error", None)
if app_error:
    st.error(f"Terjadi kesalahan tak terduga: {app_error}")

_render_narrative()
st.divider()

# --- Status live (auto-init jika sandbox belum ada) ---
try:
    status = get_system_status()
except Exception as exc:
    st.error(f"Gagal membaca status sandbox: {exc}")
    st.stop()

is_vault_locked = bool(status.get("is_vault_locked"))
logs = status.get("logs") or []

# --- Baris metrik utama: 4 kolom (kontrak poin 2) ---
m1, m2, m3, m4 = st.columns(4)
m1.metric(
    "Status Perangkat",
    "DARURAT (VAULT TERKUNCI)" if is_vault_locked else "AMAN (TERLINDUNGI)",
)
m2.metric(
    "Malware Ter-install di Sistem",
    "0%",
    delta="100% Blocked at Staging",
    delta_color="off",
)
m3.metric(
    "Status Brankas Dokumen TNI",
    "TERKUNCI (AES-FERNET)" if is_vault_locked else "TERBUKA (AKTIF)",
)
m4.metric("Total Insiden Digagalkan", str(len(logs)))

st.divider()

# --- Area utama 2 kolom (kontrak poin 3) ---
col_left, col_right = st.columns(2)
with col_left:
    _render_portal(device_profile)
with col_right:
    _render_radar()

st.divider()

# --- Panel pembuktian forensik (kontrak poin 4) ---
st.subheader("🔬 Panel Pembuktian Forensik & Brankas Dokumen")
forensic_left, forensic_right = st.columns(2)
with forensic_left:
    _render_system_apps(status.get("installed_apps") or [])
with forensic_right:
    _render_vault(
        status.get("vault_files") or [],
        status.get("vault_previews") or {},
        is_vault_locked,
    )

st.markdown("##### 🔐 Form Otorisasi Komandan")
st.caption("Brankas hanya dapat dipulihkan oleh Komandan. PIN default pengujian: TNIAD2026.")
pin = st.text_input("Masukkan PIN Komandan (Default: TNIAD2026)", type="password")
if st.button("Buka Kunci Brankas"):
    if not pin:
        st.error("PIN Komandan wajib diisi.")
    else:
        _unlock_vault(pin)

st.divider()
_render_logs(logs)

st.caption(
    "WIRA-SHIELD (Waspada Intersepsi Runtime & Automated Shield) — "
    "PUSSIBERAD TNI AD & CODEPOLITAN • Kartika Cyber Hackathon 2026. "
    "Seluruh operasi file dikunci di ./sandbox_device_prajurit oleh is_safe_path()."
)
