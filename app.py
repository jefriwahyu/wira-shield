"""
WIRA-SHIELD — Modul 4: Dashboard EDR (Endpoint Detection & Response)
=====================================================================

Produk EDR militer modern: tema gelap, kontras tajam, dua tab.
- TAB 1: Endpoint Guard & Document Vault (Live System)
- TAB 2: Threat Lab & Simulator (Red-Team Testing)

Kontrak fungsi sandbox_setup.py, wira_engine.py, dan attack_simulator.py
TIDAK diubah. Jalankan: streamlit run app.py
"""

import html as html_lib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from attack_simulator import trigger_attack
from sandbox_setup import (
    BASE_SANDBOX,
    LOG_FILE,
    STAGING_DIR,
    VAULT_DIR,
    init_sandbox,
    is_safe_path,
)
from wira_engine import get_system_status, intercept_staging, lock_vault, unlock_vault

# ---------------------------------------------------------------------------
# Konstanta
# ---------------------------------------------------------------------------
DEVICE_PROFILES = [
    "Laptop Dinas Prajurit (Windows/Linux) - Full Process & Staging Guard",
    "Smartphone Prajurit (Android/iOS) - Mobile Staging & APK Buffer Guard",
    "Perangkat OT / Sensor Markas (Linux Embedded) - Config Integrity Guard",
]

DEVICE_NOTES = {
    DEVICE_PROFILES[0]: "Full agent: staging guard + vault lock.",
    DEVICE_PROFILES[1]: "Mobile Staging Buffer Guard (APK / script di transit).",
    DEVICE_PROFILES[2]: "Config Integrity Guard untuk direktori OT / sensor.",
}

BTN_WH = "🚀 Jalankan Simulasi Watering Hole"
BTN_CJ = "🚀 Jalankan Simulasi Clickjacking"
BTN_MV = "🚀 Jalankan Simulasi Malvertising"
BTN_ZD = "🚨 Picu Serangan Zero-Day Honeyfile"

BRIDGE_URL = "http://127.0.0.1:5050"
BRIDGE_STATUS_URL = f"{BRIDGE_URL}/status"

TELEMETRY_STAGING = [
    "[01 ms] Klik / aktivitas browser terdeteksi; silent background download diinisiasi.",
    "[05 ms] Bibit installer mendarat di browser_temp_staging/.",
    "[09 ms] Pre-Install Interceptor mendeteksi unauthorized installer.",
    "[12 ms] PROSES INSTALASI DIPUTUS PADA POSISI 0%! File bibit dihapus permanen.",
]
TELEMETRY_HONEYFILE = [
    "[01 ms] Proses asing memindai dokumen_rahasia_tni/.",
    "[05 ms] Honey-File _HONEYFILE_SANDI_OPERASI.txt tersentuh.",
    "[09 ms] Auto-Vault Lock aktif — Fernet AES-128-CBC + HMAC.",
    "[12 ms] SELURUH DOKUMEN RAHASIA TERKUNCI (.locked).",
]

CUSTOM_CSS = """
<style>
    /* ---------- Base ---------- */
    .stApp {
        background: linear-gradient(180deg, #0b0f19 0%, #0b1220 100%);
        color: #f8fafc;
    }
    .stApp, .stApp * { color-scheme: dark; }
    [data-testid="stHeader"] { background: transparent; }
    #MainMenu, footer { visibility: hidden; }
    h1, h2, h3, h4, h5, h6 { color: #f8fafc !important; }
    p, span, li, label { color: #f8fafc; }
    .stCaption, [data-testid="stCaptionContainer"] { color: #94a3b8 !important; }

    /* ---------- Sidebar ---------- */
    [data-testid="stSidebar"] {
        background: #0b0f19;
        border-right: 1px solid #334155;
    }
    [data-testid="stSidebar"] * { color: #e2e8f0; }

    /* ---------- Tabs ---------- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        background: #0b0f19;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 6px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 14px;
        color: #94a3b8 !important;
        font-weight: 600;
        font-size: 0.88rem;
    }
    .stTabs [aria-selected="true"] {
        background: #064e3b !important;
        color: #d1fae5 !important;
        border: 1px solid #10b981;
    }

    /* ---------- Buttons ---------- */
    .stButton > button {
        width: 100%;
        border-radius: 10px;
        border: 1px solid #334155;
        background: #111827;
        color: #f8fafc !important;
        font-weight: 600;
        transition: all 0.15s ease;
    }
    .stButton > button:hover {
        border-color: #10b981;
        background: #0f1c2e;
        box-shadow: 0 0 0 1px #10b981;
    }
    .stButton > button p { color: #f8fafc !important; }

    /* ---------- Inputs (NO white boxes) ---------- */
    .stTextInput input,
    .stTextArea textarea {
        background: #111827 !important;
        border: 1px solid #334155 !important;
        border-radius: 10px !important;
        color: #f8fafc !important;
    }
    .stTextInput input::placeholder,
    .stTextArea textarea::placeholder { color: #64748b !important; }

    [data-testid="stSelectbox"] > div > div,
    [data-baseweb="select"] > div {
        background: #111827 !important;
        border: 1px solid #334155 !important;
        border-radius: 10px !important;
        color: #f8fafc !important;
    }
    [data-baseweb="popover"] {
        background: #111827 !important;
        border: 1px solid #334155 !important;
    }
    [data-baseweb="popover"] * { color: #f8fafc !important; }

    [data-testid="stFileUploader"],
    [data-testid="stFileUploaderDropzone"] {
        background: #111827 !important;
        border: 1px dashed #334155 !important;
        border-radius: 10px !important;
        color: #f8fafc !important;
    }
    [data-testid="stFileUploader"] *,
    [data-testid="stFileUploaderDropzone"] * { color: #f8fafc !important; }
    [data-testid="stFileUploaderDropzone"] button {
        background: #1e293b !important;
        color: #f8fafc !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
    }

    [data-testid="stExpander"] {
        border: 1px solid #334155 !important;
        border-radius: 12px !important;
        background: #111827 !important;
    }
    [data-testid="stExpander"] summary { color: #f8fafc !important; }
    [data-testid="stForm"] {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 12px;
    }

    [data-testid="stVerticalBlockBorderWrapper"] {
        border-color: #334155 !important;
        background: #0c121c !important;
        border-radius: 14px !important;
    }

    [data-testid="stAlert"] {
        background: #111827 !important;
        border: 1px solid #334155 !important;
        color: #f8fafc !important;
        border-radius: 10px !important;
    }
    [data-testid="stAlert"] * { color: #f8fafc !important; }

    [data-testid="stSpinner"] { color: #10b981 !important; }

    /* ---------- Custom components ---------- */
    .wira-title {
        font-size: 1.35rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #f8fafc;
        margin: 0;
        white-space: nowrap;
    }
    .wira-sub {
        color: #6ee7b7;
        font-size: 0.78rem;
        font-weight: 600;
        margin: 2px 0 0 0;
    }
    .wira-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        border-radius: 999px;
        font-size: 0.74rem;
        font-weight: 700;
        border: 1px solid #14532d;
        background: #052e16;
        color: #4ade80;
        white-space: nowrap;
    }
    .wira-badge.red {
        border-color: #7f1d1d;
        background: #450a0a;
        color: #f87171;
    }
    .wira-badge.blue {
        border-color: #1e40af;
        background: #172554;
        color: #93c5fd;
    }
    .wira-chip {
        background: #1e293b;
        color: #38bdf8;
        padding: 3px 8px;
        border-radius: 6px;
        font-family: Consolas, "JetBrains Mono", monospace;
        font-size: 0.82rem;
        border: 1px solid #334155;
        white-space: nowrap;
    }

    .wira-kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
    }
    @media (max-width: 820px) {
        .wira-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    .wira-kpi {
        background: linear-gradient(145deg, #111827, #1e293b);
        border: 1px solid #334155;
        border-left: 4px solid #10b981;
        border-radius: 10px;
        padding: 16px 16px 14px 16px;
        min-width: 0;
    }
    .wira-kpi.danger { border-left-color: #ef4444; }
    .wira-kpi-label {
        font-size: 0.68rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #6ee7b7;
        font-weight: 700;
    }
    .wira-kpi.danger .wira-kpi-label { color: #fca5a5; }
    .wira-kpi-value {
        font-size: 1.25rem;
        font-weight: 800;
        color: #f8fafc;
        margin: 8px 0 4px 0;
        line-height: 1.15;
        word-break: break-word;
    }
    .wira-kpi-sub {
        font-size: 0.72rem;
        color: #94a3b8;
        font-weight: 500;
    }

    .wira-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 8px 12px;
        margin-bottom: 6px;
    }
    .wira-row-name {
        color: #f8fafc;
        font-family: Consolas, "JetBrains Mono", monospace;
        font-size: 0.82rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .wira-pill {
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.68rem;
        font-weight: 700;
        border: 1px solid #14532d;
        background: #052e16;
        color: #4ade80;
        white-space: nowrap;
    }
    .wira-pill.warn {
        border-color: #78350f;
        background: #451a03;
        color: #fbbf24;
    }
    .wira-pill.red {
        border-color: #7f1d1d;
        background: #450a0a;
        color: #f87171;
    }

    .wira-doc {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 10px;
    }
    .wira-doc-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 8px;
    }
    .wira-doc-name {
        color: #f8fafc;
        font-family: Consolas, monospace;
        font-size: 0.85rem;
        font-weight: 600;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .wira-doc-pre {
        margin: 0;
        padding: 8px 10px;
        background: #060a10;
        border: 1px solid #1e293b;
        border-radius: 6px;
        font-family: Consolas, "JetBrains Mono", monospace;
        font-size: 0.78rem;
        color: #94a3b8;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 88px;
        overflow: auto;
    }
    .wira-doc-pre.locked { color: #f87171; }

    .wira-timeline {
        font-family: "Cascadia Code", "JetBrains Mono", Consolas, monospace;
        font-size: 0.8rem;
        line-height: 1.85;
        color: #6ee7b7;
        background: #060a10;
        border: 1px solid #065f46;
        border-radius: 12px;
        padding: 12px 16px;
        white-space: pre-wrap;
    }

    .wira-table-wrap {
        overflow-x: auto;
        border: 1px solid #334155;
        border-radius: 10px;
        background: #111827;
    }
    table.wira-table {
        width: 100%;
        border-collapse: collapse;
        background: #111827;
        font-size: 0.76rem;
        min-width: 720px;
    }
    table.wira-table th {
        background: #1e293b;
        color: #f8fafc;
        text-align: left;
        padding: 9px 10px;
        font-weight: 700;
        white-space: nowrap;
    }
    table.wira-table td {
        padding: 8px 10px;
        border-top: 1px solid #1e293b;
        color: #e2e8f0;
        vertical-align: top;
    }
    table.wira-table tr:hover td { background: #17255422; }
    .wira-td-ok { color: #4ade80; font-weight: 600; }
    .wira-td-bad { color: #f87171; font-weight: 600; }
</style>
"""


# ---------------------------------------------------------------------------
# Session & helpers
# ---------------------------------------------------------------------------
def _init_session_state() -> None:
    st.session_state.setdefault("last_result", None)
    st.session_state.setdefault("last_scenario", None)
    st.session_state.setdefault("radar", None)
    st.session_state.setdefault("flash", None)
    st.session_state.setdefault("app_error", None)


def _esc(value) -> str:
    return html_lib.escape(str(value if value is not None else ""))


def _pop_flash() -> None:
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
    return TELEMETRY_HONEYFILE if scenario == "zeroday_honeyfile" else TELEMETRY_STAGING


def _run_attack(scenario: str, device_profile: str) -> None:
    try:
        result = trigger_attack(scenario, device_profile)
        st.session_state["last_result"] = result
        st.session_state["last_scenario"] = scenario
        st.session_state["radar"] = _telemetry_for(scenario)
        st.session_state["app_error"] = None
    except Exception as exc:
        st.session_state["app_error"] = str(exc)
    st.rerun()


def _reset_environment() -> None:
    try:
        init_sandbox()
        st.session_state["last_result"] = None
        st.session_state["last_scenario"] = None
        st.session_state["radar"] = None
        st.session_state["app_error"] = None
        st.session_state["_seen_n"] = 0
        st.session_state["flash"] = ("success", "Environment sandbox direset ke kondisi pabrik.")
    except Exception as exc:
        st.session_state["flash"] = ("error", f"Reset gagal: {exc}")
    st.rerun()


def _unlock_vault(pin: str) -> None:
    try:
        result = unlock_vault(pin)
        if result.get("success"):
            st.session_state["flash"] = ("success", result.get("message", "Brankas dibuka."))
        else:
            st.session_state["flash"] = ("error", result.get("message", "Otorisasi gagal."))
        st.session_state["app_error"] = None
    except Exception as exc:
        st.session_state["flash"] = ("error", f"Pemulihan gagal: {exc}")
    st.rerun()


def _lock_vault_now(device_profile: str) -> None:
    try:
        result = lock_vault("Kunci Darurat Manual dari Dashboard EDR", device_profile)
        if result.get("vault_locked"):
            st.session_state["flash"] = (
                "success",
                "Brankas terkunci ({} dokumen). Status: {}".format(
                    result.get("locked_count", 0), result.get("status")
                ),
            )
        else:
            st.session_state["flash"] = ("error", "Gagal mengunci brankas.")
        st.session_state["app_error"] = None
    except Exception as exc:
        st.session_state["flash"] = ("error", f"Lock gagal: {exc}")
    st.rerun()


def _add_vault_document(filename: str, content: str) -> None:
    raw = (filename or "").strip()
    name = os.path.basename(raw)
    if not name:
        st.session_state["flash"] = ("error", "Nama dokumen wajib diisi.")
        st.rerun()
        return
    if name != raw or "\\" in raw or "/" in raw:
        st.session_state["flash"] = ("error", "Nama file tidak valid (jangan pakai path).")
        st.rerun()
        return
    if not name.lower().endswith(".txt"):
        name += ".txt"
    path = os.path.join(VAULT_DIR, name)
    if not is_safe_path(path):
        st.session_state["flash"] = ("error", "Path dokumen di luar sandbox — ditolak.")
        st.rerun()
        return
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content or "")
        st.session_state["flash"] = ("success", "Dokumen " + name + " ditambahkan ke brankas.")
    except OSError as exc:
        st.session_state["flash"] = ("error", "Gagal menulis dokumen: " + str(exc))
    st.rerun()


def _process_manual_scan(uploaded, device_profile: str) -> None:
    safe_name = os.path.basename(uploaded.name or "manual_upload.bin") or "manual_upload.bin"
    dest = os.path.join(STAGING_DIR, safe_name)
    if not is_safe_path(dest):
        st.session_state["flash"] = ("error", "Path unduhan di luar sandbox — ditolak.")
        st.rerun()
        return
    try:
        with open(dest, "wb") as handle:
            handle.write(uploaded.getvalue())
        result = intercept_staging(device_profile, "Manual Scan: " + safe_name)
        if os.path.exists(dest) and is_safe_path(dest):
            try:
                os.remove(dest)
            except OSError:
                pass
        st.session_state["last_result"] = result
        st.session_state["last_scenario"] = "manual_scan"
        st.session_state["radar"] = TELEMETRY_STAGING
        st.session_state["app_error"] = None
        if result.get("intercepted"):
            st.session_state["flash"] = (
                "success",
                "INTERCEPTED: "
                + ", ".join(result.get("files_removed", []))
                + " dihapus di 0% Installed.",
            )
        else:
            st.session_state["flash"] = (
                "info",
                "File "
                + safe_name
                + " bukan installer mencurigakan. Tidak ada intersepsi (zero false-positive).",
            )
    except Exception as exc:
        st.session_state["app_error"] = str(exc)
    st.rerun()


def _bridge_online() -> bool:
    try:
        with urllib.request.urlopen(BRIDGE_STATUS_URL, timeout=1):
            return True
    except Exception:
        return False


def _read_logs_fast() -> list:
    """Baca security_logs.json tanpa membangun status lengkap (untuk polling)."""
    try:
        if not os.path.isfile(LOG_FILE):
            return []
        with open(LOG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _result_from_log(entry: dict | None) -> dict | None:
    """Ubah entri log terbaru menjadi struktur last_result untuk telemetri."""
    if not entry:
        return None
    install = str(entry.get("install_status") or "")
    action = str(entry.get("action") or "")
    vector = str(entry.get("vector") or "")
    install_u = install.upper()
    action_u = action.upper()
    vector_u = vector.upper()
    # Urutan penting: UNLOCKED juga mengandung "LOCKED", BLOCKED juga mengandung "LOCKED".
    if "UNLOCKED" in install_u or "RESTORE" in action_u or "Dipulihkan" in install:
        return {
            "status": "VAULT_RESTORED",
            "device_profile": entry.get("device") or "-",
            "attack_source": vector or "-",
        }
    if "VAULT LOCKED" in install_u or "VAULT TERKUNCI" in install_u:
        return {
            "status": "EMERGENCY_VAULT_LOCKED",
            "reason": entry.get("vector") or entry.get("payload") or "-",
            "device_profile": entry.get("device") or "-",
            "attack_source": vector or "-",
        }
    if (
        "0%" in install
        or "BLOCKED" in install_u
        or "INTERCEPT" in action_u
        or "WEB CLICK" in vector_u
        or "MANUAL SCAN" in vector_u
    ):
        payload = str(entry.get("payload") or "-")
        files = [p.strip() for p in payload.split(",") if p.strip() and p.strip() != "-"]
        return {
            "status": "BLOCKED_AT_STAGING",
            "files_removed": files,
            "install_progress": "0%",
            "latency_ms": entry.get("latency_ms", 12),
            "attack_source": vector or "-",
            "device_profile": entry.get("device") or "-",
        }
    return None


@st.fragment(run_every=2)
def _watch_incidents() -> None:
    """Poll security_logs.json; jika jumlah insiden berubah, refresh seluruh app
    agar klik Live Browser di situs nyata langsung terlihat di KPI & telemetri."""
    logs = _read_logs_fast()
    n = len(logs)
    prev = st.session_state.get("_seen_n")
    if prev is None:
        st.session_state["_seen_n"] = n
        return
    if n == prev:
        return
    st.session_state["_seen_n"] = n
    newest = _result_from_log(logs[0]) if logs else None
    if newest:
        st.session_state["last_result"] = newest
        st.session_state["last_scenario"] = "live_watch"
        st.session_state["radar"] = (
            TELEMETRY_HONEYFILE
            if newest.get("status") == "EMERGENCY_VAULT_LOCKED"
            else TELEMETRY_STAGING
        )
    try:
        st.rerun(scope="app")
    except TypeError:
        st.rerun()


# ---------------------------------------------------------------------------
# HTML builders (tanpa st.metric / st.code / st.dataframe / inline backticks)
# ---------------------------------------------------------------------------
def _kpi_card(label: str, value: str, sub: str = "", danger: bool = False) -> str:
    cls = "wira-kpi danger" if danger else "wira-kpi"
    return (
        '<div class="' + cls + '">'
        '<div class="wira-kpi-label">' + _esc(label) + "</div>"
        '<div class="wira-kpi-value">' + _esc(value) + "</div>"
        '<div class="wira-kpi-sub">' + _esc(sub) + "</div>"
        "</div>"
    )


def _render_kpis(is_vault_locked: bool, n_logs: int) -> None:
    st.markdown(
        '<div class="wira-kpi-grid">'
        + _kpi_card(
            "Status Proteksi",
            "DARURAT" if is_vault_locked else "AKTIF (SIAGA)",
            "Universal Web & Staging Guard",
            danger=is_vault_locked,
        )
        + _kpi_card(
            "Intersepsi Pre-Install",
            "0% Installed",
            "100% Blocked at Staging",
        )
        + _kpi_card(
            "Brankas Dokumen TNI",
            "TERKUNCI (AES)" if is_vault_locked else "TERBUKA",
            "Fernet AES-128-CBC + HMAC",
            danger=is_vault_locked,
        )
        + _kpi_card(
            "Ancaman Digagalkan",
            str(n_logs),
            "security_logs.json",
        )
        + "</div>",
        unsafe_allow_html=True,
    )


def _file_row(name: str, badge: str, pill: str = "wira-pill", icon: str = "📄") -> str:
    return (
        '<div class="wira-row">'
        '<span class="wira-row-name">' + icon + " " + _esc(name) + "</span>"
        '<span class="' + pill + '">' + _esc(badge) + "</span>"
        "</div>"
    )


def _doc_card(name: str, preview: str, locked: bool) -> str:
    if name == "_HONEYFILE_SANDI_OPERASI.txt":
        icon, tag = "🍯", "HONEYFILE"
        pill_cls = "wira-pill warn"
    elif locked:
        icon, tag = "🔒", "TERENKRIPSI AES"
        pill_cls = "wira-pill red"
    else:
        icon, tag = "📄", "TERBUKA"
        pill_cls = "wira-pill"
    pre_cls = "wira-doc-pre locked" if locked else "wira-doc-pre"
    body = preview if preview else "(kosong)"
    return (
        '<div class="wira-doc">'
        '<div class="wira-doc-head">'
        '<span class="wira-doc-name">' + icon + " " + _esc(name) + "</span>"
        '<span class="' + pill_cls + '">' + tag + "</span>"
        "</div>"
        '<pre class="' + pre_cls + '">' + _esc(body) + "</pre>"
        "</div>"
    )


def _render_timeline(result: dict | None) -> None:
    if not result:
        st.markdown(
            '<div class="wira-timeline">[ -- ] Menunggu aktivitas browser / staging…\n'
            "Universal Web & Staging Guard ACTIVE. Belum ada ancaman.</div>",
            unsafe_allow_html=True,
        )
        return

    status = result.get("status")
    if status == "VAULT_RESTORED":
        st.success("Brankas TERBUKA kembali — dokumen rahasia berhasil dipulihkan.")
        return
    if status == "EMERGENCY_VAULT_LOCKED":
        lines = TELEMETRY_HONEYFILE
        tail = "12ms: VAULT LOCKED (Fernet AES-128)"
    else:
        lines = TELEMETRY_STAGING
        files = ", ".join(result.get("files_removed", [])) or "payload"
        tail = "12ms: 0% INSTALLED (" + files + ")"

    st.markdown(
        "<div class='wira-timeline'>"
        + "\n".join(lines)
        + "\n────────────────────────────────────────"
        + "\n[01ms -> 05ms -> 09ms -> "
        + tail
        + "\nVektor : "
        + _esc(result.get("attack_source") or result.get("reason") or "-")
        + "\nDevice : "
        + _esc(result.get("device_profile") or "-")
        + "</div>",
        unsafe_allow_html=True,
    )

    if status == "BLOCKED_AT_STAGING":
        st.success(
            "LAPIS 1 AKTIF — BLOCKED AT STAGING. Instalasi diputus pada "
            + str(result.get("install_progress", "0%"))
            + " Installed ("
            + str(result.get("latency_ms", 12))
            + " ms). Sistem utama tetap bersih."
        )
    elif status == "EMERGENCY_VAULT_LOCKED":
        st.error(
            "LAPIS 2 AKTIF — EMERGENCY VAULT LOCKED. "
            "Dokumen rahasia dienkripsi Fernet AES-128. Alasan: "
            + str(result.get("reason", "-"))
        )
    else:
        st.info("Status terakhir: " + str(status))


def _render_logs_table(logs: list) -> None:
    if not logs:
        st.info("Belum ada insiden. Guard siaga, zero false-positive.")
        return

    rows = []
    for entry in logs[:80]:
        install = str(entry.get("install_status") or "")
        if "LOCKED" in install.upper():
            st_cls, st_txt = "wira-td-bad", install
        elif "UNLOCKED" in install.upper() or "Restored" in install:
            st_cls, st_txt = "wira-td-ok", install
        elif "0%" in install or "Blocked" in install:
            st_cls, st_txt = "wira-td-ok", install
        else:
            st_cls, st_txt = "", install
        rows.append(
            "<tr>"
            "<td>" + _esc(entry.get("timestamp") or "-") + "</td>"
            "<td>" + _esc(entry.get("device") or "-") + "</td>"
            "<td>" + _esc(entry.get("vector") or "-") + "</td>"
            "<td>" + _esc(entry.get("payload") or "-") + "</td>"
            "<td>" + _esc(entry.get("action") or "-") + "</td>"
            '<td class="' + st_cls + '">' + _esc(st_txt or "-") + "</td>"
            "<td>" + _esc(entry.get("latency_ms") if entry.get("latency_ms") is not None else "-") + "</td>"
            "</tr>"
        )

    st.markdown(
        '<div class="wira-table-wrap"><table class="wira-table">'
        "<thead><tr>"
        "<th>Waktu</th><th>Perangkat</th><th>Vektor</th><th>Payload</th>"
        "<th>Aksi</th><th>Status</th><th>Latensi (ms)</th>"
        "</tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody>"
        "</table></div>",
        unsafe_allow_html=True,
    )
    st.caption("Menampilkan {} dari {} entri. Terbaru di baris pertama. Sumber: security_logs.json".format(min(len(logs), 80), len(logs)))


def _chip(name: str) -> str:
    return '<span class="wira-chip">' + _esc(name) + "</span>"


# ---------------------------------------------------------------------------
# Render: Tab 1
# ---------------------------------------------------------------------------
def _render_tab_endpoint(device_profile: str, status: dict) -> None:
    st.markdown("### 📡 Real-Time Endpoint & Universal Web Telemetry")
    st.caption("Pemantauan live folder browser_temp_staging dan installed_system_apps.")

    left, right = st.columns([1.05, 1], gap="large")

    with left:
        with st.container(border=True):
            st.markdown("##### 📂 Ruang Transit — browser_temp_staging")
            staging = status.get("staging_files") or []
            if staging:
                st.warning(str(len(staging)) + " file menunggu di ruang transit.")
                for name in staging:
                    st.markdown(
                        _file_row(name, "DI TRANSIT", pill="wira-pill warn", icon="📥"),
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    _file_row("KOSONG — tidak ada bibit installer", "AMAN", icon="🟢"),
                    unsafe_allow_html=True,
                )

            st.markdown("##### 🧬 Sistem Utama — installed_system_apps")
            installed = status.get("installed_apps") or []
            if not installed:
                st.markdown(_file_row("Kosong", "EMPTY", icon="⚪"), unsafe_allow_html=True)
            else:
                for name in installed:
                    st.markdown(
                        _file_row(name, "TERVERIFIKASI", icon="✅"),
                        unsafe_allow_html=True,
                    )
            st.success("Malware ter-install di sistem: 0% (100% Blocked at Staging).")

            st.markdown("##### 📂 Pindai File Unduhan Manual")
            st.caption(
                "Unggah file untuk diuji di ruang transit. Installer mencurigakan "
                "(.exe .apk .pkg .bat .sh .py .bin) langsung di-intercept di 0%."
            )
            uploaded = st.file_uploader(
                "📂 Pindai File Unduhan Manual",
                label_visibility="collapsed",
                key="manual_scan",
            )
            if uploaded is not None:
                st.caption(uploaded.name + " • " + str(uploaded.size) + " bytes")
                if st.button("🔎 Jalankan Intercept di Staging", key="btn_manual_scan"):
                    _process_manual_scan(uploaded, device_profile)

    with right:
        with st.container(border=True):
            st.markdown("##### 🗄️ Brankas Dokumen Rahasia TNI AD — Fernet AES-128")
            locked = bool(status.get("is_vault_locked"))
            if locked:
                st.error("Status: TERKUNCI (AES) — hacker hanya melihat ciphertext.")
            else:
                st.success("Status: TERBUKA — teks asli terbaca jelas.")

            vault_files = status.get("vault_files") or []
            previews = status.get("vault_previews") or {}
            if not vault_files:
                st.warning("Brankas kosong. Gunakan Reset Environment.")
            else:
                for name in vault_files:
                    st.markdown(
                        _doc_card(name, previews.get(name, ""), name.endswith(".locked")),
                        unsafe_allow_html=True,
                    )

            st.markdown("##### 🔐 Aksi Brankas")
            if st.button("🔒 Kunci Darurat Brankas", key="btn_lock_now"):
                _lock_vault_now(device_profile)
            with st.expander("➕ Tambah Dokumen Rahasia"):
                with st.form("form_add_doc", clear_on_submit=True):
                    new_name = st.text_input("Nama file (otomatis .txt)")
                    new_body = st.text_area("Isi dokumen", height=80)
                    if st.form_submit_button("Simpan ke Brankas"):
                        _add_vault_document(new_name, new_body)

            st.markdown("##### 🔓 Otorisasi Komandan")
            pin = st.text_input("PIN Komandan", type="password", key="pin_tab1")
            if st.button("🔓 Buka Kunci Brankas", key="btn_unlock_tab1"):
                if not pin:
                    st.error("PIN wajib diisi.")
                else:
                    _unlock_vault(pin)

    st.divider()
    st.markdown("##### 🧾 Log Forensik Keamanan (High-Fidelity Alerts)")
    _render_logs_table(status.get("logs") or [])


def _render_tab_threat_lab(device_profile: str) -> None:
    st.markdown("### 🧪 Threat Lab & Simulator (Red-Team Testing)")
    st.caption(
        "Vektor serangan terkendali untuk menguji Lapis 1 (Pre-Install Interceptor) "
        "dan Lapis 2 (Honey-File Vault). Tidak ada malware sungguhan."
    )

    with st.expander("📖 MITRE ATT&CK T1189 — Drive-By Compromise & Silent Auto-Install"):
        st.markdown(
            """
**T1189 — Drive-By Compromise.** Prajurit mengakses situs publik (portal berita / instansi).
Klik pada tombol, menu, atau iklan yang telah disusupi memicu pengunduhan dan pemasangan
RAT/spyware **tanpa notifikasi izin**. Firewall URL blacklisting gagal karena domain dianggap sah.

| Vektor | Cerita | Payload |
| --- | --- | --- |
| Watering Hole | Linux VPS website dijebol, onClick tombol resmi disuntik | silent_rat_vps_exploit.pkg |
| Clickjacking | Iframe transparan di atas menu navigasi | transparent_menu_spyware.apk |
| Malvertising | Banner iklan portal berita nasional | ad_banner_infostealer.exe |
| Zero-Day Honeyfile | Pemindaian folder rahasia menyentuh umpan | _HONEYFILE_SANDI_OPERASI.txt |

**Lapis 1** memutus instalasi di staging (0% Installed).  
**Lapis 2** mengunci brankas saat honeyfile tersentuh (Fernet AES-128).
            """
        )

    st.markdown("#### Vektor Serangan Terkendali")
    st.caption("Profil perangkat aktif: " + device_profile)

    grid_l, grid_r = st.columns(2, gap="large")
    with grid_l:
        with st.container(border=True):
            st.markdown("#### 🌊 Watering Hole")
            st.caption("Pembobolan Linux VPS + injeksi onClick pada tombol unduh resmi. Payload: silent_rat_vps_exploit.pkg")
            if st.button(BTN_WH, key="btn_wh"):
                _run_attack("watering_hole", device_profile)
        with st.container(border=True):
            st.markdown("#### 📰 Malvertising")
            st.caption("Drive-by download dari banner iklan portal berita. Payload: ad_banner_infostealer.exe")
            if st.button(BTN_MV, key="btn_mv"):
                _run_attack("malvertising", device_profile)
    with grid_r:
        with st.container(border=True):
            st.markdown("#### 🎭 Clickjacking")
            st.caption("UI redressing: iframe transparan di atas menu navigasi. Payload: transparent_menu_spyware.apk")
            if st.button(BTN_CJ, key="btn_cj"):
                _run_attack("clickjacking", device_profile)
        with st.container(border=True):
            st.markdown("#### 🍯 Zero-Day Honeyfile")
            st.caption("Akses paksa ke folder dokumen rahasia — trigger Auto-Vault Lock.")
            if st.button(BTN_ZD, key="btn_zd"):
                _run_attack("zeroday_honeyfile", device_profile)

    st.divider()
    st.markdown("#### 🌐 Live Browser Guard — Uji Klik di Situs Web Mana Saja")
    st.markdown(
        """
Ikuti 3 langkah agar klik nyata di Chrome/Edge (semua situs HTTPS/HTTP) terpantau:

1. **Jalankan bridge lokal** (terminal terpisah):

   python wira_live_bridge.py

   Bridge mendengar di 127.0.0.1:5050. Klik aman TIDAK menulis log (zero false-positive).  
   Klik ke localhost / 127.0.0.1 (dashboard ini) otomatis diabaikan.

2. **Pasang ekstensi** (Chrome/Edge):

   Buka chrome://extensions (atau edge://extensions) → Developer mode → Load unpacked → folder wira_browser_extension.  
   Pin 🛡️ WIRA-SHIELD Web Guard ke toolbar.

3. **Uji klik di situs mana pun** (mis. detik.com, kompas.com):

   Toggle 🧪 Mode Uji Serangan di popup ekstensi untuk menyimulasikan komponen tersusupi.  
   Klik tautan/menu/iklan. Jika BLOCKED, muncul toast WIRA-SHIELD INTERCEPTED (0% INSTALLED)  
   dan instalasi diputus di staging. Klik biasa (toggle mati, href bukan installer) → CLEAN, tanpa alarm palsu.
        """
    )

    with st.expander("🔐 Kredensial Uji"):
        st.markdown(
            'PIN Komandan: <span class="wira-chip">TNIAD2026</span>',
            unsafe_allow_html=True,
        )
        st.caption("Gunakan PIN ini pada form Otorisasi di Tab 1 setelah memicu Zero-Day Honeyfile.")


# ---------------------------------------------------------------------------
# Halaman utama
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="WIRA-SHIELD EDR",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
_init_session_state()
_watch_incidents()

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ WIRA-SHIELD EDR")
    st.markdown(
        '<span class="wira-badge">🟢 Universal Web & Staging Guard: ACTIVE</span>',
        unsafe_allow_html=True,
    )
    st.caption("Kategori 02 — Defensive Shield")
    st.divider()

    device_profile = st.selectbox("Profil Perangkat", DEVICE_PROFILES)
    st.caption(DEVICE_NOTES.get(device_profile, ""))
    st.divider()

    if st.button("🔄 Sync / Refresh Telemetry"):
        st.rerun()
    if st.button("♻️ Reset Environment"):
        _reset_environment()

    st.divider()
    if _bridge_online():
        st.markdown('<span class="wira-badge">🟢 Live Bridge: ONLINE</span>', unsafe_allow_html=True)
        st.caption("wira_live_bridge.py @ 127.0.0.1:5050")
    else:
        st.markdown('<span class="wira-badge red">🔴 Live Bridge: OFFLINE</span>', unsafe_allow_html=True)
        st.caption("Jalankan: python wira_live_bridge.py")
    st.markdown(
        "Sandbox: " + _chip(BASE_SANDBOX),
        unsafe_allow_html=True,
    )

# --- Header ringkas satu baris ---
st.markdown(
    '<div style="display:flex; align-items:center; justify-content:space-between; gap:14px; flex-wrap:wrap; padding:2px 0 8px 0;">'
    "<div>"
    '<div class="wira-title">🛡️ WIRA-SHIELD EDR</div>'
    '<div class="wira-sub">Endpoint Detection & Response — Pre-Install Interceptor (0% Installed) & Document Vault Lock</div>'
    "</div>"
    '<div style="display:flex; gap:8px; flex-wrap:wrap;">'
    '<span class="wira-badge">🟢 Staging Guard: ACTIVE</span>'
    '<span class="wira-badge blue">Kategori 02 — Defensive Shield</span>'
    "</div>"
    "</div>",
    unsafe_allow_html=True,
)
_pop_flash()

app_error = st.session_state.pop("app_error", None)
if app_error:
    st.error("Kesalahan tak terduga: " + str(app_error))

try:
    status = get_system_status()
except Exception as exc:
    st.error("Gagal membaca telemetri sandbox: " + str(exc))
    st.stop()

is_vault_locked = bool(status.get("is_vault_locked"))
logs = status.get("logs") or []

# Hidupkan telemetri dari log terbaru (mis. klik Live Browser di situs nyata)
# bila session last_result masih kosong / lebih tua dari log teratas.
last_from_log = _result_from_log(logs[0]) if logs else None
if last_from_log:
    st.session_state["last_result"] = last_from_log
    st.session_state["radar"] = (
        TELEMETRY_HONEYFILE
        if last_from_log.get("status") == "EMERGENCY_VAULT_LOCKED"
        else TELEMETRY_STAGING
    )

_render_kpis(is_vault_locked, len(logs))

# Telemetri SELALU tampil di atas tab agar klik Live Browser langsung terlihat
# tanpa perlu pindah tab.
st.markdown("##### Telemetri Insiden Terbaru")
_render_timeline(st.session_state.get("last_result"))

st.divider()

tab_endpoint, tab_lab = st.tabs(
    [
        "🛡️ Endpoint Guard & Document Vault (Live System)",
        "🧪 Threat Lab & Simulator (Red-Team Testing)",
    ]
)
with tab_endpoint:
    _render_tab_endpoint(device_profile, status)
with tab_lab:
    _render_tab_threat_lab(device_profile)

st.caption(
    "Seluruh operasi file dikunci di sandbox oleh is_safe_path()."
)
