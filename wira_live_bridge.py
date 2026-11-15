"""
WIRA-SHIELD — Live Browser Bridge (Universal Web Click Interceptor Daemon)
==========================================================================

HTTP daemon lokal di 127.0.0.1:5050 yang menerima laporan klik dari
ekstensi browser (wira_browser_extension/) lalu meneruskannya ke mesin
pertahanan WIRA-SHIELD.

- GET  /status        : health check
- POST /inspect_click : inspeksi klik { url, domain, element, simulate_infected }

Klik aman  -> CLEAN (TIDAK menulis log; zero false-positive).
Klik risiko -> payload web_driveby_drop.pkg di STAGING_DIR lalu
               intercept_staging(...) -> BLOCKED di 0% Installed.

TIDAK ada penyadapan trafik, TIDAK ada malware sungguhan, TIDAK ada
pengiriman data ke internet. Semua operasi file dikunci di sandbox
oleh is_safe_path().

Jalankan: python wira_live_bridge.py
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sandbox_setup import BASE_SANDBOX, STAGING_DIR, is_safe_path
from wira_engine import intercept_staging

HOST = "127.0.0.1"
PORT = 5050
DANGEROUS_EXT = (".exe", ".apk", ".pkg", ".bat", ".sh", ".msi", ".scr")
PAYLOAD_NAME = "web_driveby_drop.pkg"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _is_local_target(url: str, domain: str) -> bool:
    """True jika domain/URL menunjuk localhost / 127.0.0.1 (dashboard sendiri)."""
    candidates = {(domain or "").lower(), (urlparse(url or "").hostname or "").lower()}
    for host in candidates:
        if not host:
            continue
        if host in LOCAL_HOSTS or host.endswith(".localhost") or host.startswith("127."):
            return True
    return False


def _looks_dangerous(url: str) -> bool:
    """True jika path URL berakhiran ekstensi installer berbahaya."""
    path = (url or "").split("?", 1)[0].split("#", 1)[0]
    return path.lower().endswith(DANGEROUS_EXT)


def _drop_and_intercept(domain: str, element: str) -> dict:
    """Tulis web_driveby_drop.pkg ke STAGING_DIR lalu intercept 0%."""
    payload_path = os.path.join(STAGING_DIR, PAYLOAD_NAME)
    if not is_safe_path(payload_path):
        raise RuntimeError("Path payload berada di luar sandbox.")
    with open(payload_path, "w", encoding="utf-8") as handle:
        handle.write(
            "# SIMULASI PAYLOAD WIRA-SHIELD (bukan malware nyata)\n"
            "# Vektor: Universal Web Click — komponen situs nyata dianggap\n"
            "# disusupi script Silent Auto-Install (MITRE T1189).\n"
            f"# Domain  : {domain}\n"
            f"# Element : {element}\n"
        )
    return intercept_staging(
        "Live Browser Agent (Universal Web)",
        f"Web Click [{domain}] -> {element}",
    )


class WiraBridgeHandler(BaseHTTPRequestHandler):
    server_version = "WIRA-SHIELD-Bridge/1.0"

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")

    def _send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802 (http.server naming)
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/status", "/"):
            self._send_json(
                200,
                {
                    "status": "online",
                    "service": "WIRA-SHIELD Live Bridge",
                    "version": "1.0.0",
                    "listen": f"http://{HOST}:{PORT}",
                    "sandbox": BASE_SANDBOX,
                    "endpoints": ["/status", "/inspect_click"],
                },
            )
            return
        self._send_json(404, {"error": "Not found. Gunakan /status atau /inspect_click."})

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/inspect_click":
            self._send_json(404, {"error": "Gunakan POST /inspect_click."})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8", errors="replace") or "{}")
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"JSON tidak valid: {exc}"})
            return

        url = str(data.get("url") or "")[:2048]
        domain = str(data.get("domain") or urlparse(url).hostname or "unknown")[:255]
        element = str(data.get("element") or "-")[:180]
        simulate_infected = bool(data.get("simulate_infected") is True or data.get("simulate_infected") == "true")

        # Pengecualian localhost / 127.0.0.1: dashboard sendiri -> CLEAN tanpa log.
        if _is_local_target(url, domain):
            print(f'[WIRA-BRIDGE] LOCAL    [{domain}] -> "{element}" (CLEAN, tanpa log)', flush=True)
            self._send_json(200, {"status": "CLEAN", "domain": domain, "element": element})
            return

        if simulate_infected or _looks_dangerous(url):
            try:
                result = _drop_and_intercept(domain, element)
            except Exception as exc:  # sandbox / IO error
                self._send_json(500, {"status": "ERROR", "error": str(exc)})
                return
            print(
                f"[WIRA-BRIDGE] BLOCKED  [{domain}] -> \"{element}\" "
                f"({', '.join(result.get('files_removed', []) or ['web_driveby_drop.pkg'])}) "
                f"0% Installed",
                flush=True,
            )
            self._send_json(
                200,
                {
                    "status": "BLOCKED",
                    "install_progress": "0%",
                    "domain": domain,
                    "element": element,
                    "files_removed": result.get("files_removed", []),
                    "latency_ms": result.get("latency_ms", 12),
                },
            )
            return

        # Zero false-positive: jangan tulis log sampah.
        print(f"[WIRA-BRIDGE] CLEAN    [{domain}] -> \"{element}\" (tidak ada payload, tanpa log)", flush=True)
        self._send_json(200, {"status": "CLEAN", "domain": domain, "element": element})

    def log_message(self, fmt: str, *args) -> None:  # rapikan log akses
        print(f"[WIRA-BRIDGE] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), WiraBridgeHandler)
    print("=" * 62, flush=True)
    print("🛡️  WIRA-SHIELD Live Bridge — Universal Web Click Interceptor", flush=True)
    print(f"    Listening : http://{HOST}:{PORT}", flush=True)
    print(f"    Sandbox   : {BASE_SANDBOX}", flush=True)
    print("    CLEAN click -> tanpa log (zero false-positive)", flush=True)
    print("    BLOCKED click -> web_driveby_drop.pkg dihapus di 0%", flush=True)
    print("=" * 62, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[WIRA-BRIDGE] Shutdown.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
