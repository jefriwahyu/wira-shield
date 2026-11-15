/**
 * WIRA-SHIELD Web Guard — content script (all_frames + iframe shield).
 *
 * Mode Uji Serangan ON:
 *   SEMUA klik dicegat — termasuk iklan Google/AdSense di dalam iframe,
 *   menu, tombol, dan div onclick. Iframe dinonaktifkan pointer-events
 *   agar klik tidak masuk ke frame iklan (yang sering tidak bisa diinjeksi).
 *
 * Mode Uji Serangan OFF:
 *   Hanya tautan installer (.exe/.apk/.pkg/.bat/.sh/.msi/.scr) yang dicegat.
 *
 * localhost / 127.0.0.1 -> diabaikan (dashboard sendiri).
 * TIDAK membaca password. Data hanya ke 127.0.0.1:5050.
 */

(() => {
  "use strict";

  const TOAST_ID = "wira-shield-toast";
  const SHIELD_FLAG = "wiraPeBackup";
  const DANGEROUS_RE = /\.(exe|apk|pkg|bat|sh|msi|scr)(\?|#|\/|$)/i;
  const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1"]);
  const NAV_SELECTOR = "iframe, object, embed, video";

  let simulateInfected = false;
  let lastReportMs = 0;
  let iframeObserver = null;

  function isTopFrame() {
    try {
      return window.top === window;
    } catch (_) {
      return false;
    }
  }

  function isLocalPage() {
    const host = (window.location.hostname || "").toLowerCase();
    if (LOCAL_HOSTS.has(host)) return true;
    if (host.startsWith("127.")) return true;
    if (host.endsWith(".localhost")) return true;
    // Frame utama tanpa host (about:blank / new tab) -> skip.
    // about:blank / srcdoc di dalam iframe iklan -> JANGAN skip.
    if (!host) return isTopFrame();
    return false;
  }

  // ----- Mode uji dari popup -----
  chrome.storage.local.get({ simulate_infected: false }, (data) => {
    simulateInfected = data.simulate_infected === true;
    applyArmState();
  });
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.simulate_infected) {
      simulateInfected = changes.simulate_infected.newValue === true;
      applyArmState();
    }
  });

  // ----- Iframe shield: pointer-events none saat armed -----
  function disableNavPointers() {
    try {
      document.querySelectorAll(NAV_SELECTOR).forEach((el) => {
        if (el.dataset[SHIELD_FLAG] === undefined) {
          el.dataset[SHIELD_FLAG] = el.style.pointerEvents || "";
        }
        el.style.pointerEvents = "none";
      });
    } catch (_) {}
  }

  function restoreNavPointers() {
    try {
      document.querySelectorAll(NAV_SELECTOR).forEach((el) => {
        if (el.dataset[SHIELD_FLAG] !== undefined) {
          el.style.pointerEvents = el.dataset[SHIELD_FLAG];
          delete el.dataset[SHIELD_FLAG];
        }
      });
    } catch (_) {}
  }

  function startIframeWatch() {
    disableNavPointers();
    if (iframeObserver) return;
    iframeObserver = new MutationObserver(() => {
      if (simulateInfected) disableNavPointers();
    });
    iframeObserver.observe(document.documentElement || document, {
      childList: true,
      subtree: true,
    });
  }

  function stopIframeWatch() {
    restoreNavPointers();
    if (iframeObserver) {
      iframeObserver.disconnect();
      iframeObserver = null;
    }
  }

  function applyArmState() {
    if (simulateInfected) {
      startIframeWatch();
    } else {
      stopIframeWatch();
    }
  }

  // ----- Klasifikasi & info elemen -----
  function isDangerous(el) {
    try {
      const link = el.closest ? el.closest("a, [href], form") || el : el;
      const href = link.href || el.src || el.getAttribute("data-url") || "";
      const action = el.form ? el.form.action || "" : "";
      return DANGEROUS_RE.test(String(href)) || DANGEROUS_RE.test(String(action));
    } catch (_) {
      return false;
    }
  }

  function elementInfo(el) {
    try {
      const link = el.closest ? el.closest("a, [href]") || el : el;
      const href = link.href || el.src || el.getAttribute("data-url") || "";
      const text =
        (el.innerText || el.alt || el.getAttribute("aria-label") || el.title ||
          el.tagName || "")
          .toString()
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 120) || el.tagName || "element";
      return {
        href: String(href || location.href).slice(0, 2048),
        text,
      };
    } catch (_) {
      return { href: String(location.href), text: "element" };
    }
  }

  function showToast(message) {
    try {
      const old = document.getElementById(TOAST_ID);
      if (old) old.remove();

      const el = document.createElement("div");
      el.id = TOAST_ID;
      el.textContent = message;
      el.style.cssText = [
        "position: fixed",
        "right: 18px",
        "bottom: 18px",
        "z-index: 2147483647",
        "max-width: 360px",
        "padding: 14px 16px",
        "border-radius: 14px",
        "background: rgba(8, 15, 25, 0.96)",
        "color: #e0f2fe",
        "border: 1px solid #0ea5e9",
        "box-shadow: 0 12px 40px rgba(2, 132, 199, 0.35)",
        "font: 600 13px/1.5 system-ui, -apple-system, Segoe UI, sans-serif",
        "cursor: default",
        "pointer-events: auto",
      ].join(";");
      (document.documentElement || document.body).appendChild(el);
      setTimeout(() => el.remove(), 6000);
    } catch (_) {}
  }

  function halt(e) {
    try {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
    } catch (_) {}
  }

  function report(el, e) {
    const now = Date.now();
    if (now - lastReportMs < 400) {
      halt(e);
      return;
    }
    lastReportMs = now;
    const info = elementInfo(el);
    try {
      chrome.runtime.sendMessage(
        {
          type: "INSPECT_CLICK",
          payload: {
            url: info.href || location.href,
            domain: location.hostname || "iframe",
            element: info.text,
            simulate_infected: simulateInfected,
          },
        },
        (resp) => {
          if (chrome.runtime.lastError) return;
          if (resp && resp.status === "BLOCKED") {
            halt(e);
            showToast(
              "🛡️ WIRA-SHIELD INTERCEPTED (0% INSTALLED): Mencegah Silent Auto-Install dari komponen yang baru saja Anda klik di situs ini!"
            );
          } else if (resp && resp.status === "BRIDGE_OFFLINE") {
            showToast("🛡️ WIRA-SHIELD: Bridge lokal OFFLINE. Jalankan python wira_live_bridge.py");
          }
        }
      );
    } catch (_) {}
  }

  function isLocalPageNow() {
    return isLocalPage();
  }

  /**
   * Dipasang di window (capture) supaya berlari sebelum handler iklan.
   * Mode Uji ON  -> halt SEMUA gesture + lapor ke bridge.
   * Mode Uji OFF -> hanya halt jika installer berbahaya.
   */
  function onGesture(e) {
    if (isLocalPageNow()) return;
    if (e.target && e.target.id === TOAST_ID) return;

    const armed = simulateInfected;
    const dangerous = isDangerous(e.target || document.body);

    if (!armed && !dangerous) return;

    halt(e);
    report(e.target || document.body, e);
  }

  function installListeners() {
    // window capture berlari paling awal (sebelum document & target iklan).
    const opts = { capture: true, passive: false };
    window.addEventListener("click", onGesture, opts);
    window.addEventListener("pointerdown", onGesture, opts);
    window.addEventListener("mousedown", onGesture, opts);
    window.addEventListener("touchstart", onGesture, opts);
    window.addEventListener("auxclick", onGesture, opts);
    window.addEventListener("submit", onGesture, opts);
  }

  installListeners();
  applyArmState();
})();
