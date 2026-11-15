/**
 * WIRA-SHIELD Web Guard — content script.
 *
 * Mendeteksi klik pada elemen situs (a, button, img, iklan, menu) di
 * SEMUA situs web, melapor ke bridge lokal, dan jika respons BLOCKED:
 * - mencegah aksi bawaan (e.preventDefault)
 * - menampilkan toast "WIRA-SHIELD INTERCEPTED (0% INSTALLED)".
 *
 * TIDAK membaca nilai input / password. TIDAK mengirim data ke internet.
 * Hanya domain + teks elemen + URL target -> 127.0.0.1:5050.
 */

(() => {
  "use strict";

  const TOAST_ID = "wira-shield-toast";
  const DANGEROUS_RE = /\.(exe|apk|pkg|bat|sh|msi|scr)(\?|#|\/|$)/i;

  let simulateInfected = false;

  // Muat mode uji dari popup.
  chrome.storage.local.get({ simulate_infected: false }, (data) => {
    simulateInfected = data.simulate_infected === true;
  });
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.simulate_infected) {
      simulateInfected = changes.simulate_infected.newValue === true;
    }
  });

  function shouldWatch(el) {
    if (!el || el.id === TOAST_ID) return false;
    return Boolean(el.closest("a, button, img, [role='button'], [role='menuitem'], .ad, .ads, iframe"));
  }

  function elementInfo(el) {
    const link = el.closest("a, [href]") || el;
    const href = link.href || el.src || el.action || "";
    const text =
      (el.innerText || el.alt || el.getAttribute("aria-label") || el.title || el.tagName || "")
        .toString()
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120) || el.tagName || "element";
    return { href: String(href).slice(0, 2048), text };
  }

  function showToast(message) {
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
  }

  document.addEventListener(
    "click",
    (e) => {
      // Jangan mencegat klik di dashboard WIRA-SHIELD sendiri (localhost).
      const host = window.location.hostname;
      if (host === "localhost" || host === "127.0.0.1") return;
      if (!host) return; // chrome://, about:, new tab
      if (!shouldWatch(e.target)) return;

      const { href, text } = elementInfo(e.target);
      const dangerous = DANGEROUS_RE.test(href);
      // Mode uji ON, atau target memang installer: blokir dulu secara sinkron
      // agar navigasi/download default tidak sempat terjadi sebelum fetch balik.
      if (simulateInfected || dangerous) {
        e.preventDefault();
        e.stopPropagation();
      }

      try {
        chrome.runtime.sendMessage(
          {
            type: "INSPECT_CLICK",
            payload: {
              url: href || location.href,
              domain: location.hostname,
              element: text,
              simulate_infected: simulateInfected,
            },
          },
          (resp) => {
            if (chrome.runtime.lastError) return;
            if (resp && resp.status === "BLOCKED") {
              e.preventDefault();
              e.stopPropagation();
              showToast(
                "🛡️ WIRA-SHIELD INTERCEPTED (0% INSTALLED): Mencegah Silent Auto-Install dari komponen yang baru saja Anda klik di situs ini!"
              );
            }
            // CLEAN / BRIDGE_OFFLINE: biarkan aksi bawaan (kecuali sudah diblokir karena mode uji).
            if (resp && resp.status === "BRIDGE_OFFLINE" && (simulateInfected || dangerous)) {
              showToast("🛡️ WIRA-SHIELD: Bridge lokal OFFLINE. Jalankan python wira_live_bridge.py");
            }
          }
        );
      } catch (_) {
        /* ekstensi context reload — abaikan */
      }
    },
    true
  );
})();
