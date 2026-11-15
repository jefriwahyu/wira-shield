/**
 * WIRA-SHIELD Web Guard — background service worker (Manifest V3).
 *
 * Tugas: meneruskan laporan klik dari content.js ke bridge lokal
 * http://127.0.0.1:5050/inspect_click agar bebas blokir Mixed-Content
 * pada situs HTTPS. TIDAK mengirim data ke server internet mana pun.
 */

const BRIDGE_ENDPOINT = "http://127.0.0.1:5050/inspect_click";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "INSPECT_CLICK" || !message.payload) {
    return false;
  }

  fetch(BRIDGE_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(message.payload),
  })
    .then((resp) => resp.json())
    .then((data) => sendResponse(data))
    .catch((err) => sendResponse({ status: "BRIDGE_OFFLINE", error: String(err) }));

  // true = respons dikirim asinkron lewat sendResponse
  return true;
});
