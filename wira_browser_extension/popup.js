/**
 * WIRA-SHIELD Web Guard — popup controller.
 * Simpan toggle Mode Uji Serangan ke chrome.storage.local
 * dan tampilkan status bridge 127.0.0.1:5050.
 */

const toggle = document.getElementById("simToggle");
const statusEl = document.getElementById("bridgeStatus");

chrome.storage.local.get({ simulate_infected: false }, (data) => {
  toggle.checked = data.simulate_infected === true;
});

toggle.addEventListener("change", () => {
  chrome.storage.local.set({ simulate_infected: toggle.checked === true });
});

// Health check bridge lokal.
fetch("http://127.0.0.1:5050/status", { method: "GET" })
  .then((resp) => {
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return resp.json();
  })
  .then(() => {
    statusEl.textContent = "🟢 Bridge: CONNECTED (127.0.0.1:5050)";
    statusEl.style.color = "#4ade80";
  })
  .catch(() => {
    statusEl.textContent = "🔴 Bridge: OFFLINE — jalankan python wira_live_bridge.py";
    statusEl.style.color = "#f87171";
  });
