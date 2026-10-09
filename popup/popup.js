const LABELS = { safe: "Looks safe", suspicious: "Suspicious", dangerous: "High risk" };

const statusEl = document.getElementById("status");
const listEl = document.getElementById("results-list");
const updatedEl = document.getElementById("updated");
const hostEl = document.getElementById("host");
const rescanBtn = document.getElementById("rescan");

let currentTab = null;

function addItem(text) {
  const li = document.createElement("li");
  li.textContent = text; // MAI innerHTML con dati che arrivano dalla pagina
  listEl.appendChild(li);
}

function timeAgo(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return s + " s ago";
  return Math.round(s / 60) + " min ago";
}

function showMessage(title, text) {
  statusEl.textContent = title;
  statusEl.className = "status-box neutral";
  listEl.replaceChildren();
  addItem(text);
  updatedEl.textContent = "";
}

function render(state) {
  if (!state) {
    showMessage("Not analyzed yet", "Reload the page or press Re-scan.");
    return;
  }
  statusEl.textContent = LABELS[state.level];
  statusEl.className = "status-box " + state.level;
  listEl.replaceChildren();
  if (state.reasons.length === 0) {
    addItem("No phishing heuristics triggered. Stay cautious anyway.");
  } else {
    state.reasons.forEach(addItem);
  }
  updatedEl.textContent = "Score " + state.score + " · " + timeAgo(state.timestamp);
}

(async () => {
  [currentTab] = await api.tabs.query({ active: true, currentWindow: true });
  const url = (currentTab && currentTab.url) || "";

  if (!/^(https?|file):/.test(url)) {
    rescanBtn.disabled = true;
    showMessage("Not scannable", "Browser internal pages and extension pages cannot be analyzed.");
    return;
  }
  hostEl.textContent = url.startsWith("file:") ? "local file" : new URL(url).hostname;

  // Lettura diretta: le pagine dell'estensione (popup incluso) possono leggere storage.session.
  const key = "tab:" + currentTab.id;
  const data = await api.storage.session.get(key);
  render(data[key] || null);

  // Aggiornamento dal vivo: se la pagina viene rianalizzata mentre il popup è aperto.
  api.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes[key]) render(changes[key].newValue || null);
  });
})();

rescanBtn.addEventListener("click", async () => {
  if (!currentTab) return;
  try {
    await api.tabs.sendMessage(currentTab.id, { type: "reanalyze", force: true });
  } catch (e) {
    showMessage("Not available", "The page is not reachable by BaitBlocker. Reload it and try again.");
  }
});