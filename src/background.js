if (typeof importScripts === "function") {
  importScripts("lib/api.js");
}

// ---------------------------------------------------------------- livelli e badge

// Soglie provvisorie, coerenti con i punteggi attuali (le ricalibriamo al passo 6).
function levelFor(score) {
  if (score >= 3) return "dangerous";
  if (score > 0) return "suspicious";
  return "safe";
}

const BADGE = {
  safe:       { text: "",   color: "#2e7d32" },
  suspicious: { text: "!",  color: "#e6a100" },
  dangerous:  { text: "!!", color: "#c62828" }
};

async function updateBadge(tabId, level) {
  const b = BADGE[level];
  try {
    await api.action.setBadgeText({ tabId, text: b.text });
    await api.action.setBadgeBackgroundColor({ tabId, color: b.color });
    await api.action.setTitle({ tabId, title: "BaitBlocker: " + level });
  } catch (e) {
    // La scheda potrebbe essere stata chiusa nel frattempo: niente da fare.
  }
}

// ---------------------------------------------------------------- stato per scheda

const tabKey = (tabId) => "tab:" + tabId;

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "page-report" && sender.tab) {
    const tabId = sender.tab.id;
    const level = levelFor(msg.result.score);
    const state = { ...msg.result, level };

    api.storage.session.set({ [tabKey(tabId)]: state })
      .then(() => updateBadge(tabId, level))
      .then(() => sendResponse({ level }));
    return true; // risposta asincrona: tieni aperto il canale
  }

  if (msg.type === "get-tab-state") {
    api.storage.session.get(tabKey(msg.tabId))
      .then((data) => sendResponse(data[tabKey(msg.tabId)] || null));
    return true;
  }
});

// ---------------------------------------------------------------- eventi di navigazione

// Nuova pagina nella scheda: cancella il vecchio verdetto finché non arriva quello nuovo.
api.webNavigation.onCommitted.addListener(({ tabId, frameId }) => {
  if (frameId !== 0) return; // solo la pagina principale, non gli iframe
  api.storage.session.remove(tabKey(tabId));
  updateBadge(tabId, "safe");
});

// Siti single-page (Gmail, Outlook): l'URL cambia con history.pushState.
// Il content script non lo vede, il background sì: glielo diciamo noi.
api.webNavigation.onHistoryStateUpdated.addListener(({ tabId, frameId }) => {
  if (frameId !== 0) return;
  api.tabs.sendMessage(tabId, { type: "reanalyze" }).catch(() => {});
});

api.tabs.onRemoved.addListener((tabId) => {
  api.storage.session.remove(tabKey(tabId));
});

// ---------------------------------------------------------------- installazione

// Chrome NON inietta i content script nelle schede già aperte quando installi
// l'estensione: lo facciamo noi, così la protezione parte subito.
// Firefox invece lo fa da solo.
async function injectIntoOpenTabs() {
  if (typeof browser !== "undefined") return;
  const files = api.runtime.getManifest().content_scripts[0].js;
  const tabs = await api.tabs.query({ url: ["http://*/*", "https://*/*"] });
  for (const tab of tabs) {
    api.scripting.executeScript({ target: { tabId: tab.id }, files }).catch(() => {});
  }
}

api.runtime.onInstalled.addListener(async (details) => {
  console.log("BaitBlocker installato:", details.reason);
  await injectIntoOpenTabs();
});