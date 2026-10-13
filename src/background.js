// In Chrome il background è un service worker: le librerie si caricano qui.
// In Firefox le elenca il manifest (background.scripts).
if (typeof importScripts === "function") {
  importScripts(
  "lib/api.js", "lib/psl.js", "lib/punycode.js", "lib/confusables.js",
  "lib/distance.js", "lib/brands.js", "lib/domain-analyzer.js", "lib/url-analyzer.js",
  "lib/blocklist.js"
  );
}

// ---------------------------------------------------------------- badge

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
    // La scheda potrebbe essere stata chiusa nel frattempo.
  }
}

// ---------------------------------------------------------------- impostazioni utente

async function getTrustedHosts() {
  const { trustedHosts } = await api.storage.local.get("trustedHosts");
  return trustedHosts || [];
}

// Siti per cui l'utente ha scelto "Continua comunque" (fino alla chiusura del browser).
async function isAllowedOnce(host) {
  const { allowOnce } = await api.storage.session.get("allowOnce");
  return (allowOnce || []).includes(host);
}

async function analyzeUrlForTab(url) {
  return BB.analyzeUrlFull(url, { trustedHosts: await getTrustedHosts() });
}

// ---------------------------------------------------------------- stato per scheda

const tabKey = (tabId) => "tab:" + tabId;

async function getState(tabId) {
  const k = tabKey(tabId);
  return (await api.storage.session.get(k))[k] || null;
}

// Verdetto finale = indizi dell'URL (background) + indizi della pagina (content script).
async function saveState(tabId, url, urlResult, page) {
  const findings = [...urlResult.findings, ...(page ? page.findings : [])];
  const score = findings.reduce((s, x) => s + x.points, 0);
  const state = { url, urlResult, page, findings, score, level: BB.levelFor(score), timestamp: Date.now() };
  await api.storage.session.set({ [tabKey(tabId)]: state });
  await updateBadge(tabId, state.level);
  return state;
}

// ---------------------------------------------------------------- guardia sulle navigazioni

function warningPageUrl(url) {
  return api.runtime.getURL("warning/warning.html") + "?url=" + encodeURIComponent(url);
}

// Pagine "prerender": Chrome le carica in anticipo, senza che l'utente le abbia aperte.
// Non vanno bloccate (bloccheremmo la scheda su cui l'utente sta lavorando).
const isPrerender = (d) => d.documentLifecycle === "prerender";

const redirected = new Map(); // tabId -> ultimo URL mandato alla pagina di avviso

async function blockIfDangerous(tabId, url, result, phase) {
  if (result.level !== "dangerous") return false;
  if (await isAllowedOnce(result.host)) return false;
  // onCommitted dopo un onBeforeNavigate già bloccato: non serve rifarlo.
  if (phase === "commit" && redirected.get(tabId) === url) return true;
  redirected.set(tabId, url);
  await api.tabs.update(tabId, { url: warningPageUrl(url) });
  return true;
}

// 1) PRIMA che la pagina venga richiesta al server.
api.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || isPrerender(d) || !/^https?:/i.test(d.url)) return;
  await blockIfDangerous(d.tabId, d.url, await analyzeUrlForTab(d.url), "before");
});

// 2) Quando la pagina viene "confermata": salva il verdetto dell'URL.
//    Intercetta anche i redirect lato server (shortener -> sito di phishing).
api.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || isPrerender(d)) return;
  if (!/^https?:/i.test(d.url)) {
    await api.storage.session.remove(tabKey(d.tabId));
    await updateBadge(d.tabId, "safe");
    return;
  }
  const result = await analyzeUrlForTab(d.url);
  if (await blockIfDangerous(d.tabId, d.url, result, "commit")) return;
  await saveState(d.tabId, d.url, result, null);
});

// 3) Siti single-page (Gmail, Outlook): l'URL cambia senza ricaricare.
api.webNavigation.onHistoryStateUpdated.addListener(async (d) => {
  if (d.frameId !== 0 || isPrerender(d) || !/^https?:/i.test(d.url)) return;
  await saveState(d.tabId, d.url, await analyzeUrlForTab(d.url), null);
  api.tabs.sendMessage(d.tabId, { type: "reanalyze" }).catch(() => {});
});

api.tabs.onRemoved.addListener((tabId) => {
  redirected.delete(tabId);
  api.storage.session.remove(tabKey(tabId));
});

// ---------------------------------------------------------------- messaggi dal content script

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "page-report" && sender.tab) {
    if (sender.documentLifecycle === "prerender") return; // vedi isPrerender
    const tabId = sender.tab.id;
    (async () => {
      const prev = await getState(tabId);
      const urlResult = prev && prev.url === msg.result.url ? prev.urlResult : await analyzeUrlForTab(msg.result.url);
      // Pagina arrivata senza passare dalla guardia (es. prerender attivato): controlla ora.
      if (await blockIfDangerous(tabId, msg.result.url, urlResult, "commit")) return sendResponse(null);
      const state = await saveState(tabId, msg.result.url, urlResult, msg.result);
      sendResponse({ level: state.level });
    })();
    return true;
  }
});
// ---------------------------------------------------------------- blocklist

const FEED_ALARM = "baitblocker-feeds";

// Un "alarm" sopravvive allo spegnimento del service worker (setInterval no).
async function scheduleFeedUpdates() {
  if (!(await api.alarms.get(FEED_ALARM))) {
    api.alarms.create(FEED_ALARM, { periodInMinutes: 360 });
  }
  await BB.blocklist.update(false); // scarica solo se le liste hanno più di 6 ore
}

api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === FEED_ALARM) BB.blocklist.update(false);
});

api.runtime.onStartup.addListener(scheduleFeedUpdates);
// ---------------------------------------------------------------- installazione

async function injectIntoOpenTabs() {
  if (typeof browser !== "undefined") return; // Firefox lo fa da solo
  const files = api.runtime.getManifest().content_scripts[0].js;
  const tabs = await api.tabs.query({ url: ["http://*/*", "https://*/*"] });
  for (const tab of tabs) {
    api.scripting.executeScript({ target: { tabId: tab.id }, files }).catch(() => {});
  }
}

api.runtime.onInstalled.addListener(async (details) => {
  console.log("BaitBlocker installato:", details.reason);
  await injectIntoOpenTabs();
  await scheduleFeedUpdates();
});