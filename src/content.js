(function () {
  // Evita di girare due volte nella stessa pagina (servirà al passo 4,
  // quando inietteremo lo script anche nelle schede già aperte).
  if (window.__baitBlockerLoaded) return;
  window.__baitBlockerLoaded = true;

  // ===== QUI INCOLLA, INVARIATI, I TUOI: =====
  //   const TARGET_BRANDS = [...]
  //   function getLevenshteinDistance(a, b) { ... }
  //   function analyzeHeuristics() { ... }
  // ===========================================

  let lastResult = null;
  let lastSignature = "";

  function runAnalysis(trigger) {
    const result = analyzeHeuristics();
    result.url = location.href;
    result.timestamp = Date.now();
    lastResult = result;

    // Logga solo se il risultato è cambiato, non a ogni rianalisi.
    const signature = result.url + "|" + result.score + "|" + result.reasons.join("|");
    if (signature !== lastSignature) {
      lastSignature = signature;
      console.log(`[BaitBlocker] (${trigger}) score ${result.score}`, result.reasons);
      // Al passo 4 qui invieremo il risultato al background.
    }
  }

  // --- Rianalisi quando la pagina cambia --------------------------------
  let timer = null;
  let firstScheduled = 0;

  function scheduleAnalysis(trigger) {
    const now = Date.now();
    if (!timer) firstScheduled = now;
    clearTimeout(timer);
    // Debounce di 500 ms, ma mai più di 3 s di attesa sulle pagine sempre in movimento.
    const wait = now - firstScheduled > 3000 ? 0 : 500;
    timer = setTimeout(() => {
      timer = null;
      runAnalysis(trigger);
    }, wait);
  }

  const RELEVANT = "form, input, a[href], iframe";

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === "attributes") {
        scheduleAnalysis("dom-attribute");
        return;
      }
      for (const node of m.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches(RELEVANT) || node.querySelector(RELEVANT)) {
          scheduleAnalysis("dom");
          return;
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["action", "type", "href"]
  });

  // Siti "single page" (Gmail, Outlook): l'URL cambia senza ricaricare.
  window.addEventListener("popstate", () => scheduleAnalysis("url-change"));
  window.addEventListener("hashchange", () => scheduleAnalysis("url-change"));

  // --- Prima analisi, appena caricato -----------------------------------
  runAnalysis("load");

  // --- Il popup ora riceve l'ultimo risultato ----------------------------
  api.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_page") {
      runAnalysis("popup");
      sendResponse(lastResult);
    }
  });
})();