(function () {
  // Evita di girare due volte nella stessa pagina (servirà al passo 4,
  // quando inietteremo lo script anche nelle schede già aperte).
  if (window.__baitBlockerLoaded) return;
  window.__baitBlockerLoaded = true;

  const f = BB.makeFinding;

function analyzeHeuristics() {
  const findings = [];
  const host = location.hostname.toLowerCase();
  const registrable = BB.registrableDomain(host);
  const official = BB.officialBrandFor(host);

  // --- 1-3. Dominio: IP, IDN/omografi, typosquatting, brand -------------
  if (host) findings.push(...BB.analyzeDomain(host).findings);

  // --- 4. Cifratura e password ------------------------------------------
  const hasPassword = !!document.querySelector('input[type="password"]');
  if (location.protocol === "http:") {
    if (hasPassword) {
      findings.push(f("password-http", 5, "high", "Asks for a password over an unencrypted (HTTP) connection."));
    } else if (!BB.isIpHost(host)) {
      findings.push(f("no-https", 1, "low", "The connection is not encrypted (HTTP)."));
    }
  }

  // --- 5. Form con password che inviano i dati altrove ------------------
  const offsite = new Set();
  let mailto = false;
  for (const form of document.querySelectorAll("form")) {
    if (!form.querySelector('input[type="password"]')) continue;
    const action = (form.getAttribute("action") || "").trim();
    if (!action) continue; // nessun action = invia alla pagina stessa
    if (/^mailto:/i.test(action)) { mailto = true; continue; }
    let target;
    try { target = new URL(action, location.href).hostname.toLowerCase(); } catch (e) { continue; }
    if (!target || BB.registrableDomain(target) === registrable) continue;
    // Login legittimi che passano tra domini dello stesso brand (outlook.com -> microsoftonline.com)
    if (official && BB.officialBrandFor(target) === official) continue;
    offsite.add(target);
  }
  if (mailto) {
    findings.push(f("form-mailto", 4, "high", "A login form sends the data by e-mail (mailto:)."));
  }
  if (offsite.size) {
    findings.push(f("form-offsite", 3, "medium",
      `A login form sends the password to another domain: ${[...offsite].slice(0, 3).join(", ")}.`));
  }

  const score = findings.reduce((s, x) => s + x.points, 0);
  return { score, level: BB.levelFor(score), findings };
}

  let lastResult = null;
  let lastSignature = "";

  function sendReport(result) {
    try {
      api.runtime.sendMessage({ type: "page-report", result }).catch(() => {});
    } catch (e) {
    // "Extension context invalidated": l'estensione è stata ricaricata
    // e questo script è rimasto orfano. Smettiamo di osservare la pagina.
      observer.disconnect();
    }
  }
  function runAnalysis(trigger) {
    const result = analyzeHeuristics();
    result.url = location.href;
    result.timestamp = Date.now();
    lastResult = result;

    // Logga solo se il risultato è cambiato, non a ogni rianalisi.
    const signature = result.url + "|" + result.score + "|" + result.findings.map((x) => x.id).join(",");
    if (force || signature !== lastSignature) {
      lastSignature = signature;
      console.log(`[BaitBlocker] (${trigger}) ${result.level}, score ${result.score}`,
        result.findings.map((x) => x.message));
      sendReport(result);
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
    api.runtime.onMessage.addListener((request) => {
    if (request.type === "reanalyze") {
        if (request.force) runAnalysis("manual", true);
        else scheduleAnalysis("url-change");
    }
    });
})();