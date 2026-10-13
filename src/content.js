(function () {
  // Evita di girare due volte nella stessa pagina (es. iniezione nelle schede già aperte).
  if (window.__baitBlockerLoaded) return;
  window.__baitBlockerLoaded = true;

  const f = BB.makeFinding;

  // Solo indizi che richiedono il DOM. Quelli sull'URL li calcola il background.
  function analyzeHeuristics() {
    const findings = [];
    const host = location.hostname.toLowerCase();
    const registrable = BB.registrableDomain(host);
    const official = BB.officialBrandFor(host);

    // --- Password su connessione non cifrata ------------------------------
    if (location.protocol === "http:" && document.querySelector('input[type="password"]')) {
      findings.push(f("password-http", 5, "high", "Asks for a password over an unencrypted (HTTP) connection."));
    }

    // --- Form con password che inviano i dati altrove ---------------------
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

  // --- Scansione dei link ---------------------------------------------------
  const MAX_LINKS_PER_SCAN = 500;
  const linkCache = new Map();   // "href|testo" -> risultato (stesso link = stessa analisi)
  const scanned = new WeakMap(); // <a> -> href già analizzato (se cambia, si rianalizza)

  function linkKey(a) {
    return a.href + "|" + (a.textContent || "").trim();
  }

  function markLink(a, result) {
    if (result.level === "safe") {
      if (a.hasAttribute("data-baitblocker")) {
        a.removeAttribute("data-baitblocker");
        a.title = a.dataset.bbTitle || "";
      }
      return;
    }
    if (a.dataset.bbTitle === undefined) a.dataset.bbTitle = a.title || ""; // salva il titolo originale
    a.setAttribute("data-baitblocker", result.level);
    const reasons = result.findings.filter((x) => x.points > 0).map((x) => "• " + x.message);
    a.title = `BaitBlocker: ${result.level} link\n${reasons.join("\n")}` +
      (a.dataset.bbTitle ? "\n\n" + a.dataset.bbTitle : "");
  }

  function scanLinks() {
    const pageRegistrable = BB.registrableDomain(location.hostname);
    let analyzed = 0;
    for (const a of document.querySelectorAll("a[href]")) {
      const href = a.href; // URL assoluto, già risolto dal browser
      if (scanned.get(a) === href) continue;
      if (analyzed >= MAX_LINKS_PER_SCAN) { scheduleAnalysis("more-links"); break; } // il resto al prossimo giro
      scanned.set(a, href);
      if (!/^(https?|data):/i.test(href)) continue; // mailto:, tel:, javascript:...
      analyzed++;
      const key = linkKey(a);
      let result = linkCache.get(key);
      if (!result) {
        const text = (a.textContent || "").trim();
        let host = "";
        try { host = new URL(href).hostname; } catch (e) { /* data: URL */ }
        // Link interni allo stesso sito: li copre già il verdetto della pagina.
        const internal = host && BB.registrableDomain(host) === pageRegistrable && !BB.hostShownIn(text);
        result = internal ? { level: "safe", findings: [] } : BB.analyzeLink(href, text);
        if (linkCache.size > 3000) linkCache.clear();
        linkCache.set(key, result);
      }
      markLink(a, result);
    }

    // Riepilogo di TUTTI i link segnalati presenti ora nella pagina.
    const dangerous = new Set();
    let suspicious = 0;
    for (const a of document.querySelectorAll("a[data-baitblocker]")) {
      const r = linkCache.get(linkKey(a));
      if (!r) continue;
      if (r.level === "dangerous") dangerous.add(r.host || "data: URL");
      else suspicious++;
    }
    return { dangerous: [...dangerous], suspicious };
  }

  // --- Clic su un link pericoloso: ferma e mostra l'avviso -------------------
  // Serve per i link pericolosi solo per via del TESTO (es. "www.paypal.com" che
  // apre altro): il background vede solo l'URL e non saprebbe che il testo mentiva.
  function onLinkClick(e) {
    if (e.type === "auxclick" && e.button !== 1) return; // solo il clic centrale
    const a = e.target.closest && e.target.closest('a[data-baitblocker="dangerous"]');
    if (!a) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    const newTab = e.type === "auxclick" || e.ctrlKey || e.metaKey || e.shiftKey || a.target === "_blank";
    try {
      api.runtime.sendMessage({ type: "block-link", url: a.href, text: (a.textContent || "").trim(), newTab });
    } catch (err) { /* estensione ricaricata */ }
  }
  // Fase di "capture": arriviamo prima degli handler della pagina.
  document.addEventListener("click", onLinkClick, true);
  document.addEventListener("auxclick", onLinkClick, true);

  // --- Invio al background -------------------------------------------------
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

  function runAnalysis(trigger, force = false) {
    const result = analyzeHeuristics();

    // Link pericolosi nella pagina (es. dentro un'email aperta in Gmail/Outlook).
    const links = scanLinks();
    if (links.dangerous.length) {
      result.findings.push(f("dangerous-links", 3, "medium",
        `This page contains links to dangerous sites (outlined in red): ${links.dangerous.slice(0, 3).join(", ")}.`));
    }
    if (links.suspicious) {
      result.findings.push(f("suspicious-links", 0, "info", `${links.suspicious} suspicious link(s) outlined in orange.`));
    }
    result.score = result.findings.reduce((s, x) => s + x.points, 0);
    result.level = BB.levelFor(result.score);
    result.url = location.href;
    result.timestamp = Date.now();

    // Invia solo se il risultato è cambiato (o se è un re-scan manuale).
    const signature = result.url + "|" + result.score + "|" + result.findings.map((x) => x.id).join(",");
    if (force || signature !== lastSignature) {
      lastSignature = signature;
      console.log(`[BaitBlocker] (${trigger}) page score ${result.score}`, result.findings.map((x) => x.message));
      sendReport(result);
    }
  }

  // --- Rianalisi quando la pagina cambia -------------------------------------
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

  // Pagina caricata in anticipo da Chrome e poi aperta dall'utente: ora conta.
  document.addEventListener("prerenderingchange", () => runAnalysis("activated", true));

  // --- Prima analisi, appena caricato ----------------------------------------
  runAnalysis("load");

  // --- Messaggi dal background e dal popup ------------------------------------
  api.runtime.onMessage.addListener((request) => {
    if (request.type === "reanalyze") {
      if (request.force) runAnalysis("manual", true);  // pulsante Re-scan del popup
      else scheduleAnalysis("url-change");             // cambio URL nelle single-page app
    }
  });
})();