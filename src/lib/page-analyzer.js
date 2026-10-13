// Analisi della pagina. Lavora su un oggetto di "fatti" già estratti dal DOM
// (li raccoglie content.js con collectPageFacts), non sul DOM stesso:
// così la logica si testa con Node e il codice che tocca il DOM resta minimo.
//
// facts = {
//   url, title, siteName,
//   headings: [testi degli h1], logoTexts: [alt delle immagini "logo"],
//   passwordFields: n, cardFields: n,
//   forms: [{ action, sensitive }],
//   resources: [url di immagini, icone, fogli di stile]
// }
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});
  const f = (...a) => BB.makeFinding(...a);

  // "Sign in with Google", "Accedi con Apple": login social legittimi, NON impersonificazione.
  const SOCIAL_LOGIN = /\b(sign|log)\s?in with|continue with|accedi con|continua con|registrati con/i;

  // Brand i cui file si trovano su moltissimi siti legittimi (font, pulsanti social, analytics).
  const UBIQUITOUS_ASSETS = new Set(["google", "facebook", "twitter", "linkedin", "microsoft"]);

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // Il nome del brand compare come parola intera, con le sue maiuscole ("PayPal", "INPS", "eBay").
  function mentionsBrand(texts, brand) {
    return brand.names.some((name) => {
      const re = new RegExp("(^|[^A-Za-z0-9])" + escapeRegex(name) + "($|[^A-Za-z0-9])");
      return texts.some((t) => re.test(t));
    });
  }

  function hostOf(raw, base) {
    try { return new URL(raw, base).hostname.toLowerCase(); } catch (e) { return ""; }
  }

  function analyzePage(facts, options = {}) {
    const findings = [];
    let u;
    try { u = new URL(facts.url); } catch (e) { return { score: 0, level: "safe", findings }; }

    const host = u.hostname.toLowerCase();
    const registrable = BB.registrableDomain(host);
    const owner = host ? BB.officialBrandFor(host) : null;
    const userTrusted = (options.trustedHosts || []).some((d) => BB.hostMatches(host, d));
    const sensitive = facts.passwordFields > 0 || facts.cardFields > 0;
    const asks = facts.passwordFields > 0 ? "a password" : "payment card data";

    // --- 1. Credenziali su canali sbagliati ------------------------------------
    if (u.protocol === "http:" && facts.passwordFields > 0) {
      findings.push(f("password-http", 5, "high", "Asks for a password over an unencrypted (HTTP) connection."));
    }
    // File HTML aperto dal disco con un form di login: tipico allegato di phishing.
    if (u.protocol === "file:" && sensitive) {
      findings.push(f("local-login-form", 6, "high",
        `A local HTML file asks for ${asks}: this is typical of phishing e-mail attachments.`));
    }

    // --- 2. Dove vanno i dati dei form sensibili --------------------------------
    const offsite = new Set();
    let mailto = false;
    for (const form of facts.forms || []) {
      if (!form.sensitive || !form.action) continue;
      if (/^mailto:/i.test(form.action)) { mailto = true; continue; }
      if (/^(javascript|data):/i.test(form.action)) continue;
      const target = hostOf(form.action, facts.url);
      if (!target || (registrable && BB.registrableDomain(target) === registrable)) continue;
      // Login legittimi tra domini dello stesso brand (outlook.com -> microsoftonline.com).
      if (owner && BB.officialBrandFor(target) === owner) continue;
      offsite.add(target);
    }
    if (mailto) findings.push(f("form-mailto", 4, "high", "A login or payment form sends the data by e-mail (mailto:)."));
    if (offsite.size) {
      findings.push(f("form-offsite", 3, "medium",
        `A form with sensitive fields sends the data to another domain: ${[...offsite].slice(0, 3).join(", ")}.`));
    }

    // --- 3. La pagina si presenta come un brand che non la ospita ----------------
    if (sensitive && !owner && !userTrusted) {
      const texts = [facts.title, facts.siteName, ...(facts.headings || []), ...(facts.logoTexts || [])]
        .filter((t) => t && !SOCIAL_LOGIN.test(t))
        .map((t) => String(t).slice(0, 300));
      const brand = BB.BRANDS.find((b) => mentionsBrand(texts, b));
      if (brand) {
        findings.push(f("brand-impersonation", 6, "high",
          `The page presents itself as ${brand.names[0]} and asks for ${asks}, but it is not on an official ${brand.names[0]} domain.`));
      }
    }

    // --- 4. Pagina clonata: immagini e stili presi direttamente dai server del brand
    if (sensitive && !owner && !userTrusted) {
      const counts = new Map();
      for (const r of (facts.resources || []).slice(0, 300)) {
        const b = BB.officialBrandFor(hostOf(r, facts.url));
        if (b && !UBIQUITOUS_ASSETS.has(b.id)) counts.set(b, (counts.get(b) || 0) + 1);
      }
      for (const [b, n] of counts) {
        if (n >= 2) {
          findings.push(f("cloned-assets", 3, "medium",
            `Loads ${n} images or styles directly from ${b.names[0]} servers: the page looks copied from the original.`));
          break;
        }
      }
    }

    const score = findings.reduce((s, x) => s + x.points, 0);
    return { score, level: BB.levelFor(score), findings };
  }

  BB.analyzePage = analyzePage;
})();