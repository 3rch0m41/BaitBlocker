// Analisi di un URL completo. Parte da analyzeDomain() e aggiunge gli indizi
// che stanno nel resto dell'URL: schema, @, porta, TLD, percorso, redirect.
// Funzione pura: la usano il background (navigazioni) e il content script (link).
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});
  const f = (...a) => BB.makeFinding(...a);

  // TLD economici e molto usati per campagne usa-e-getta.
  const RISKY_TLDS = new Set([
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "cyou", "sbs", "cfd", "click",
    "rest", "cam", "quest", "monster", "lol", "bond", "work", "fit", "country", "kim", "men",
    "loan", "win", "bid", "review", "date", "racing", "stream", "gdn", "beauty", "hair", "skin",
    "autos", "boats", "yachts", "mom", "pics", "makeup", "shop", "online", "site", "live", "life"
  ]);
  // TLD che sembrano estensioni di file: "fattura.zip" è un sito, non un allegato.
  const FILE_LIKE_TLDS = new Set(["zip", "mov"]);

  const SHORTENERS = new Set([
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "qrco.de", "v.gd", "shorte.st",
    "adf.ly", "bl.ink", "short.io", "tny.im", "lnkd.in", "urlz.fr", "x.gd"
  ]);

  const RISKY_EXTENSIONS = /\.(exe|scr|msi|msix|bat|cmd|ps1|vbs|vbe|hta|jar|apk|iso|img|lnk|wsf|jse|cpl|appx|dmg|pkg)$/i;
  const DOUBLE_EXTENSION = /\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|js|vbs|hta|bat|cmd|lnk|html?)$/i;

  // Servizi che "avvolgono" i link: la destinazione vera è in un parametro.
  const REDIRECTORS = [
    { name: "Google redirect", params: ["q", "url"], test: (h, p) => /(^|\.)google\.[a-z.]+$/.test(h) && p === "/url" },
    { name: "Outlook Safe Links", params: ["url"], test: (h) => h.endsWith("safelinks.protection.outlook.com") },
    { name: "Facebook redirect", params: ["u"], test: (h, p) => (h === "l.facebook.com" || h === "lm.facebook.com") && p === "/l.php" },
    { name: "Instagram redirect", params: ["u"], test: (h) => h === "l.instagram.com" },
    { name: "YouTube redirect", params: ["q"], test: (h, p) => h.endsWith("youtube.com") && p === "/redirect" },
    { name: "LinkedIn redirect", params: ["url"], test: (h, p) => h.endsWith("linkedin.com") && p.startsWith("/redir") },
    { name: "Slack redirect", params: ["url"], test: (h) => h === "slack-redir.net" },
    { name: "Reddit redirect", params: ["url"], test: (h) => h === "out.reddit.com" }
  ];

  function parse(raw) {
    try { return new URL(raw); } catch (e) { return null; }
  }

  function decode(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  function unwrapRedirect(u) {
    const host = u.hostname.toLowerCase();
    for (const r of REDIRECTORS) {
      if (!r.test(host, u.pathname)) continue;
      for (const p of r.params) {
        const v = u.searchParams.get(p);
        if (v && /^https?:\/\//i.test(v)) return { target: v, via: r.name };
      }
    }
    // Proofpoint URL Defense v3: https://urldefense.com/v3/__https://vero.sito/__;!!...
    if (host === "urldefense.com") {
      const m = u.href.match(/\/v3\/__(.+?)__;/);
      if (m) return { target: m[1], via: "Proofpoint URL Defense" };
    }
    return null;
  }

  // Un parametro qualsiasi che contiene un URL completo verso un altro sito (open redirect).
  function embeddedRedirect(u, registrable) {
    for (const [key, value] of u.searchParams) {
      if (!/^https?:\/\//i.test(value)) continue;
      const inner = parse(value);
      if (inner && BB.registrableDomain(inner.hostname) !== registrable) return { key, target: value };
    }
    return null;
  }

  function entropy(s) {
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    let e = 0;
    for (const k in freq) {
      const p = freq[k] / s.length;
      e -= p * Math.log2(p);
    }
    return e;
  }

  function finalize(result) {
    result.score = result.findings.reduce((s, x) => s + x.points, 0);
    result.level = BB.levelFor(result.score);
    return result;
  }

  // options: { trustedHosts: [...] }
  function analyzeUrl(raw, options = {}, depth = 0) {
    const result = { url: raw, host: "", registrable: "", trusted: false, score: 0, level: "safe", findings: [] };
    const u = parse(raw);
    if (!u) return result;

    if (u.protocol === "data:") {
      result.findings.push(f("data-url", 6, "high",
        "data: URL: the whole page is hidden inside the link, a trick to avoid domain checks."));
      return finalize(result);
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return result;

    // Link avvolti (Google, Safe Links, Proofpoint...): analizza la destinazione vera.
    if (depth < 3) {
      const wrapped = unwrapRedirect(u);
      if (wrapped) {
        const inner = analyzeUrl(wrapped.target, options, depth + 1);
        inner.findings.unshift(f("redirector", 0, "info", `Link goes through ${wrapped.via}; real destination: ${inner.host}.`));
        inner.wrapper = raw;
        return finalize(inner);
      }
    }

    // --- Dominio (passo 6) ----------------------------------------------------
    const domain = BB.analyzeDomain(u.hostname, options);
    const parts = BB.splitHost(domain.host);
    Object.assign(result, { host: domain.host, registrable: domain.registrable, trusted: domain.trusted, brand: domain.brand });
    result.findings.push(...domain.findings);
    const host = domain.host;
    const isIp = BB.isIpHost(host);

    // --- "Credenziali" prima della @ --------------------------------------------
    // https://www.paypal.com@evil.example/  ->  il sito vero è evil.example
    if (u.username || u.password) {
      const shown = decode(u.username);
      result.findings.push(f("userinfo", /\w\.\w/.test(shown) ? 7 : 3, "high",
        `The address starts with "${shown}@", but the real site is ${host}: everything before "@" is decoration.`));
    }

    // --- Controlli che valgono solo per siti non fidati -------------------------
    if (!result.trusted && !isIp) {
      const tld = host.split(".").pop();
      if (FILE_LIKE_TLDS.has(tld)) {
        result.findings.push(f("file-tld", 3, "medium", `The .${tld} domain looks like a file name.`));
      } else if (RISKY_TLDS.has(tld)) {
        result.findings.push(f("risky-tld", 1, "low", `.${tld} domains are cheap and often abused for phishing.`));
      }
      if (BB.isFreeHostingSuffix(parts.suffix)) {
        result.findings.push(f("free-hosting", 1, "low", `Hosted on a free platform (${parts.suffix}).`));
      }
      if (BB.isUserContentHost(host)) {
        result.findings.push(f("user-content", 1, "low", `Content uploaded by third parties to a public service (${host}).`));
      }
      if (SHORTENERS.has(host)) {
        result.findings.push(f("shortener", 1, "low", "URL shortener: the final destination is hidden."));
      }
      if (/(^|\.)(ipfs|ipns)\./.test(host) || /^\/ip[fn]s\//.test(u.pathname)) {
        result.findings.push(f("ipfs", 2, "medium", "Served from IPFS, popular with phishing kits because pages cannot be taken down."));
      }
      const subCount = parts.subdomain ? parts.subdomain.split(".").length : 0;
      if (subCount >= 4) result.findings.push(f("deep-subdomain", 1, "low", `Unusually many subdomains (${subCount}).`));
      if (host.length > 50) result.findings.push(f("long-host", 1, "low", "Very long host name."));
      if ((parts.label.match(/-/g) || []).length >= 3) {
        result.findings.push(f("many-hyphens", 1, "low", "Domain name with many hyphens."));
      }
      // Nomi generati a caso (kq8xzvbrtp4wmn): tante lettere diverse, poche vocali.
      const core = parts.label.replace(/[-\d]/g, "");
      if (core.length >= 12) {
        const vowels = (core.match(/[aeiouy]/g) || []).length / core.length;
        if (entropy(core) >= 3.5 && vowels < 0.25) {
          result.findings.push(f("random-domain", 2, "medium", "Random-looking domain name, typical of throwaway domains."));
        }
      }
    }

    if (!result.trusted) {
      // Brand usato come cartella su un sito estraneo ("185.x.x.x/paypal/login.php").
      const segs = decode(u.pathname).toLowerCase().split(/[\/._-]+/).filter(Boolean);
      const pathBrand = BB.BRANDS.find((b) => b.tokens.some((t) => t.length >= 4 && segs.includes(t)));
      if (pathBrand) {
        result.findings.push(f("brand-in-path", 3, "medium", `The path mentions "${pathBrand.names[0]}", but the site does not belong to it.`));
      }
      // Vocabolario da phishing nel dominio e nel percorso.
      const words = (BB.hostToUnicode(host) + " " + decode(u.pathname)).toLowerCase().split(/[^a-z\u00c0-\u024f]+/);
      const hits = [...new Set(words.filter((w) => w.length >= 4 && BB.PHISHY_WORDS.has(w)))];
      if (hits.length >= 2) {
        result.findings.push(f("phishy-words", 1, "low", `Credential-related words in the address: ${hits.slice(0, 4).join(", ")}.`));
      }
      if (u.protocol === "http:" && !isIp) {
        result.findings.push(f("no-https", 1, "low", "The connection is not encrypted (HTTP)."));
      }
    }

    // --- Porta, percorso, lunghezza -------------------------------------------------
    if (u.port && u.port !== "80" && u.port !== "443") {
      result.findings.push(f("odd-port", 1, "low", `Non-standard port :${u.port}.`));
    }
    const path = decode(u.pathname);
    if (DOUBLE_EXTENSION.test(path)) {
      result.findings.push(f("double-extension", 7, "high", "Downloads a file with a disguised double extension (e.g. invoice.pdf.exe)."));
    } else if (RISKY_EXTENSIONS.test(path) && !result.trusted) {
      result.findings.push(f("executable", 2, "medium", "Points directly to an executable or installer file."));
    }
    if (raw.length > 250) result.findings.push(f("long-url", 1, "low", "Extremely long address."));
    const encoded = (u.pathname.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encoded > 10 && encoded * 3 > u.pathname.length * 0.3) {
      result.findings.push(f("obfuscated-path", 1, "low", "Heavily percent-encoded path (obfuscation)."));
    }

    // --- Open redirect verso un altro sito: analizza anche la destinazione -------
    if (depth < 3) {
      const emb = embeddedRedirect(u, result.registrable);
      if (emb) {
        const inner = analyzeUrl(emb.target, options, depth + 1);
        if (inner.score > 0) {
          result.findings.push(f("open-redirect", 1, "low", `Parameter "${emb.key}" forwards to another site (${inner.host}).`));
          for (const x of inner.findings) result.findings.push({ ...x, message: "Redirect target: " + x.message });
        }
      }
    }

    return finalize(result);
  }

  BB.analyzeUrl = analyzeUrl;
})();