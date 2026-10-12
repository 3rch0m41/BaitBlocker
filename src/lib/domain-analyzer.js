// Analisi del nome di dominio: IP, IDN/omografi, typosquatting, combosquatting,
// brand nel sottodominio. Funzione pura: niente DOM, niente rete.
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  // Soglie dei livelli (valgono per tutta l'estensione).
  const LEVELS = { DANGEROUS: 7, SUSPICIOUS: 3 };

  function levelFor(score) {
    if (score >= LEVELS.DANGEROUS) return "dangerous";
    if (score >= LEVELS.SUSPICIOUS) return "suspicious";
    return "safe";
  }

  // Un "finding" = un indizio: id stabile, punti, gravità, spiegazione per l'utente.
  function makeFinding(id, points, severity, message) {
    return { id, points, severity, message };
  }

  // Parole tipiche dei domini di phishing (anche in italiano).
  const PHISHY_WORDS = new Set([
    "login", "logon", "signin", "signon", "verify", "verification", "verifica", "account", "accounts",
    "update", "aggiorna", "aggiornamento", "secure", "security", "sicurezza", "confirm", "conferma",
    "banking", "webscr", "password", "wallet", "unlock", "sblocca", "suspended", "sospeso", "recover",
    "recovery", "billing", "auth", "authenticate", "validate", "support", "assistenza", "helpdesk",
    "service", "servizi", "refund", "rimborso", "payment", "pagamento", "invoice", "fattura",
    "delivery", "consegna", "tracking", "spedizione", "customer", "client", "online", "mobile", "app",
    "id", "help", "access", "accesso", "portal", "alert", "notice", "team", "official", "center", "centre"
  ]);

  // "", "login", "logins", "securelogin", "verifyaccount" (al massimo due parole)
  function isPhishyCompound(rest) {
    if (rest === "" || PHISHY_WORDS.has(rest)) return true;
    if (rest.endsWith("s") && PHISHY_WORDS.has(rest.slice(0, -1))) return true;
    for (let i = 2; i < rest.length - 1; i++) {
      if (PHISHY_WORDS.has(rest.slice(0, i)) && PHISHY_WORDS.has(rest.slice(i))) return true;
    }
    return false;
  }

  function isPrivateIp(host) {
    return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host === "[::1]";
  }

  // ---------------------------------------------------------------- IDN

  function idnFindings(host) {
    const labels = host.split(".").filter((l) => l.startsWith("xn--"));
    if (labels.length === 0) return [];
    const shown = BB.hostToUnicode(host);
    let mixed = false;
    let wholeScript = false;
    for (const l of labels) {
      const uni = BB.punycodeToUnicodeLabel(l);
      const scripts = BB.scriptsIn(uni);
      if (scripts.size > 1) mixed = true;
      // Tutto in un alfabeto non latino, ma fatto solo di lettere che sembrano latine (аррӏе).
      if (!scripts.has("Latin") && BB.unicodeSkeleton(uni).complete) wholeScript = true;
    }
    if (mixed) {
      return [makeFinding("idn-mixed-script", 4, "high", `Domain mixes different alphabets: it is displayed as "${shown}".`)];
    }
    if (wholeScript) {
      return [makeFinding("idn-confusable", 3, "medium", `Domain written only with letters that look Latin: it is displayed as "${shown}".`)];
    }
    return [makeFinding("idn", 0, "info", `Internationalized domain, displayed as "${shown}".`)];
  }

  // ---------------------------------------------------------------- brand

  function brandFindings(parts) {
    const label = parts.label;                              // "paypa1", "xn--80ak6aa92e"
    const unicodeLabel = BB.punycodeToUnicodeLabel(label);  // "paypa1", "аррӏе"
    const isIdn = label !== unicodeLabel;
    const variants = BB.readingVariants(unicodeLabel);
    const pieces = unicodeLabel.split("-").filter(Boolean);
    const pieceVariants = pieces.map((p) => BB.readingVariants(p));
    const hasPhishyPiece = pieces.some((p) => PHISHY_WORDS.has(p));
    // Suffissi "nazionali" (yahoo.co.jp, google.cn): il brand potrebbe esserci davvero.
    const ccLike = /^[a-z]{2}$/.test(parts.suffix) || /^(com|co|net|org)\.[a-z]{2}$/.test(parts.suffix);

    const results = [];
    for (const brand of BB.BRANDS) {
      const name = brand.names[0];
      for (const token of brand.tokens) {
        // 1) Il nome esatto del brand, su un dominio che il brand non possiede.
        if (unicodeLabel === token) {
          results.push(ccLike
            ? makeFinding("brand-unofficial-domain", 2, "medium", `Uses the name "${name}" on .${parts.suffix}, which is not one of its official domains.`)
            : makeFinding("brand-unofficial-domain", 5, "high", `Uses the name "${name}" on an unofficial domain (.${parts.suffix}).`));
          continue;
        }

        // Nomi molto corti (dhl, ups): contano solo come pezzo separato da trattini,
        // accanto a una parola da phishing ("dhl-tracking-delivery").
        if (token.length < 4) {
          if (pieces.length > 1 && pieces.includes(token) && hasPhishyPiece) {
            results.push(makeFinding("combosquatting", 6, "high", `Domain combines "${name}" with phishing words ("${unicodeLabel}").`));
          }
          continue;
        }

        // 2) Sosia: si legge esattamente come il brand (paypa1, аррӏе, rnicrosoft).
        if (variants.includes(token)) {
          results.push(isIdn
            ? makeFinding("idn-homograph", 8, "high", `Homograph attack: "${unicodeLabel}" uses look-alike characters to imitate "${name}".`)
            : makeFinding("lookalike-chars", 7, "high", `Look-alike characters: "${label}" reads as "${token}" (${name}).`));
          continue;
        }

        // 3) Typosquatting: poche modifiche di distanza, soglia relativa alla lunghezza.
        const thr = BB.typoThreshold(token.length);
        if (thr > 0) {
          let best = Infinity;
          for (const v of variants) best = Math.min(best, BB.osaDistance(v, token, thr));
          if (best > 0 && best <= thr) {
            results.push(makeFinding("typosquatting", 5, "high",
              `Typosquatting: "${unicodeLabel}" is ${best} edit${best > 1 ? "s" : ""} away from "${token}" (${name}).`));
            continue;
          }
        }

        // 4) Combosquatting: brand + altre parole ("paypal-secure", "amazonlogin").
        const pieceHit = pieces.length > 1 && pieceVariants.some((pv) => pv.includes(token));
        let concatHit = false;
        if (!pieceHit) {
          for (const v of variants) {
            const flat = v.replace(/-/g, "");
            let rest = null;
            if (flat.startsWith(token)) rest = flat.slice(token.length);
            else if (flat.endsWith(token)) rest = flat.slice(0, flat.length - token.length);
            if (rest !== null && rest.length > 0 && isPhishyCompound(rest.replace(/\d+/g, ""))) {
              concatHit = true;
              break;
            }
          }
        }
        if (pieceHit || concatHit) {
          results.push(makeFinding("combosquatting", hasPhishyPiece || concatHit ? 6 : 5, "high",
            `Domain combines the brand "${name}" with other words ("${unicodeLabel}").`));
        }
      }
    }

    // 5) Brand nel sottodominio di un dominio estraneo ("paypal.com.account-verify.xyz").
    if (parts.subdomain) {
      const subPieces = BB.hostToUnicode(parts.subdomain).split(/[.-]/).filter(Boolean);
      const subPhishy = subPieces.some((p) => PHISHY_WORDS.has(p));
      outer: for (const brand of BB.BRANDS) {
        for (const token of brand.tokens) {
          if (token.length < 4 && !subPhishy) continue;
          const hit = subPieces.some((p) => p === token || (token.length >= 5 && BB.readingVariants(p).includes(token)));
          if (hit) {
            results.push(makeFinding("brand-in-subdomain", 5, "high",
              `"${brand.names[0]}" appears in the subdomain, but the real domain is ${parts.registrable}.`));
            break outer;
          }
        }
      }
    }

    // Gli indizi di brand si sovrappongono (paypa1 è sia sosia sia typo):
    // conta il più forte, più al massimo +2 se ce ne sono altri a conferma.
    const byId = new Map();
    for (const f of results) {
      const prev = byId.get(f.id);
      if (!prev || f.points > prev.points) byId.set(f.id, f);
    }
    const list = [...byId.values()].sort((a, b) => b.points - a.points);
    if (list.length > 1) {
      list[0] = { ...list[0], points: list[0].points + Math.min(2, list.length - 1) };
      for (let i = 1; i < list.length; i++) list[i] = { ...list[i], points: 0 };
    }
    return list;
  }

  // ---------------------------------------------------------------- entry point

  // options.trustedHosts: domini che l'utente ha dichiarato fidati.
  function analyzeDomain(hostname, options = {}) {
    const host = String(hostname || "").toLowerCase();
    const parts = BB.splitHost(host);
    const findings = [];

    const official = BB.isUserContentHost(host) ? null : BB.officialBrandFor(host);
    const userTrusted = (options.trustedHosts || []).some((d) => BB.hostMatches(host, d));
    const trusted = !!official || userTrusted;

    if (BB.isIpHost(host)) {
      findings.push(isPrivateIp(host)
        ? makeFinding("private-ip", 0, "info", "Local network address.")
        : makeFinding("raw-ip", 4, "high", "Uses a raw IP address instead of a domain name."));
    } else {
      findings.push(...idnFindings(host));
      if (!trusted) findings.push(...brandFindings(parts));
    }

    const score = findings.reduce((s, f) => s + f.points, 0);
    return { host, registrable: parts.registrable, trusted, brand: official ? official.id : null, score, level: levelFor(score), findings };
  }

  BB.LEVELS = LEVELS;
  BB.levelFor = levelFor;
  BB.makeFinding = makeFinding;
  BB.PHISHY_WORDS = PHISHY_WORDS;
  BB.analyzeDomain = analyzeDomain;
})();