// Analisi di un singolo link: dove porta davvero (analyzeUrl) e se il testo
// visibile promette un sito diverso ("www.paypal.com" che apre altro).
// Funzione pura: riceve stringhe, non elementi del DOM, così si testa con Node.
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});
  const f = (...a) => BB.makeFinding(...a);

  // Servizi di invio newsletter: riscrivono i link per contare i clic.
  // Testo "www.negozio.it" + link su sendgrid.net è normale... ma anche gli
  // attaccanti usano questi servizi, quindi l'indizio resta, solo più debole.
  const EMAIL_TRACKERS = [
    "sendgrid.net", "list-manage.com", "mailchimp.com", "mcusercontent.com", "hubspotlinks.com",
    "hs-sites.com", "exacttarget.com", "mailgun.org", "sparkpostmail.com", "rs6.net", "cmail19.com",
    "cmail20.com", "createsend.com", "mandrillapp.com", "mailjet.com", "sendinblue.com", "brevo.com",
    "klaviyomail.com", "awstrack.me", "salesforce.com", "constantcontact.com", "emlnk.com", "mktoedge.com"
  ];

  // Ultime "estensioni" che fanno sembrare un nome di file un dominio (report.pdf).
  const FILE_EXTENSIONS = /\.(pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|svg|txt|csv|html?|php|aspx?|js|css|exe|zip|rar|7z)$/i;

  // Il testo del link È un indirizzo? ("www.paypal.com", "https://poste.it/login")
  // Restituisce l'host mostrato, oppure null se il testo è normale prosa.
  function hostShownIn(text) {
    const t = String(text || "").trim();
    if (t.length > 200) return null;
    if (!/^(https?:\/\/)?[^\s\/@:]+\.[a-z\u00a1-\uffef]{2,24}(:\d+)?([\/?#]\S*)?$/i.test(t)) return null;
    let host;
    try {
      host = new URL(/^https?:\/\//i.test(t) ? t : "http://" + t).hostname.toLowerCase();
    } catch (e) {
      return null;
    }
    if (FILE_EXTENSIONS.test(host) || /^\d+(\.\d+)*$/.test(host.split(".").pop())) return null;
    return host;
  }

  // href: indirizzo vero; text: testo visibile del link.
  function analyzeLink(href, text, options = {}) {
    const base = BB.analyzeUrl(href, options);
    const findings = base.findings.slice();

    const shown = hostShownIn(text);
    if (shown && base.host) {
      const shownReg = BB.registrableDomain(shown);
      const sameSite = shownReg === base.registrable || BB.hostMatches(base.host, shownReg);
      if (!sameSite) {
        const tracker = EMAIL_TRACKERS.some((d) => BB.hostMatches(base.host, d));
        findings.push(tracker
          ? f("text-href-tracker", 2, "low", `The text shows "${shown}" but the link goes through an e-mail tracking service (${base.host}).`)
          : f("text-href-mismatch", 5, "high", `The link text shows "${shown}" but it actually opens ${base.host}.`));
        // Il testo mostra il dominio di un brand, il link no: impersonificazione.
        const shownBrand = BB.officialBrandFor(shown);
        if (shownBrand && BB.officialBrandFor(base.host) !== shownBrand) {
          findings.push(f("text-shows-brand", 2, "high", `The text pretends to be ${shownBrand.names[0]}.`));
        }
      }
    }

    const score = findings.reduce((s, x) => s + x.points, 0);
    return { href, host: base.host, registrable: base.registrable, score, level: BB.levelFor(score), findings };
  }

  BB.hostShownIn = hostShownIn;
  BB.analyzeLink = analyzeLink;
})();