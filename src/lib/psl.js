// Gestione compatta dei Public Suffix: trova il dominio registrabile (eTLD+1).
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  const MULTI_LABEL_SUFFIXES = [
    // Secondi livelli nazionali
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "com.br", "net.br", "org.br", "gov.br",
    "com.ar", "com.mx", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my",
    "co.id", "co.th", "com.vn", "com.ph", "com.pk", "com.tr", "com.sa", "com.eg",
    "co.za", "co.il", "com.ng", "co.ke", "com.ua", "com.pl", "com.ru",
    "gov.it", "edu.it", "com.es", "nom.es", "org.es", "gouv.fr", "com.pt", "com.gr",
    // Piattaforme di hosting / tunnel: ogni cliente ha il suo sottodominio
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com", "fly.dev",
    "azurewebsites.net", "cloudapp.net", "appspot.com", "blogspot.com",
    "glitch.me", "repl.co", "replit.app", "replit.dev", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "trycloudflare.com", "loca.lt", "serveo.net",
    "weebly.com", "wixsite.com", "wordpress.com", "square.site", "godaddysites.com",
    "webflow.io", "framer.website", "framer.app", "myshopify.com", "carrd.co",
    "000webhostapp.com", "duckdns.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
    "freehostia.com", "byethost.com", "infinityfreeapp.com", "rf.gd", "epizy.com",
    "s3.amazonaws.com", "translate.goog", "ipfs.dweb.link", "ipfs.w3s.link"
  ];

  // Sottoinsieme: hosting gratuito/anonimo, legittimo ma molto usato dai kit di phishing.
  const FREE_HOSTING = new Set([
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com", "fly.dev",
    "azurewebsites.net", "glitch.me", "repl.co", "replit.app", "replit.dev",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net",
    "weebly.com", "wixsite.com", "square.site", "godaddysites.com", "webflow.io",
    "framer.website", "framer.app", "carrd.co", "000webhostapp.com", "duckdns.org",
    "ddns.net", "hopto.org", "zapto.org", "sytes.net", "freehostia.com", "byethost.com",
    "infinityfreeapp.com", "rf.gd", "epizy.com", "ipfs.dweb.link", "ipfs.w3s.link", "blogspot.com"
  ]);

  const SUFFIX_SET = new Set(MULTI_LABEL_SUFFIXES);

  function isIp(host) {
    // IPv4 puntato, oppure IPv6 (che new URL() restituisce tra parentesi quadre)
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[") || host.includes(":");
  }

  // "a.b.paypal-login.netlify.app" ->
  // { suffix: "netlify.app", registrable: "paypal-login.netlify.app",
  //   label: "paypal-login", subdomain: "a.b" }
  function splitHost(hostname) {
    const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
    if (!host || isIp(host)) {
      return { host, suffix: "", registrable: host, label: host, subdomain: "" };
    }
    const parts = host.split(".");
    let suffixLen = 1;
    // Vince il suffisso più lungo che corrisponde (es. "s3.amazonaws.com" su "amazonaws.com").
    for (let n = Math.min(4, parts.length - 1); n >= 2; n--) {
      if (SUFFIX_SET.has(parts.slice(-n).join("."))) { suffixLen = n; break; }
    }
    if (parts.length <= suffixLen) {
      return { host, suffix: host, registrable: host, label: parts[0], subdomain: "" };
    }
    const suffix = parts.slice(-suffixLen).join(".");
    const label = parts[parts.length - suffixLen - 1];
    const registrable = label + "." + suffix;
    const subdomain = parts.slice(0, parts.length - suffixLen - 1).join(".");
    return { host, suffix, registrable, label, subdomain };
  }

  BB.splitHost = splitHost;
  BB.isIpHost = isIp;
  BB.registrableDomain = (h) => splitHost(h).registrable;
  BB.isFreeHostingSuffix = (suffix) => FREE_HOSTING.has(suffix);
})();