// Brand protetti: nomi imitati dagli attaccanti e domini che il brand possiede davvero.
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  const BRANDS = [
    { id: "google", names: ["Google", "Gmail"], tokens: ["google", "gmail"],
      domains: ["google.com", "google.it", "google.co.uk", "google.de", "google.fr", "google.es", "gmail.com", "youtube.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "withgoogle.com", "google.dev"] },
    { id: "paypal", names: ["PayPal"], tokens: ["paypal"],
      domains: ["paypal.com", "paypal.me", "paypalobjects.com", "paypal.it"] },
    { id: "amazon", names: ["Amazon"], tokens: ["amazon"],
      domains: ["amazon.com", "amazon.it", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es", "amazon.nl", "amazon.ca", "amazon.co.jp", "amazon.com.br", "amazon.com.au", "amazon.in", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com", "primevideo.com", "a2z.com", "amazon.dev"] },
    { id: "netflix", names: ["Netflix"], tokens: ["netflix"],
      domains: ["netflix.com", "nflxext.com", "nflximg.net", "nflxso.net", "nflxvideo.net"] },
    { id: "apple", names: ["Apple ID", "iCloud", "Apple"], tokens: ["apple", "icloud", "appleid", "itunes"],
      domains: ["apple.com", "icloud.com", "me.com", "mzstatic.com", "apple.news", "cdn-apple.com"] },
    { id: "microsoft", names: ["Microsoft", "Office 365", "Microsoft 365", "Outlook", "OneDrive", "SharePoint", "Hotmail"],
      tokens: ["microsoft", "office365", "microsoft365", "outlook", "onedrive", "sharepoint", "hotmail", "microsoftonline"],
      domains: ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "office.net", "windows.net", "sharepoint.com", "onedrive.com", "msauth.net", "msftauth.net", "azure.com", "bing.com", "skype.com", "xbox.com", "hotmail.com", "msn.com", "microsoft365.com", "cloud.microsoft", "live.net", "aka.ms"] },
    { id: "facebook", names: ["Facebook", "Meta"], tokens: ["facebook"],
      domains: ["facebook.com", "fb.com", "fbcdn.net", "facebook.net", "messenger.com", "meta.com"] },
    { id: "instagram", names: ["Instagram"], tokens: ["instagram"], domains: ["instagram.com", "cdninstagram.com"] },
    { id: "whatsapp", names: ["WhatsApp"], tokens: ["whatsapp"], domains: ["whatsapp.com", "whatsapp.net", "wa.me"] },
    { id: "linkedin", names: ["LinkedIn"], tokens: ["linkedin"], domains: ["linkedin.com", "licdn.com", "lnkd.in"] },
    { id: "chase", names: ["Chase"], tokens: ["chase", "jpmorgan"], domains: ["chase.com", "jpmorgan.com", "jpmorganchase.com"] },
    { id: "bankofamerica", names: ["Bank of America"], tokens: ["bankofamerica"], domains: ["bankofamerica.com", "bofa.com"] },
    { id: "wellsfargo", names: ["Wells Fargo"], tokens: ["wellsfargo"], domains: ["wellsfargo.com"] },
    { id: "dropbox", names: ["Dropbox"], tokens: ["dropbox"], domains: ["dropbox.com", "dropboxusercontent.com", "dropboxstatic.com"] },
    { id: "docusign", names: ["DocuSign"], tokens: ["docusign"], domains: ["docusign.com", "docusign.net"] },
    { id: "adobe", names: ["Adobe"], tokens: ["adobe"], domains: ["adobe.com", "adobelogin.com", "typekit.net", "adobe.io"] },
    { id: "dhl", names: ["DHL"], tokens: ["dhl"], domains: ["dhl.com", "dhl.it", "dhl.de"] },
    { id: "fedex", names: ["FedEx"], tokens: ["fedex"], domains: ["fedex.com"] },
    { id: "yahoo", names: ["Yahoo"], tokens: ["yahoo"], domains: ["yahoo.com", "yahoo.it", "yimg.com"] },
    { id: "spotify", names: ["Spotify"], tokens: ["spotify"], domains: ["spotify.com", "scdn.co"] },
    { id: "twitter", names: ["Twitter"], tokens: ["twitter"], domains: ["twitter.com", "x.com", "twimg.com", "t.co"] },
    { id: "github", names: ["GitHub"], tokens: ["github"], domains: ["github.com", "githubassets.com"] },
    { id: "ebay", names: ["eBay"], tokens: ["ebay"], domains: ["ebay.com", "ebay.it", "ebay.co.uk", "ebay.de", "ebaystatic.com"] },
    { id: "steam", names: ["Steam"], tokens: ["steampowered", "steamcommunity"], domains: ["steampowered.com", "steamcommunity.com", "steamstatic.com"] },
    { id: "binance", names: ["Binance"], tokens: ["binance"], domains: ["binance.com"] },
    { id: "coinbase", names: ["Coinbase"], tokens: ["coinbase"], domains: ["coinbase.com"] },
    { id: "metamask", names: ["MetaMask"], tokens: ["metamask"], domains: ["metamask.io"] },
    // Bersagli italiani
    { id: "poste", names: ["Poste Italiane", "PostePay", "BancoPosta"], tokens: ["poste", "posteitaliane", "postepay", "bancoposta"],
      domains: ["poste.it", "posteitaliane.it", "postepay.it"] },
    { id: "intesasanpaolo", names: ["Intesa Sanpaolo"], tokens: ["intesasanpaolo"], domains: ["intesasanpaolo.com", "intesasanpaolo.it"] },
    { id: "unicredit", names: ["UniCredit"], tokens: ["unicredit"], domains: ["unicredit.it", "unicredit.eu", "unicreditgroup.eu"] },
    { id: "fineco", names: ["Fineco"], tokens: ["finecobank"], domains: ["finecobank.com", "fineco.it"] },
    { id: "mediolanum", names: ["Banca Mediolanum"], tokens: ["mediolanum", "bancamediolanum"], domains: ["bancamediolanum.it", "mediolanum.it"] },
    { id: "bper", names: ["BPER Banca"], tokens: ["bper"], domains: ["bper.it"] },
    { id: "nexi", names: ["Nexi"], tokens: ["nexi"], domains: ["nexi.it", "nexigroup.com"] },
    { id: "satispay", names: ["Satispay"], tokens: ["satispay"], domains: ["satispay.com"] },
    { id: "aruba", names: ["Aruba"], tokens: ["aruba"], domains: ["aruba.it", "arubapec.it", "pec.it"] },
    { id: "inps", names: ["INPS"], tokens: ["inps"], domains: ["inps.it"] },
    { id: "agenziaentrate", names: ["Agenzia delle Entrate"], tokens: ["agenziaentrate", "agenziaentrateriscossione"],
      domains: ["agenziaentrate.gov.it", "agenziaentrateriscossione.gov.it", "agenziaentrate.it"] }
  ];

  // Domini di aziende fidate dove però CHIUNQUE può pubblicare contenuti.
  const USER_CONTENT_HOSTS = [
    "storage.googleapis.com", "firebasestorage.googleapis.com", "sites.google.com",
    "docs.google.com", "drive.google.com", "forms.gle", "script.google.com",
    "googleusercontent.com", "blob.core.windows.net", "web.core.windows.net",
    "forms.office.com", "1drv.ms", "sway.office.com", "onedrive.live.com",
    "dropboxusercontent.com", "dl.dropboxusercontent.com", "s3.amazonaws.com",
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "gateway.pinata.cloud", "ipfs.w3s.link"
  ];

  // "login.paypal.com" corrisponde a "paypal.com"; "paypal.com.evil.xyz" no.
  function hostMatches(host, domain) {
    return host === domain || host.endsWith("." + domain);
  }

  function officialBrandFor(host) {
    for (const b of BRANDS) {
      if (b.domains.some((d) => hostMatches(host, d))) return b;
    }
    return null;
  }

  function isUserContentHost(host) {
    return USER_CONTENT_HOSTS.some((d) => hostMatches(host, d));
  }

  BB.BRANDS = BRANDS;
  BB.officialBrandFor = officialBrandFor;
  BB.isUserContentHost = isUserContentHost;
  BB.hostMatches = hostMatches;
})();