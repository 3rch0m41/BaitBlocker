// Blocklist pubbliche, scaricate periodicamente e confrontate IN LOCALE.
// Gli URL che l'utente visita non vengono mai inviati a nessuno.
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  const FEEDS = [
    // Phishing attivo. hostMatch: segnala anche il resto del sito (con meno punti).
    { id: "openphish", name: "OpenPhish", url: "https://openphish.com/feed.txt", hostMatch: true },
    // Malware (soprattutto download), spesso su siti legittimi compromessi: solo URL esatti.
    { id: "urlhaus", name: "URLhaus (abuse.ch)", url: "https://urlhaus.abuse.ch/downloads/text_online/", hostMatch: false }
  ];
  const MAX_AGE_MS = 6 * 60 * 60 * 1000; // 6 ore

  let cache = null;   // Map feedId -> { urls: Set, hosts: Set }
  let loading = null;

  // "HTTPS://Evil.com/Path/?a=1#x" -> "evil.com/Path?a=1"  (senza schema, frammento e "/" finale)
  function normalize(raw) {
    try {
      const u = new URL(String(raw).trim());
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      const path = u.pathname.replace(/\/+$/, "");
      return u.hostname.toLowerCase() + (u.port ? ":" + u.port : "") + path + u.search;
    } catch (e) {
      return null;
    }
  }

  function hostOf(key) {
    return key.split(/[/:?]/)[0];
  }

  // Un URL visitato corrisponde se coincide con una voce, con o senza parametri.
  function keysFor(raw) {
    const k = normalize(raw);
    if (!k) return [];
    const q = k.indexOf("?");
    return q > 0 ? [k, k.slice(0, q).replace(/\/+$/, "")] : [k];
  }

  function toSets(entries, feed) {
    const urls = new Set(entries);
    const hosts = new Set();
    if (feed.hostMatch) for (const k of urls) hosts.add(hostOf(k));
    return { urls, hosts };
  }

  async function load() {
    if (cache) return cache;
    if (!loading) {
      loading = (async () => {
        const stored = await api.storage.local.get(FEEDS.map((f) => "feed:" + f.id));
        const m = new Map();
        for (const feed of FEEDS) {
          const text = stored["feed:" + feed.id] || "";
          m.set(feed.id, toSets(text ? text.split("\n") : [], feed));
        }
        cache = m;
        loading = null;
        return m;
      })();
    }
    return loading;
  }

  // Scarica i feed più vecchi di 6 ore (o tutti, con force = true).
  async function update(force = false) {
    const { feedMeta = {} } = await api.storage.local.get("feedMeta");
    const now = Date.now();
    for (const feed of FEEDS) {
      const meta = feedMeta[feed.id] || {};
      if (!force && meta.updated && now - meta.updated < MAX_AGE_MS) continue;
      try {
        const res = await fetch(feed.url, { cache: "no-store" });
        if (!res.ok) throw new Error("HTTP " + res.status);
        const entries = new Set();
        for (const line of (await res.text()).split(/\r?\n/)) {
          if (!line || line.startsWith("#")) continue; // URLhaus ha righe di commento
          const k = normalize(line);
          if (k) entries.add(k);
        }
        if (entries.size === 0) throw new Error("empty feed");
        await api.storage.local.set({ ["feed:" + feed.id]: [...entries].join("\n") });
        feedMeta[feed.id] = { updated: now, count: entries.size, error: null };
        if (cache) cache.set(feed.id, toSets([...entries], feed));
      } catch (e) {
        // Se il download fallisce teniamo la lista vecchia: meglio datata che niente.
        feedMeta[feed.id] = { ...meta, error: String(e.message || e), lastAttempt: now };
      }
    }
    await api.storage.local.set({ feedMeta });
    return feedMeta;
  }

  // -> { feed, exact: true|false } oppure null
  async function lookup(raw) {
    const m = await load();
    const keys = keysFor(raw);
    if (!keys.length) return null;
    for (const feed of FEEDS) {
      const s = m.get(feed.id);
      if (keys.some((k) => s.urls.has(k))) return { feed, exact: true };
    }
    const host = hostOf(keys[0]);
    // Mai segnalare per dominio i servizi condivisi (Google Docs, Dropbox...) o i brand ufficiali.
    if (BB.isUserContentHost(host) || BB.officialBrandFor(host)) return null;
    for (const feed of FEEDS) {
      if (feed.hostMatch && m.get(feed.id).hosts.has(host)) return { feed, exact: false };
    }
    return null;
  }

  // analyzeUrl() + blocklist: è la versione "completa" usata da background e pagina di avviso.
  async function analyzeUrlFull(raw, options = {}) {
    const result = BB.analyzeUrl(raw, options);
    if (options.useBlocklists === false || !result.host) return result;
    // Controlla sia l'URL originale sia la destinazione vera (link avvolti).
    const hit = (await lookup(raw)) || (result.wrapper ? await lookup(result.url) : null);
    if (hit) {
      result.findings.unshift(hit.exact
        ? BB.makeFinding("blocklist", 10, "high", `Listed as malicious by the ${hit.feed.name} threat feed.`)
        : BB.makeFinding("blocklist-host", 5, "high", `This site recently hosted phishing pages (${hit.feed.name}).`));
      result.score = result.findings.reduce((s, x) => s + x.points, 0);
      result.level = BB.levelFor(result.score);
    }
    return result;
  }

  async function status() {
    const { feedMeta = {} } = await api.storage.local.get("feedMeta");
    return FEEDS.map((f) => ({ id: f.id, name: f.name, ...(feedMeta[f.id] || {}) }));
  }

  BB.blocklist = { update, lookup, status, normalize, FEEDS };
  BB.analyzeUrlFull = analyzeUrlFull;
})();