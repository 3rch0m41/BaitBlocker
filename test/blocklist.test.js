import test from "node:test";
import assert from "node:assert/strict";
import { loadBB } from "./load.mjs";

// Finti storage.local e fetch: nessuna rete, nessun browser.
function fakeEnvironment(feeds) {
  const store = {};
  const api = {
    storage: {
      local: {
        get: async (keys) => {
          const out = {};
          for (const k of [].concat(keys)) if (k in store) out[k] = store[k];
          return out;
        },
        set: async (obj) => { Object.assign(store, obj); }
      }
    }
  };
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    if (!(url in feeds)) return { ok: false, status: 503 };
    return { ok: true, text: async () => feeds[url] };
  };
  return { api, fetch, store, calls };
}

const OPENPHISH = "https://openphish.com/feed.txt";
const URLHAUS = "https://urlhaus.abuse.ch/downloads/text_online/";

function setup(feeds) {
  const env = fakeEnvironment(feeds);
  const BB = loadBB({ api: env.api, fetch: env.fetch });
  return { BB, env };
}

test("normalize: schema, maiuscole, frammento e slash finale non contano", () => {
  const { BB } = setup({});
  assert.equal(BB.blocklist.normalize("HTTPS://Evil.COM/Path/?a=1#x"), "evil.com/Path?a=1");
  assert.equal(BB.blocklist.normalize("http://evil.com/"), "evil.com");
  assert.equal(BB.blocklist.normalize("javascript:alert(1)"), null);
});

test("URL esatto in blocklist -> pericoloso anche se l'URL sembra pulito", async () => {
  const { BB } = setup({
    [OPENPHISH]: "https://innocent-looking.example/promo/\nhttps://other.example/x\n",
    [URLHAUS]: "# comment\n# another\nhttp://198.51.100.7/bins/payload\n"
  });
  await BB.blocklist.update(true);
  const r = await BB.analyzeUrlFull("https://innocent-looking.example/promo");
  assert.equal(r.level, "dangerous");
  assert.equal(r.findings[0].id, "blocklist");
  const m = await BB.analyzeUrlFull("http://198.51.100.7/bins/payload");
  assert.equal(m.findings[0].id, "blocklist");
});

test("stesso sito, altra pagina: OpenPhish segnala il dominio con meno punti", async () => {
  const { BB } = setup({ [OPENPHISH]: "https://innocent-looking.example/promo\n", [URLHAUS]: "#\nhttp://a.example/x\n" });
  await BB.blocklist.update(true);
  const r = await BB.analyzeUrlFull("https://innocent-looking.example/other-page");
  assert.equal(r.findings[0].id, "blocklist-host");
  assert.equal(r.level, "suspicious");
});

test("i servizi condivisi non vengono mai segnalati per dominio", async () => {
  const { BB } = setup({ [OPENPHISH]: "https://docs.google.com/forms/d/evil123/viewform\n", [URLHAUS]: "#\nhttp://a.example/x\n" });
  await BB.blocklist.update(true);
  assert.equal((await BB.analyzeUrlFull("https://docs.google.com/forms/d/evil123/viewform")).findings[0].id, "blocklist");
  assert.equal((await BB.analyzeUrlFull("https://docs.google.com/document/d/legit")).level, "safe");
});

test("link avvolti: si controlla anche la destinazione", async () => {
  const { BB } = setup({ [OPENPHISH]: "https://innocent-looking.example/promo\n", [URLHAUS]: "#\nhttp://a.example/x\n" });
  await BB.blocklist.update(true);
  const r = await BB.analyzeUrlFull("https://www.google.com/url?q=https://innocent-looking.example/promo");
  assert.equal(r.level, "dangerous");
});

test("niente ri-download prima di 6 ore", async () => {
  const { BB, env } = setup({ [OPENPHISH]: "https://innocent-looking.example/promo\n", [URLHAUS]: "#\nhttp://a.example/x\n" });
  await BB.blocklist.update(true);
  assert.equal(env.calls.length, 2);
  await BB.blocklist.update(false);
  assert.equal(env.calls.length, 2); // liste ancora fresche: nessuna richiesta
});

test("download fallito: si tiene la lista vecchia", async () => {
  const feeds = { [OPENPHISH]: "https://innocent-looking.example/promo\n", [URLHAUS]: "#\nhttp://a.example/x\n" };
  const { BB } = setup(feeds);
  await BB.blocklist.update(true);
  delete feeds[OPENPHISH];                 // ora il server risponde 503
  const meta = await BB.blocklist.update(true);
  assert.match(meta.openphish.error, /503/);
  assert.equal(meta.openphish.count, 1);   // il conteggio della lista precedente resta
  assert.equal((await BB.analyzeUrlFull("https://innocent-looking.example/promo")).level, "dangerous");
});

test("feed irraggiungibile: errore registrato, nessuna eccezione", async () => {
  const { BB } = setup({});
  const meta = await BB.blocklist.update(true);
  assert.match(meta.openphish.error, /503/);
  assert.equal((await BB.analyzeUrlFull("https://example.com/")).level, "safe");
});