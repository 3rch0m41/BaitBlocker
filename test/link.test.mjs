import test from "node:test";
import assert from "node:assert/strict";
import { loadBB } from "./load.mjs";

const BB = loadBB();
const dump = (r) => `score ${r.score}: ` + r.findings.map((f) => `${f.id}(${f.points})`).join(", ");

test("riconosce quando il testo del link è un indirizzo", () => {
  assert.equal(BB.hostShownIn("www.paypal.com"), "www.paypal.com");
  assert.equal(BB.hostShownIn("https://www.poste.it/accesso"), "www.poste.it");
  assert.equal(BB.hostShownIn("  PayPal.com  "), "paypal.com");
});

test("ignora testo normale, nomi di file, email e numeri", () => {
  for (const t of ["Clicca qui", "Accedi al tuo account", "report.pdf", "foto.jpg",
                   "mario@rossi.it", "Versione 1.2.3", "Node.js", "e.g. this", ""]) {
    assert.equal(BB.hostShownIn(t), null, t);
  }
});

test("testo 'www.paypal.com' ma il link porta altrove -> pericoloso", () => {
  const r = BB.analyzeLink("https://secure-check.example/login", "www.paypal.com");
  assert.equal(r.level, "dangerous", dump(r));
  assert.ok(r.findings.some((f) => f.id === "text-href-mismatch"));
  assert.ok(r.findings.some((f) => f.id === "text-shows-brand"));
});

test("testo e link sullo stesso sito -> nessun indizio", () => {
  const r = BB.analyzeLink("https://www.amazon.it/gp/your-account", "amazon.it");
  assert.equal(r.findings.length, 0, dump(r));
  assert.equal(BB.analyzeLink("https://login.example.com/x", "www.example.com").findings.length, 0);
});

test("newsletter tramite servizio di tracking -> indizio debole", () => {
  const r = BB.analyzeLink("https://u123.ct.sendgrid.net/ls/click?upn=abc", "www.negozio.it");
  assert.equal(r.level, "safe", dump(r));
  assert.ok(r.findings.some((f) => f.id === "text-href-tracker"));
});

test("testo normale: conta solo dove porta il link", () => {
  assert.equal(BB.analyzeLink("https://paypa1.com/signin", "Accedi").level, "dangerous");
  assert.equal(BB.analyzeLink("https://www.wikipedia.org/", "Leggi di più").level, "safe");
});

test("link Outlook Safe Links: si analizza la destinazione", () => {
  const r = BB.analyzeLink("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.com%2F", "Verifica account");
  assert.equal(r.host, "paypa1.com");
  assert.equal(r.level, "dangerous");
});