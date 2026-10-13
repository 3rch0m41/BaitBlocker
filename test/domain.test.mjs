import test from "node:test";
import assert from "node:assert/strict";
import { loadBB } from "./load.mjs";

const BB = loadBB();
const check = (host) => BB.analyzeDomain(host);
const dump = (r) => `score ${r.score}: ` + r.findings.map((f) => `${f.id}(${f.points})`).join(", ");

const SAFE = [
  "www.paypal.com", "accounts.google.com", "www.amazon.co.uk", "www.amazon.com.br",
  "login.microsoftonline.com", "appleid.apple.com", "www.poste.it", "www.intesasanpaolo.com",
  "www.agenziaentrate.gov.it", "github.com", "en.wikipedia.org", "www.repubblica.it",
  "xn--mller-kva.de",          // müller.de
  "xn--e1afmkfd.xn--p1ai",     // пример.рф
  "www.laposte.fr", "arubanetworks.com", "www.chess.com", "maple.com",
  "192.168.1.1", "yahoo.co.jp", "www.unimi.it", "stackoverflow.com",
  "docs.google.com", "storage.googleapis.com", "forms.office.com"
];

const DANGEROUS = [
  "paypa1.com",
  "xn--80ak6aa92e.com",        // аррӏе.com (tutto cirillico)
  "xn--pypal-4ve.com",         // pаypal.com (una 'а' cirillica)
  "rn1crosoft.com",
  "intesasanpaol0.com"
];

const SUSPICIOUS = [
  "amazn.com", "gogle.com", "netflx.com", "paypal.xyz",
  "paypal-secure-login.xyz", "paypal.com.account-verify.xyz",
  "login-microsoftonline.netlify.app", "poste-italiane-verifica.com",
  "dhl-tracking-delivery.com", "185.62.190.12"
];

for (const h of SAFE) test(`safe: ${h}`, () => assert.equal(check(h).level, "safe", dump(check(h))));
for (const h of DANGEROUS) test(`dangerous: ${h}`, () => assert.equal(check(h).level, "dangerous", dump(check(h))));
for (const h of SUSPICIOUS) test(`at least suspicious: ${h}`, () => assert.notEqual(check(h).level, "safe", dump(check(h))));

test("i domini fidati dall'utente non vengono confrontati con i brand", () => {
  assert.equal(BB.analyzeDomain("paypal-login.example.com", { trustedHosts: ["example.com"] }).level, "safe");
});

test("l'IDN legittimo è solo informativo", () => {
  const r = check("xn--mller-kva.de");
  assert.equal(r.findings[0].id, "idn");
  assert.equal(r.findings[0].points, 0);
});

test("contenuti di terzi su domini di brand: non fidati, ma nemmeno 'brand falso'", () => {
  const r = check("docs.google.com");
  assert.equal(r.trusted, false);
  assert.ok(!r.findings.some((f) => f.id.startsWith("brand")));
});