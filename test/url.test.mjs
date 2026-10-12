import test from "node:test";
import assert from "node:assert/strict";
import { loadBB } from "./load.mjs";

const BB = loadBB();
const dump = (r) => `score ${r.score}: ` + r.findings.map((f) => `${f.id}(${f.points})`).join(", ");

const SAFE = [
  "https://www.paypal.com/signin",
  "https://accounts.google.com/ServiceLogin",
  "https://www.amazon.co.uk/gp/cart",
  "https://login.microsoftonline.com/common/oauth2/authorize",
  "https://www.poste.it/",
  "https://www.agenziaentrate.gov.it/portale/",
  "https://github.com/login",
  "https://en.wikipedia.org/wiki/Phishing",
  "https://xn--mller-kva.de/",                                   // müller.de
  "https://www.google.com/url?q=https://www.wikipedia.org/&sa=D", // redirect verso sito pulito
  "http://192.168.1.1/admin",                                    // router di casa
  "https://shop.example.com/login?next=/account",
  "https://www.unimi.it/it"
];

const DANGEROUS = [
  "https://paypa1.com/signin",
  "https://xn--80ak6aa92e.com/",                                 // аррӏе.com
  "https://paypal.com.account-verify.xyz/login",
  "https://paypal-secure-login.xyz/",
  "https://www.google.com@evil.example/login",
  "https://amaz0n-account-update.top/verify",
  "https://poste-italiane-verifica.com/accesso",
  "https://login-microsoftonline.netlify.app/",
  "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.com%2Fsignin&data=x",
  "https://www.google.com/url?q=https://paypal-login-verify.xyz/&sa=D",
  "http://185.62.190.12/paypal/login.php",
  "https://dhl-tracking-delivery.com/consegna",
  "https://cdn.example.org/files/fattura.pdf.exe"
];

const SUSPICIOUS = [
  "https://amazn.com/",
  "https://paypal.xyz/",
  "https://kq8xzvbrtp4wmn.top/a",
  "https://invoice.zip/"
];

for (const u of SAFE) test(`safe: ${u}`, () => { const r = BB.analyzeUrl(u); assert.equal(r.level, "safe", dump(r)); });
for (const u of DANGEROUS) test(`dangerous: ${u}`, () => { const r = BB.analyzeUrl(u); assert.equal(r.level, "dangerous", dump(r)); });
for (const u of SUSPICIOUS) test(`at least suspicious: ${u}`, () => { const r = BB.analyzeUrl(u); assert.notEqual(r.level, "safe", dump(r)); });

test("i link avvolti vengono analizzati sulla destinazione vera", () => {
  const r = BB.analyzeUrl("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.com%2F");
  assert.equal(r.host, "paypa1.com");
  assert.equal(r.findings[0].id, "redirector");
});

test("gli shortener sono segnalati ma da soli non bastano", () => {
  const r = BB.analyzeUrl("https://bit.ly/3xYz");
  assert.ok(r.findings.some((f) => f.id === "shortener"));
  assert.equal(r.level, "safe");
});

test("schemi non web vengono ignorati", () => {
  assert.equal(BB.analyzeUrl("chrome://extensions").findings.length, 0);
  assert.equal(BB.analyzeUrl("non è un url").findings.length, 0);
});