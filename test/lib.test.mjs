import test from "node:test";
import assert from "node:assert/strict";
import { loadBB } from "./load.mjs";

const BB = loadBB();

test("registrable domain: suffissi a più livelli", () => {
  assert.equal(BB.registrableDomain("login.amazon.co.uk"), "amazon.co.uk");
  assert.equal(BB.splitHost("login.amazon.co.uk").label, "amazon");
  assert.equal(BB.splitHost("paypa1.co.uk").label, "paypa1");
  assert.equal(BB.registrableDomain("www.agenziaentrate.gov.it"), "agenziaentrate.gov.it");
});

test("registrable domain: piattaforme di hosting", () => {
  const p = BB.splitHost("a.b.paypal-login.netlify.app");
  assert.equal(p.registrable, "paypal-login.netlify.app");
  assert.equal(p.label, "paypal-login");
  assert.equal(p.subdomain, "a.b");
  assert.ok(BB.isFreeHostingSuffix(p.suffix));
});

test("indirizzi IP", () => {
  assert.ok(BB.isIpHost("185.62.190.12"));
  assert.ok(BB.isIpHost("[::1]"));
  assert.ok(!BB.isIpHost("example.com"));
});

test("punycode: omografo cirillico e IDN legittimo", () => {
  assert.equal(BB.punycodeToUnicodeLabel("xn--80ak6aa92e"), "аррӏе");   // finto apple
  assert.equal(BB.punycodeToUnicodeLabel("xn--mller-kva"), "müller");
  assert.equal(BB.hostToUnicode("xn--e1afmkfd.xn--p1ai"), "пример.рф");
  assert.equal(BB.punycodeToUnicodeLabel("example"), "example");         // non IDN: invariato
  assert.equal(BB.punycodeToUnicodeLabel("xn--!!!"), "xn--!!!");         // malformato: invariato
});

test("alfabeti: misto vs singolo", () => {
  assert.deepEqual([...BB.scriptsIn("pаypal")].sort(), ["Cyrillic", "Latin"]); // 'а' cirillica
  assert.deepEqual([...BB.scriptsIn("пример")], ["Cyrillic"]);
  assert.deepEqual([...BB.scriptsIn("müller")], ["Latin"]);
});

test("skeleton: i sosia collassano sul latino", () => {
  assert.deepEqual(BB.unicodeSkeleton("аррӏе"), { skeleton: "apple", complete: true });
  assert.equal(BB.unicodeSkeleton("müller").skeleton, "muller");
  assert.equal(BB.unicodeSkeleton("пример").complete, false); // п, и, м non hanno sosia latini
});

test("letture plausibili di typosquat ASCII", () => {
  assert.ok(BB.readingVariants("paypa1").includes("paypal"));
  assert.ok(BB.readingVariants("m1crosoft").includes("microsoft"));
  assert.ok(BB.readingVariants("rnicrosoft").includes("microsoft"));
  assert.ok(BB.readingVariants("amaz0n").includes("amazon"));
});

test("OSA: la trasposizione conta 1", () => {
  assert.equal(BB.osaDistance("gogole", "google"), 1);
  assert.equal(BB.osaDistance("amzon", "amazon"), 1);
  assert.equal(BB.osaDistance("kitten", "sitting"), 3);
  assert.equal(BB.osaDistance("abc", "abcdefgh", 2), 3); // uscita anticipata: max+1
});

test("soglia relativa: niente falsi positivi sui nomi corti", () => {
  const isTypo = (label, brand) => {
    const d = BB.osaDistance(label, brand, BB.typoThreshold(brand.length));
    return d > 0 && d <= BB.typoThreshold(brand.length);
  };
  assert.ok(!isTypo("chess", "chase"));   // prima: falso positivo
  assert.ok(!isTypo("maple", "apple"));   // prima: falso positivo
  assert.ok(isTypo("paypai", "paypal"));
  assert.ok(isTypo("microsfot", "microsoft"));
});