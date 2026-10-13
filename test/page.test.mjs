import test from "node:test";
import assert from "node:assert/strict";
import { loadBB } from "./load.mjs";

const BB = loadBB();
// Array.from crea l'array nel contesto del test (quelli creati nella VM hanno un altro prototipo).
const ids = (r) => Array.from(r.findings, (f) => f.id);

// "Fatti" di una pagina: si parte da una pagina vuota e si cambia solo quello che serve.
const page = (over) => ({
  url: "https://example.com/", title: "", siteName: "", headings: [], logoTexts: [],
  passwordFields: 0, cardFields: 0, forms: [], resources: [], ...over
});

test("kit di phishing PayPal: titolo, logo clonato, form verso altro dominio", () => {
  const r = BB.analyzePage(page({
    url: "https://account-review.example/signin",
    title: "Log in to your PayPal account",
    logoTexts: ["PayPal logo"],
    passwordFields: 1,
    forms: [{ action: "https://collector.example/post.php", sensitive: true }],
    resources: ["https://www.paypalobjects.com/logo.svg", "https://www.paypalobjects.com/main.css"]
  }));
  assert.deepEqual(ids(r).sort(), ["brand-impersonation", "cloned-assets", "form-offsite"]);
  assert.equal(r.level, "dangerous");
});

test("Poste Italiane finta: chiede i dati della carta", () => {
  const r = BB.analyzePage(page({
    url: "https://verifica-conto.example/", title: "Poste Italiane - Area riservata", cardFields: 3
  }));
  assert.ok(ids(r).includes("brand-impersonation"));
  assert.match(r.findings[0].message, /payment card data/);
});

test("il sito vero del brand non è mai 'impersonificazione'", () => {
  const r = BB.analyzePage(page({
    url: "https://www.paypal.com/signin", title: "Log in to your PayPal account", passwordFields: 1,
    resources: ["https://www.paypalobjects.com/a.svg", "https://www.paypalobjects.com/b.css"]
  }));
  assert.equal(r.findings.length, 0);
});

test("pagina che parla di un brand ma non chiede credenziali: nessun indizio", () => {
  const r = BB.analyzePage(page({ url: "https://blog.example/", title: "Come funziona PayPal", headings: ["PayPal spiegato"] }));
  assert.equal(r.findings.length, 0);
});

test("i nomi rispettano le maiuscole: 'paypal' in minuscolo dentro un testo non conta", () => {
  const r = BB.analyzePage(page({ url: "https://shop.example/login", title: "Accedi - paga anche con paypal", passwordFields: 1 }));
  assert.ok(!ids(r).includes("brand-impersonation"));
});

test("login tra domini dello stesso brand: non è 'form verso altro dominio'", () => {
  const r = BB.analyzePage(page({
    url: "https://outlook.live.com/owa/", passwordFields: 1,
    forms: [{ action: "https://login.microsoftonline.com/common/login", sensitive: true }]
  }));
  assert.equal(r.findings.length, 0);
});

test("allegato HTML aperto dal disco con form di login", () => {
  const r = BB.analyzePage(page({ url: "file:///C:/Users/mario/Downloads/Fattura_2026.html", title: "Microsoft 365", passwordFields: 1 }));
  assert.ok(ids(r).includes("local-login-form"));
  assert.ok(ids(r).includes("brand-impersonation"));
  assert.equal(r.level, "dangerous");
});

test("form che spedisce la password via mailto e password su HTTP", () => {
  const r = BB.analyzePage(page({
    url: "http://old-site.example/login", passwordFields: 1,
    forms: [{ action: "mailto:attacker@example.net", sensitive: true }]
  }));
  assert.deepEqual(ids(r).sort(), ["form-mailto", "password-http"]);
});

test("Google Fonts e pulsanti social non sono 'pagina clonata'", () => {
  const r = BB.analyzePage(page({
    url: "https://shop.example/login", passwordFields: 1,
    resources: ["https://fonts.googleapis.com/css2?family=Inter", "https://fonts.gstatic.com/x.woff2",
                "https://www.facebook.com/tr?id=1", "https://static.xx.fbcdn.net/rsrc.php/x.css"]
  }));
  assert.ok(!ids(r).includes("cloned-assets"));
});

test("sito fidato dall'utente: niente controlli sul brand", () => {
  const r = BB.analyzePage(page({ url: "https://intranet.example/login", title: "Microsoft 365 login", passwordFields: 1 }),
    { trustedHosts: ["intranet.example"] });
  assert.equal(r.findings.length, 0);
});

test("i pulsanti di login social non sono impersonificazione", () => {
  const r = BB.analyzePage(page({
    url: "https://shop.example/login", title: "Accedi a Shop", passwordFields: 1,
    headings: ["Sign in with Google", "Accedi con Apple"], logoTexts: ["Continue with Microsoft"]
  }));
  assert.equal(r.findings.length, 0);
});