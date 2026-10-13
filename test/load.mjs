// Esegue gli script classici dell'estensione in un contesto VM e restituisce BB.
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/lib");

// In ordine di dipendenza. I file non ancora esistenti vengono saltati,
// così questo elenco non va toccato quando ne aggiungeremo altri.
const FILES = ["api.js", "psl.js", "punycode.js", "confusables.js", "distance.js",
               "brands.js", "url-analyzer.js", "page-analyzer.js", "url-analyzer.js", "blocklist.js","link-analyzer.js","page-analyzer.js"];

export function loadBB(extraGlobals = {}) {
  const ctx = { URL, console, ...extraGlobals };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  for (const f of FILES) {
    const p = path.join(root, f);
    if (fs.existsSync(p)) vm.runInContext(fs.readFileSync(p, "utf8"), ctx, { filename: f });
  }
  return ctx.BB;
}