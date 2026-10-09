// Costruisce dist/chrome e dist/firefox: copia src/ e ci mette il manifest giusto.
import fs from "node:fs";

for (const target of ["chrome", "firefox"]) {
  const out = `dist/${target}`;
  fs.rmSync(out, { recursive: true, force: true });
  fs.cpSync("src", out, { recursive: true });
  fs.copyFileSync(`manifests/${target}.json`, `${out}/manifest.json`);
  console.log("✓ built", out);
}