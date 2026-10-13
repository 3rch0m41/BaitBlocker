// Pagina di avviso: mostra perché l'URL è stato bloccato e lascia decidere l'utente.
// ATTENZIONE: il parametro ?url= arriva (indirettamente) dall'attaccante.
// Va mostrato solo come testo e usato solo se è un vero indirizzo http(s).

const target = new URLSearchParams(location.search).get("url") || "";
const isWebUrl = /^https?:\/\//i.test(target);

const $ = (id) => document.getElementById(id);

(async () => {
  const { trustedHosts } = await api.storage.local.get("trustedHosts");
  const result = await BB.analyzeUrlFull(target, { trustedHosts: trustedHosts || [] });

  // Il dominio come lo vede l'utente (Unicode) e, se diverso, com'è davvero (punycode).
  const shown = BB.hostToUnicode(result.host || "");
  $("host").textContent = shown !== result.host ? `${shown}  (${result.host})` : result.host || "unknown address";
  $("url").textContent = target;
  $("trust-domain").textContent = result.registrable || "this site";

  for (const f of result.findings) {
    const li = document.createElement("li");
    li.textContent = f.message;
    if (f.points === 0) li.className = "info";
    $("findings").appendChild(li);
  }

  $("proceed").addEventListener("click", async () => {
    if (!isWebUrl) return; // mai navigare verso javascript:, data:, ecc.
    // "Continua comunque": vale per questo sito fino alla chiusura del browser.
    const { allowOnce } = await api.storage.session.get("allowOnce");
    await api.storage.session.set({ allowOnce: [...new Set([...(allowOnce || []), result.host])] });
    // "Fidati sempre": il dominio non verrà più confrontato con i brand.
    if ($("trust").checked && result.registrable) {
      await api.storage.local.set({ trustedHosts: [...new Set([...(trustedHosts || []), result.registrable])] });
    }
    location.replace(target);
  });

  $("back").addEventListener("click", async () => {
    if (history.length > 1) {
      history.back();
    } else {
      // Scheda aperta apposta per il link (es. da un'email): chiudila.
      const tab = await api.tabs.getCurrent();
      api.tabs.remove(tab.id);
    }
  });

  if (!isWebUrl) $("proceed").disabled = true;
})();