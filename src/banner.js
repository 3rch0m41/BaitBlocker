// Banner in cima alle pagine pericolose.
// Vive in uno Shadow DOM "chiuso": il CSS della pagina non può deformarlo
// e gli script della pagina non possono leggerne o modificarne il contenuto.
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  const STYLE = `
    :host { all: initial; }
    .bar {
      box-sizing: border-box; width: 100%; padding: 12px 16px;
      background: #b3261e; color: #fff; font: 14px/1.45 system-ui, sans-serif;
      display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center;
      box-shadow: 0 2px 8px rgba(0,0,0,.3);
    }
    .text { flex: 1 1 320px; min-width: 0; }
    strong { font-size: 15px; }
    ul { margin: 4px 0 0; padding-left: 18px; }
    li { margin: 2px 0; overflow-wrap: anywhere; }
    .actions { display: flex; gap: 8px; }
    button {
      font: inherit; font-weight: 600; cursor: pointer; border-radius: 6px; padding: 6px 12px;
      border: 1px solid #fff; background: #fff; color: #b3261e;
    }
    button.ghost { background: transparent; color: #fff; }
  `;

  // Piccolo helper per creare elementi senza innerHTML (il linter di Mozilla lo segnala sempre).
  function h(tag, props, ...children) {
    const e = document.createElement(tag);
    Object.assign(e, props);
    for (const c of children) e.append(c);
    return e;
  }

  let host = null;
  let dismissedFor = null; // URL per cui l'utente ha chiuso il banner

  function hideBanner() {
    if (host) host.remove();
    host = null;
  }

  // verdict = { findings: [...] } (il verdetto completo URL + pagina dal background)
  function showBanner(verdict) {
    if (dismissedFor === location.href) return;
    hideBanner();

    host = document.createElement("baitblocker-banner");
    for (const [k, v] of [["position", "fixed"], ["top", "0"], ["left", "0"], ["right", "0"],
                          ["z-index", "2147483647"], ["display", "block"]]) {
      host.style.setProperty(k, v, "important"); // vince anche sul CSS "!important" della pagina
    }
    const root = host.attachShadow({ mode: "closed" });

    const reasons = verdict.findings.filter((x) => x.points > 0).sort((a, b) => b.points - a.points).slice(0, 3);
    const list = h("ul", {}, ...reasons.map((r) => h("li", { textContent: r.message }))); // testo, mai HTML

    const leave = h("button", { className: "leave", textContent: "Leave this page" });
    const dismiss = h("button", { className: "ghost dismiss", textContent: "Dismiss" });
    leave.addEventListener("click", () => {
      if (history.length > 1) history.back();
      else api.runtime.sendMessage({ type: "close-tab" }).catch(() => {});
    });
    dismiss.addEventListener("click", () => {
      dismissedFor = location.href;
      hideBanner();
    });

    root.append(
      h("style", { textContent: STYLE }),
      h("div", { className: "bar", role: "alert" },
        h("div", { className: "text" },
          h("strong", { textContent: "BaitBlocker: this page looks dangerous." }),
          " Do not enter passwords or payment data.",
          list),
        h("div", { className: "actions" }, leave, dismiss))
    );

    document.documentElement.appendChild(host);
  }

  BB.showBanner = showBanner;
  BB.hideBanner = hideBanner;
})();