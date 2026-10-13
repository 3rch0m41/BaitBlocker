// Impostazioni dell'utente, condivise da background, content script e popup.
// Stanno in storage.local: sopravvivono al riavvio del browser.
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  const DEFAULT_SETTINGS = {
    enabled: true,          // interruttore generale
    blockNavigation: true,  // pagina di avviso prima dei siti pericolosi
    highlightLinks: true,   // bordo rosso/arancione sui link e blocco del clic
    showBanner: true,       // banner in cima alle pagine pericolose
    useBlocklists: true     // OpenPhish / URLhaus
  };

  async function getSettings() {
    const { settings } = await api.storage.local.get("settings");
    return { ...DEFAULT_SETTINGS, ...(settings || {}) };
  }

  async function setSettings(patch) {
    const next = { ...(await getSettings()), ...patch };
    await api.storage.local.set({ settings: next });
    return next;
  }

  // cb(nuoveImpostazioni) ogni volta che cambiano (da qualunque parte dell'estensione).
  function onSettingsChanged(cb) {
    api.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.settings) cb({ ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) });
    });
  }

  BB.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
  BB.getSettings = getSettings;
  BB.setSettings = setSettings;
  BB.onSettingsChanged = onSettingsChanged;
})();