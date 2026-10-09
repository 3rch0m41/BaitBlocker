// Firefox espone `browser`, Chrome espone `chrome`.
// In Manifest V3 entrambi restituiscono Promise, quindi possiamo usarli allo stesso modo.
(function () {
  const g = globalThis;
  g.api = g.api || (typeof g.browser !== "undefined" && g.browser.runtime ? g.browser : g.chrome);
  g.BB = g.BB || {}; // "namespace" dove metteremo tutte le funzioni di BaitBlocker
})();