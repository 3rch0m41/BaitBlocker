// In Chrome il background è un service worker: le librerie si caricano con importScripts.
// In Firefox le carica il manifest (background.scripts), e importScripts non esiste.
if (typeof importScripts === "function") {
  importScripts("lib/api.js");
}

api.runtime.onInstalled.addListener((details) => {
  console.log("BaitBlocker installato:", details.reason);
});