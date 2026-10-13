<p align="center"><img src="src/icons/icon-128.png" width="96" alt="Logo di BaitBlocker"></p>

# BaitBlocker

[English](README.md) | **Italiano**

Un'estensione per Chrome e Firefox che riconosce **pagine di phishing e URL malevoli** mentre navighi, compresi i link dentro le email aperte in Gmail o in Outlook web.

Tutto avviene **in locale**: l'estensione non invia mai a nessun server le pagine o gli indirizzi che visiti.

## Cosa fa

| Protezione | Come |
|---|---|
| **Blocca i siti pericolosi prima che si carichino** | Ogni navigazione viene analizzata *prima* che la richiesta esca dal browser. Gli URL pericolosi vengono sostituiti da una pagina di avviso ("Go back to safety" / "Continue anyway"). |
| **Controlla tutti i link della pagina** | I link vengono evidenziati in rosso (pericolosi) o arancione (sospetti), con i motivi nel tooltip. Cliccando un link pericoloso si apre la pagina di avviso. Funziona anche sulle pagine dinamiche come le webmail. |
| **Smaschera i link che mentono** | Un link il cui testo dice `www.paypal.com` ma che apre un altro sito. |
| **Riconosce chi si spaccia per un brand** | Pagine che si presentano come PayPal, Microsoft, Poste Italiane… e chiedono password o dati della carta, ma non sono ospitate sui domini di quel brand. |
| **Avvisa sulle pagine pericolose** | Un banner (isolato in uno Shadow DOM chiuso) e un badge sull'icona della barra degli strumenti. |
| **Blocklist** | Le liste OpenPhish e URLhaus, scaricate ogni 6 ore e confrontate in locale. |

## Tecniche di rilevamento

**Analisi del dominio**
- **Dominio registrabile (eTLD+1)** tramite una Public Suffix List compatta: `login.amazon.co.uk` → `amazon`, `paypal-login.netlify.app` → `paypal-login`.
- **Omografi IDN**: decodifica Punycode (RFC 3492), riconoscimento degli alfabeti misti e "skeleton" Unicode ispirati a Unicode TR39 (`xn--80ak6aa92e.com` → `аррӏе.com`, lettere cirilliche che imitano *apple*).
- **Typosquatting** con la distanza Optimal String Alignment (Levenshtein + trasposizioni di lettere adiacenti) e una soglia relativa alla lunghezza del brand, più le sostituzioni con caratteri sosia (`paypa1`, `rnicrosoft`, `amaz0n`).
- **Combosquatting** (`paypal-secure-login`, `poste-italiane-verifica`) e **brand nel sottodominio** (`paypal.com.account-verify.xyz`).

**Analisi dell'URL**
- Estrae la destinazione vera dai link "avvolti" (redirect di Google, Outlook Safe Links, Proofpoint URL Defense, Facebook, LinkedIn…) e analizza quella.
- Trucchi `utente@host`, IP diretti, URL `data:`, doppie estensioni (`fattura.pdf.exe`), eseguibili, TLD a rischio o che sembrano file (`.zip`, `.mov`), hosting gratuiti e tunnel, IPFS, domini dall'aspetto casuale, open redirect, parole tipiche del phishing (in inglese e in italiano).

**Analisi della pagina**
- Password su HTTP, form di login o di pagamento che inviano i dati a un altro dominio o via `mailto:`.
- Impersonificazione di un brand (titolo, nome del sito, intestazioni, loghi) e pagine clonate che caricano immagini e stili dai server del brand stesso.
- Allegati HTML aperti dal disco (`file://`) che chiedono credenziali.

Ogni indizio aggiunge punti: **da 3 a 6 = sospetto**, **7 o più = pericoloso**. I controlli sui brand non si applicano mai ai domini ufficiali del brand, e l'utente può dichiarare fidato un sito.

## Installazione

### Dal codice sorgente (sviluppo)

```bash
npm install        # installa web-ext (lo strumento di Mozilla per le estensioni)
npm run build      # crea dist/chrome e dist/firefox
```

- **Chrome / Edge**: `chrome://extensions` → attiva *Modalità sviluppatore* → *Carica estensione non pacchettizzata* → scegli `dist/chrome`.
  Per analizzare i file HTML locali, attiva *Consenti l'accesso agli URL dei file* nei dettagli dell'estensione.
- **Firefox**: `about:debugging` → *Questo Firefox* → *Carica componente aggiuntivo temporaneo* → scegli `dist/firefox/manifest.json`.
  Se serve, concedi l'accesso a tutti i siti in `about:addons` → BaitBlocker → *Permessi*.

### Pacchetti

```bash
npm run package    # packages/baitblocker-chrome-<versione>.zip e baitblocker-firefox-<versione>.zip
```

## Sviluppo

```bash
npm test           # test unitari (test runner integrato di Node, senza browser)
npm run lint       # web-ext lint di Mozilla sulla build per Firefox
```

### Struttura del progetto

```
src/
├── background.js        guardia sulle navigazioni, verdetto per scheda, badge, aggiornamento feed
├── content.js           raccolta dei dati della pagina, scansione link, blocco clic, banner
├── banner.js            banner di avviso nella pagina (Shadow DOM chiuso)
├── content.css          evidenziazione dei link
├── lib/
│   ├── api.js           compatibilità chrome/browser
│   ├── psl.js           dominio registrabile (Public Suffix List compatta)
│   ├── punycode.js      decoder RFC 3492
│   ├── confusables.js   skeleton dei caratteri sosia, riconoscimento alfabeti
│   ├── distance.js      distanza OSA, soglie relative
│   ├── brands.js        brand protetti e loro domini ufficiali
│   ├── domain-analyzer.js
│   ├── url-analyzer.js
│   ├── link-analyzer.js
│   ├── page-analyzer.js
│   ├── blocklist.js     OpenPhish / URLhaus, confrontate in locale
│   └── settings.js
├── popup/               verdetto, impostazioni, siti fidati, stato dei feed
└── warning/             pagina di avviso a schermo intero
manifests/               chrome.json, firefox.json
tests/                   test unitari per ogni analizzatore
build.mjs                copia src/ e il manifest giusto in dist/<browser>
```

Gli analizzatori sono **funzioni pure** (in ingresso stringhe e oggetti semplici, in uscita gli indizi). Il codice che tocca il DOM si limita a raccogliere i dati, quindi tutta la logica di rilevamento è testata con Node.

## Privacy

- Nessuna statistica d'uso, nessuna analisi remota: URL e contenuti delle pagine non escono mai dal browser.
- Le uniche richieste di rete dell'estensione sono i download delle blocklist pubbliche.

## Limiti

- Le euristiche possono dare falsi positivi (per esempio brand il cui nome è anche una parola comune, come *Apple* o *Chase*) e non vedere un phishing ben fatto su un dominio "pulito". Per il primo caso c'è *Trust this site*; per il secondo aiutano le blocklist.
- Una pagina malevola può rimuovere il banner; il badge sull'icona e la guardia sulle navigazioni invece non sono raggiungibili dagli script della pagina.
- L'elenco dei brand e la Public Suffix List sono volutamente compatti e andranno ampliati nel tempo.

## Sviluppi futuri

- Analisi del mittente nelle webmail (nome visualizzato rispetto all'indirizzo reale).
- Public Suffix List completa e un elenco di brand più ampio.
- Interfaccia tradotta (italiano / inglese).
- Controllo facoltativo dell'età del dominio.

## Crediti

- Dati sulle minacce: feed community di [OpenPhish](https://openphish.com/) e [URLhaus](https://urlhaus.abuse.ch/) di abuse.ch.
- Gestione dei caratteri sosia ispirata allo [Unicode Technical Standard #39](https://www.unicode.org/reports/tr39/).
- Suffissi pubblici dalla [Public Suffix List](https://publicsuffix.org/).

## Licenza

[CC0 1.0 Universal](LICENSE): dedicato al pubblico dominio.
