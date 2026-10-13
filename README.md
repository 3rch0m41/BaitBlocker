<p align="center"><img src="src/icons/icon-128.png" width="96" alt="BaitBlocker logo"></p>

# BaitBlocker

**English** | [Italiano](README.it.md)

A browser extension for Chrome and Firefox that detects **phishing pages and malicious URLs** while you browse, including the links inside e-mails opened in Gmail or Outlook on the web.

Everything runs **locally**: the extension never sends the pages or URLs you visit to any server.

## What it does

| Protection | How |
|---|---|
| **Blocks dangerous sites before they load** | Every navigation is analysed *before* the request leaves the browser. Dangerous URLs are replaced by a warning page ("Go back to safety" / "Continue anyway"). |
| **Checks every link on the page** | Links are outlined in red (dangerous) or orange (suspicious), with the reasons in the tooltip. Clicking a dangerous link opens the warning page. Works on dynamic pages such as webmail. |
| **Catches lying links** | A link whose text says `www.paypal.com` but that opens another site. |
| **Detects brand impersonation** | Pages that present themselves as PayPal, Microsoft, Poste Italiane… and ask for a password or card data, but are not hosted on that brand's domains. |
| **Warns on dangerous pages** | A banner (isolated in a closed Shadow DOM) and a badge on the toolbar icon. |
| **Threat feeds** | OpenPhish and URLhaus lists, downloaded every 6 hours and matched locally. |

## Detection techniques

**Domain analysis**
- **Registrable domain (eTLD+1)** via a compact Public Suffix List: `login.amazon.co.uk` → `amazon`, `paypal-login.netlify.app` → `paypal-login`.
- **IDN homographs**: Punycode decoding (RFC 3492), mixed-script detection and Unicode "skeletons" inspired by Unicode TR39 (`xn--80ak6aa92e.com` → `аррӏе.com`, Cyrillic letters imitating *apple*).
- **Typosquatting** with Optimal String Alignment distance (Levenshtein + adjacent transpositions) and a threshold relative to the brand length, plus look-alike substitutions (`paypa1`, `rnicrosoft`, `amaz0n`).
- **Combosquatting** (`paypal-secure-login`, `poste-italiane-verifica`) and **brand in subdomain** (`paypal.com.account-verify.xyz`).

**URL analysis**
- Unwraps link wrappers (Google redirect, Outlook Safe Links, Proofpoint URL Defense, Facebook, LinkedIn…) and analyses the real destination.
- `user@host` tricks, raw IPs, `data:` URLs, double extensions (`invoice.pdf.exe`), executables, risky and file-like TLDs (`.zip`, `.mov`), free hosting and tunnels, IPFS, random-looking domains, open redirects, phishing vocabulary (English and Italian).

**Page analysis**
- Passwords over HTTP, login/payment forms posting to another domain or to `mailto:`.
- Brand impersonation (title, site name, headings, logos) and pages cloned from a brand's own servers.
- HTML attachments opened from disk (`file://`) that ask for credentials.

Each signal adds points; **3–6 = suspicious**, **≥ 7 = dangerous**. Brand checks never run on the brand's official domains, and users can mark sites as trusted.

## Install

### From source (development)

```bash
npm install        # installs web-ext (Mozilla's extension tool)
npm run build      # creates dist/chrome and dist/firefox
```

- **Chrome / Edge**: `chrome://extensions` → enable *Developer mode* → *Load unpacked* → select `dist/chrome`.
  To analyse local HTML files, enable *Allow access to file URLs* in the extension details.
- **Firefox**: `about:debugging` → *This Firefox* → *Load Temporary Add-on* → select `dist/firefox/manifest.json`.
  If needed, grant access to all websites in `about:addons` → BaitBlocker → *Permissions*.

### Packages

```bash
npm run package    # packages/baitblocker-chrome-<version>.zip and baitblocker-firefox-<version>.zip
```

## Development

```bash
npm test           # unit tests (Node's built-in test runner, no browser needed)
npm run lint       # Mozilla's web-ext lint on the Firefox build
```

### Project structure

```
src/
├── background.js        navigation guard, per-tab verdicts, badge, feed updates
├── content.js           page facts, link scanner, click guard, banner trigger
├── banner.js            in-page warning banner (closed Shadow DOM)
├── content.css          link highlighting
├── lib/
│   ├── api.js           chrome/browser compatibility
│   ├── psl.js           registrable domain (compact Public Suffix List)
│   ├── punycode.js      RFC 3492 decoder
│   ├── confusables.js   homoglyph skeletons, script detection
│   ├── distance.js      OSA distance, relative thresholds
│   ├── brands.js        protected brands and their official domains
│   ├── domain-analyzer.js
│   ├── url-analyzer.js
│   ├── link-analyzer.js
│   ├── page-analyzer.js
│   ├── blocklist.js     OpenPhish / URLhaus, matched locally
│   └── settings.js
├── popup/               verdict, settings, trusted sites, feed status
└── warning/             full-page warning
manifests/               chrome.json, firefox.json
tests/                   unit tests for every analyzer
build.mjs                copies src/ + the right manifest into dist/<browser>
```

The analyzers are **pure functions** (strings and plain objects in, findings out). The code that touches the DOM only collects facts, so all the detection logic is tested in Node.

## Privacy

- No analytics, no remote analysis: URLs and page contents never leave the browser.
- The only network requests made by the extension are the downloads of the public threat feeds.

## Limitations

- Heuristics can produce false positives (e.g. brand names that are also common words, such as *Apple* or *Chase*) and miss well-made phishing on clean domains. Use *Trust this site* for the first case; the threat feeds help with the second.
- A malicious page can remove the in-page banner; the toolbar badge and the navigation guard cannot be reached by page scripts.
- The brand list and the Public Suffix List are compact by design and should be extended over time.

## Roadmap

- Sender analysis inside webmail (display name vs. address).
- Full Public Suffix List and a larger brand list.
- Localisation (Italian / English UI).
- Optional domain-age lookup.

## Credits

- Threat data: [OpenPhish](https://openphish.com/) community feed and [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch.
- Homoglyph handling inspired by [Unicode Technical Standard #39](https://www.unicode.org/reports/tr39/).
- Public suffixes from the [Public Suffix List](https://publicsuffix.org/).

## License

[CC0 1.0 Universal](LICENSE) — dedicated to the public domain.
