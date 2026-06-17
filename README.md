# BaitBlocker

Lightweight Browser phishing detector using local heuristics, Levenshtein distance, and IDN tracking.

## How to install it
- For Chrome: 
  1. Open Chrome
  2. Go to <code>chrome://extension</code>
  3. Enable Developer Mode
  4. Click "Load Unpacked"
  5. Select the folder where you downloaded the extension and inside it go for "chrome" folder

- For Firefox: 
  1. Open Mozzilla Firefox
  2. Go to <code>about:debugging</code>
  3. Click on "This Firefox"
  4. Click on "Load Temporary Add-on.."

## Functionalities

This extension developed to work with both Google Chrome and Mozzilla Firefox, performs a sequence of checks to determine if a website is potentially a phishing or not. 

Bait Blocker checks: 

- If it use a raw IP addresses
- Misdirected Form Targets
- Form and Encryption Analisys
- IDN Homogrpahs
- Calculate the Levenshtein distance for the Typosquatting tracking on most famous websites
  
It includes a banner that warns the user of whether a website is a potential or not phishing. 

## Future Developments

Bait Blocker could be improved adding: 

- Add icons
- Domain Age Checking through API
- BlackList checks
- Google Safe Browsing API
- SSL certification checks
- Maching learning scoring
- Real-time phishing database update
- https://github.com/ilianAZZ/young-domain-guard/blob/main/build/js/background.js
