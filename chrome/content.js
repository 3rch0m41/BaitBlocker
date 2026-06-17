chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_page") {
    sendResponse(analyzeHeuristics());
  }
  return true;
});

// High-value targets commonly used in Typosquatting/Phishing variations
const TARGET_BRANDS = ["google", "paypal", "amazon", "netflix", "apple", "microsoft", "facebook", "chase", "bankofamerica"];

// Pure JavaScript implementation of Levenshtein Distance matrix calculation
function getLevenshteinDistance(a, b) {
  const tmp = [];
  for (let i = 0; i <= a.length; i++) { tmp[i] = [i]; }
  for (let j = 0; j <= b.length; j++) { tmp[0][j] = j; }
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[a.length][b.length];
}

function analyzeHeuristics() {
  let score = 0;
  let reasons = [];
  const hostname = window.location.hostname.toLowerCase();

  // --- 1. IDN Homograph Attack (Punycode tracking) ---
  const domainParts = hostname.split('.');
  const isPunycode = domainParts.some(part => part.startsWith('xn--'));

  if (isPunycode) {
    score += 4;
    reasons.push("Warning: Uses an Internationalized Domain Name (Punycode 'xn--'). This is often used to spoof trusted brands via lookalike characters.");
  }

  // --- 2. Levenshtein Distance (Typosquatting tracking) ---
  if (domainParts.length >= 2) {
    // Extract the main domain token (e.g. "paypa1" out of "login.paypa1.com")
    const mainDomain = domainParts[domainParts.length - 2];
    
    for (const brand of TARGET_BRANDS) {
      if (mainDomain === brand) continue; // Matches exactly; legitimate asset domain

      const distance = getLevenshteinDistance(mainDomain, brand);
      // Catch domains with a character substitution, deletion, or insertion (e.g. "amzon", "paypa1")
      if (distance > 0 && distance <= 2) {
        score += 3;
        reasons.push(`Potential Typosquatting: The domain name closely resembles the protected brand trademark "${brand}".`);
        break;
      }
    }
  }

  // --- 3. Check for raw IP address domains ---
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 3;
    reasons.push("Uses an insecure raw IP address instead of an authenticated domain registry.");
  }

  // --- 4. Form and Encryption analysis ---
  if (window.location.protocol !== "https:") {
    if (document.querySelector('input[type="password"]')) {
      score += 3;
      reasons.push("Critical: Sending login credentials over an unencrypted (HTTP) link.");
    } else {
      score += 1;
      reasons.push("Website security warning: Connection does not offer HTTPS certificate protection.");
    }
  }

  // --- 5. Misdirected Form Targets ---
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action && action.startsWith('http')) {
      try {
        if (new URL(action).hostname !== hostname) {
          score += 2;
          reasons.push("Contains an active document form submitting client data off-site to a different external domain.");
        }
      } catch(e){}
    }
  });

  return { score, reasons };
}