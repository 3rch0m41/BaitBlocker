(async () => {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });

  if (!tab || !/^(https?|file):/.test(tab.url || "")) {
    renderResults(0, ["Cannot scan internal browser pages."]);
    return;
  }

  try {
    const response = await api.tabs.sendMessage(tab.id, { action: "analyze_page" });
    if (!response) throw new Error("empty response");
    renderResults(response.score, response.reasons);
  } catch (e) {
    renderResults(0, ["Content script not responding. Try reloading the page."]);
  }
})();

function renderResults(score, reasons) {
  const statusDiv = document.getElementById('status');
  const list = document.getElementById('results-list');
  list.innerHTML = "";

  if (reasons.length === 0) {
    statusDiv.innerText = "Looks Secure";
    statusDiv.className = "status-box safe";
    list.innerHTML = "<li>No immediate phishing heuristics triggered. Remain cautious.</li>";
    return;
  }

  if (score >= 3) {
    statusDiv.innerText = "High Risk / Danger";
    statusDiv.className = "status-box danger";
  } else {
    statusDiv.innerText = "Suspicious Activity";
    statusDiv.className = "status-box warning";
  }

  reasons.forEach(reason => {
    const li = document.createElement('li');
    li.innerText = reason;
    list.appendChild(li);
  });
}