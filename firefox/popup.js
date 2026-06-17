browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
  const activeTab = tabs[0];
  
  if (!activeTab.url || activeTab.url.startsWith("about:") || activeTab.url.startsWith("chrome://")) {
    renderResults(0, ["Cannot scan internal browser pages."]);
    return;
  }

  browser.tabs.sendMessage(activeTab.id, { action: "analyze_page" })
    .then((response) => {
      if (!response) {
        renderResults(0, ["Unable to extract analytical data. Try reloading the tab."]);
        return;
      }
      renderResults(response.score, response.reasons);
    })
    .catch((error) => {
      renderResults(0, ["Injected content script not responding. Try refreshing the page."]);
    });
});

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