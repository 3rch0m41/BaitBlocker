api.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_page") {
    sendResponse(analyzeHeuristics());
  }
  return true;
});