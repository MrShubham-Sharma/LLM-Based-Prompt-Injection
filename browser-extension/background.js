/**
 * SecureLLM Background Service Worker
 * Routes screening requests from content scripts to the local Flask API.
 */

const FLASK_API = "http://127.0.0.1:5000/api/screen";

// Receive screening request from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCREEN_PROMPT") {
    screenPrompt(message.prompt, message.threshold || 0.5)
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true; // keep channel open for async response
  }

  if (message.type === "GET_STATS") {
    chrome.storage.local.get(["securellm_stats"], data => {
      sendResponse(data.securellm_stats || { total: 0, flagged: 0, blocked: 0 });
    });
    return true;
  }

  if (message.type === "RESET_STATS") {
    chrome.storage.local.set({ securellm_stats: { total: 0, flagged: 0, blocked: 0 } });
    sendResponse({ ok: true });
    return true;
  }
});

async function screenPrompt(prompt, threshold) {
  const response = await fetch(FLASK_API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, intent_threshold: threshold })
  });

  if (!response.ok) {
    throw new Error(`Flask API returned ${response.status}`);
  }

  const result = await response.json();

  // Update session stats in storage
  chrome.storage.local.get(["securellm_stats"], data => {
    const stats = data.securellm_stats || { total: 0, flagged: 0, blocked: 0 };
    stats.total += 1;
    if (!result.allowed) stats.blocked += 1;
    else if (result.findings && result.findings.length > 0) stats.flagged += 1;
    chrome.storage.local.set({ securellm_stats: stats });
  });

  return result;
}
