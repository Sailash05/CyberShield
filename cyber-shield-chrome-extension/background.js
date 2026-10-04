const API_URL = "http://127.0.0.1:8000/api/legitimacy-analysis";
const CHECKER_PAGE = chrome.runtime.getURL("checker.html");

function isWebUrl(url) {
  return typeof url === "string" &&
    (url.startsWith("http://") || url.startsWith("https://"));
}

function allowKey(tabId, url) {
  return `allow-once:${tabId}:${url}`;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only inspect top-level navigations to ordinary web pages.
  if (details.frameId !== 0 || !isWebUrl(details.url)) return;

  const key = allowKey(details.tabId, details.url);

  try {
    const stored = await chrome.storage.session.get(key);

    // A safe result or explicit user choice permits this exact URL once.
    if (stored[key]) {
      await chrome.storage.session.remove(key);
      return;
    }

    // Redirect to the extension's local checker/warning page.
    const checkerUrl = `${CHECKER_PAGE}?url=${encodeURIComponent(details.url)}`;
    await chrome.tabs.update(details.tabId, { url: checkerUrl });
  } catch (error) {
    console.error("Cyber Shield navigation interception error:", error);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "CYBER_SHIELD_ALLOW_AND_OPEN") return;

  const tabId = sender.tab?.id;
  const targetUrl = message.url;

  if (typeof tabId !== "number" || !isWebUrl(targetUrl)) {
    sendResponse({ ok: false, error: "Invalid tab or URL." });
    return;
  }

  (async () => {
    try {
      await chrome.storage.session.set({
        [allowKey(tabId, targetUrl)]: true
      });
      await chrome.tabs.update(tabId, { url: targetUrl });
      sendResponse({ ok: true });
    } catch (error) {
      sendResponse({ ok: false, error: error.message });
    }
  })();

  return true;
});