// Service worker: quick automatic check (URL model + reputation, no live fetch)
// on every page load, shown as a coloured badge on the extension icon.
importScripts("shared.js");

const cache = new Map(); // url -> result (cleared when the service worker sleeps)
const MAX_CACHE = 300;

async function setBadge(tabId, level) {
  const b = BADGE[level] || BADGE.error;
  await chrome.action.setBadgeText({ tabId, text: b.text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function autoCheck(tabId, url) {
  const settings = await getSettings();
  if (!settings.autoCheck || !isCheckable(url, settings.backend)) {
    await chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  let result = cache.get(url);
  if (!result) {
    try {
      result = await checkUrl(url);
    } catch {
      await setBadge(tabId, "error"); // backend not running
      return;
    }
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(url, result);
    if (settings.notify && result.status.level === "danger") {
      chrome.notifications.create(`tl-${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "ThreatLens warning",
        message: `${result.status.headline}\n${new URL(url).hostname}`,
        priority: 2,
      });
    }
  }
  await setBadge(tabId, result.status.level);
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url) autoCheck(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab.url) autoCheck(tabId, tab.url);
});
