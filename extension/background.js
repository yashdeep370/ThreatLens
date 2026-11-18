// Service worker: quick automatic check (URL model + reputation, no live fetch)
// as soon as a page starts loading. Shows a coloured badge, and for dangerous
// URLs redirects the tab to the warning page before the user can interact.
importScripts("shared.js");

const cache = new Map(); // url -> result (cleared when the service worker sleeps)
const MAX_CACHE = 300;
const WARNING_PAGE = chrome.runtime.getURL("warning.html");

async function setBadge(tabId, level) {
  const b = BADGE[level] || BADGE.error;
  await chrome.action.setBadgeText({ tabId, text: b.text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function isAllowed(url) {
  const { allowed = [] } = await chrome.storage.session.get("allowed");
  return allowed.includes(new URL(url).hostname);
}

// navigation=true: a page load (always checked by the backend and logged on the
// browsing dashboard). navigation=false: a tab switch (cached result, not logged).
async function autoCheck(tabId, url, navigation) {
  const settings = await getSettings();
  if (url.startsWith(WARNING_PAGE)) {
    await setBadge(tabId, "danger");
    return;
  }
  if (!settings.autoCheck || !isCheckable(url, settings.backend)) {
    await chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  let result = navigation ? null : cache.get(url);
  if (!result) {
    try {
      result = await checkUrl(url, navigation ? { source: "extension", block: settings.block } : {});
    } catch {
      await setBadge(tabId, "error"); // backend not running
      return;
    }
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(url, result);
  }
  await setBadge(tabId, result.status.level);

  if (result.status.level !== "danger" || (await isAllowed(url))) return;
  if (settings.block) {
    await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?url=${encodeURIComponent(url)}` });
  } else if (settings.notify) {
    chrome.notifications.create(`tl-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "ThreatLens warning",
      message: `${result.status.headline}\n${new URL(url).hostname}`,
      priority: 2,
    });
  }
}

// "loading" fires as soon as navigation starts, so the warning replaces the page early.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "loading" && (info.url || tab.url)) autoCheck(tabId, info.url || tab.url, true);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab.url) autoCheck(tabId, tab.url, false);
});
