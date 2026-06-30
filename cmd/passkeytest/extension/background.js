// Service worker: privileged fetch proxy to the local whatsmeow bridge. Background fetches are not
// subject to the page's CSP, so they can reach 127.0.0.1 (with host_permissions).
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || msg.type !== "pkbridge-fetch") return;
  fetch(msg.url, {
    method: msg.method,
    headers: { "Content-Type": "application/json" },
    body: msg.body || undefined,
  })
    .then(function (r) { return r.text().then(function (t) { sendResponse({ status: r.status, text: t }); }); })
    .catch(function (e) { sendResponse({ status: 0, error: String(e) }); });
  return true;
});
