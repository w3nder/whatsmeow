// Content script (isolated world): polls the bridge via the background, and relays signing requests
// to the page-world signer (inject.js) over window.postMessage. The poll loop lives here (not in the
// service worker) so it survives — the tab stays open while the worker may sleep between fetches.
(function () {
  "use strict";
  var BASE = "http://127.0.0.1:7799";

  var inject = document.createElement("script");
  inject.src = chrome.runtime.getURL("inject.js");
  inject.onload = function () { inject.remove(); };
  (document.documentElement || document.head).appendChild(inject);

  var pending = {};
  window.addEventListener("message", function (ev) {
    var d = ev.data;
    if (!d || d.__pkbridge !== "res") return;
    var cb = pending[d.id];
    if (cb) { delete pending[d.id]; cb(d); }
  });

  function signInPage(id, options) {
    return new Promise(function (resolve) {
      pending[id] = resolve;
      window.postMessage({ __pkbridge: "req", id: id, options: options }, "*");
    });
  }

  function bgFetch(method, url, body) {
    return chrome.runtime.sendMessage({ type: "pkbridge-fetch", method: method, url: url, body: body });
  }

  async function tick() {
    try {
      var r = await bgFetch("GET", BASE + "/pending");
      if (r && r.status === 200 && r.text) {
        var job = JSON.parse(r.text);
        var res = await signInPage(job.id, job.options);
        var body = res.error
          ? { id: job.id, error: res.error }
          : { id: job.id, assertion_json: res.assertion_json, credential_id: res.credential_id };
        await bgFetch("POST", BASE + "/assertion", JSON.stringify(body));
      }
    } catch (e) { /* bridge not reachable yet */ }
    setTimeout(tick, 1500);
  }
  tick();
  console.log("[passkey-bridge] extensão ativa, escutando " + BASE);
})();
