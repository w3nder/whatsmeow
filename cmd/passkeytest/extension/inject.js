// Page-world signer: runs navigator.credentials.get with page-native buffers and replies to the
// content script over window.postMessage.
(function () {
  function b64url(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64url(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    var pad = s.length % 4 ? "=".repeat(4 - s.length % 4) : "";
    var bin = atob(s + pad);
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  window.addEventListener("message", function (ev) {
    var d = ev.data;
    if (!d || d.__pkbridge !== "req") return;
    (async function () {
      try {
        var opts = JSON.parse(d.options);
        if (opts.challenge) opts.challenge = fromB64url(opts.challenge);
        if (Array.isArray(opts.allowCredentials)) opts.allowCredentials.forEach(function (c) { if (c.id) c.id = fromB64url(c.id); });
        var cred = await navigator.credentials.get({ publicKey: opts });
        var assertion = {
          id: cred.id,
          rawId: b64url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: b64url(cred.response.clientDataJSON),
            authenticatorData: b64url(cred.response.authenticatorData),
            signature: b64url(cred.response.signature),
            userHandle: cred.response.userHandle ? b64url(cred.response.userHandle) : null,
          },
        };
        window.postMessage({ __pkbridge: "res", id: d.id, assertion_json: JSON.stringify(assertion), credential_id: b64url(cred.rawId) }, "*");
      } catch (e) {
        window.postMessage({ __pkbridge: "res", id: d.id, error: String(e) }, "*");
      }
    })();
  });
})();
