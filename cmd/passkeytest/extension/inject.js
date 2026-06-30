// Page-world WebAuthn helper. Runs on the whatsapp.com origin (the only place navigator.credentials
// works with rpId "whatsapp.com"). Handles two requests from the content script:
//   __pk:"sign"  -> real assertion for the whatsmeow bridge (uses the server's request options)
//   __pk:"check" -> dummy assertion just to detect if a passkey exists and where it lives
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
    if (!d || d.__pk == null) return;

    if (d.__pk === "sign") {
      (async function () {
        try {
          var opts = JSON.parse(d.options);
          if (opts.challenge) opts.challenge = fromB64url(opts.challenge);
          if (Array.isArray(opts.allowCredentials)) opts.allowCredentials.forEach(function (c) { if (c.id) c.id = fromB64url(c.id); });
          var cred = await navigator.credentials.get({ publicKey: opts });
          var assertion = {
            id: cred.id, rawId: b64url(cred.rawId), type: cred.type,
            response: {
              clientDataJSON: b64url(cred.response.clientDataJSON),
              authenticatorData: b64url(cred.response.authenticatorData),
              signature: b64url(cred.response.signature),
              userHandle: cred.response.userHandle ? b64url(cred.response.userHandle) : null,
            },
          };
          window.postMessage({ __pk: "sign-res", id: d.id, assertion_json: JSON.stringify(assertion), credential_id: b64url(cred.rawId) }, "*");
        } catch (e) {
          window.postMessage({ __pk: "sign-res", id: d.id, error: String(e) }, "*");
        }
      })();
    } else if (d.__pk === "check") {
      (async function () {
        try {
          var cred = await navigator.credentials.get({
            publicKey: { challenge: new Uint8Array(32), rpId: "whatsapp.com", userVerification: "preferred", timeout: 60000 },
          });
          window.postMessage({ __pk: "check-res", ok: true, id: cred.id, type: cred.type, attachment: cred.authenticatorAttachment || "desconhecido" }, "*");
        } catch (e) {
          window.postMessage({ __pk: "check-res", ok: false, name: e.name || "Error", message: String(e.message || e) }, "*");
        }
      })();
    }
  });
})();
