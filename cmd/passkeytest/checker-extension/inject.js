// Page-world: runs navigator.credentials.get on the whatsapp.com origin (the only place it's allowed)
// and reports the chosen credential back to the content script. The challenge is a dummy — this only
// checks whether a passkey exists and where it lives; it does not log in.
(function () {
  function b64url(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  window.addEventListener("message", function (ev) {
    var d = ev.data;
    if (!d || d.__pkcheck !== "run") return;
    (async function () {
      try {
        var cred = await navigator.credentials.get({
          publicKey: {
            challenge: new Uint8Array(32),
            rpId: "whatsapp.com",
            userVerification: "preferred",
            timeout: 60000,
          },
        });
        window.postMessage({
          __pkcheck: "result",
          ok: true,
          id: cred.id,
          type: cred.type,
          attachment: cred.authenticatorAttachment || "desconhecido",
        }, "*");
      } catch (e) {
        window.postMessage({ __pkcheck: "result", ok: false, name: e.name || "Error", message: String(e.message || e) }, "*");
      }
    })();
  });
})();
