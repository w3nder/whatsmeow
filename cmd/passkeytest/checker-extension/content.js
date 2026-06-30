// Content script: injects a floating button + result panel on web.whatsapp.com. Clicking it runs the
// WebAuthn check (in page world via inject.js) and shows whether a passkey exists and where it lives.
(function () {
  "use strict";

  var inject = document.createElement("script");
  inject.src = chrome.runtime.getURL("inject.js");
  inject.onload = function () { inject.remove(); };
  (document.documentElement || document.head).appendChild(inject);

  var btn = document.createElement("button");
  btn.textContent = "🔑 Verificar passkey";
  Object.assign(btn.style, {
    position: "fixed", bottom: "16px", right: "16px", zIndex: 999999,
    padding: "10px 14px", borderRadius: "8px", border: "none", cursor: "pointer",
    background: "#25D366", color: "#073127", fontWeight: "600", fontSize: "13px",
    boxShadow: "0 2px 8px rgba(0,0,0,.3)", fontFamily: "system-ui, sans-serif",
  });

  var panel = document.createElement("div");
  Object.assign(panel.style, {
    position: "fixed", bottom: "60px", right: "16px", zIndex: 999999,
    maxWidth: "320px", padding: "12px 14px", borderRadius: "10px",
    background: "#111b21", color: "#e9edef", fontSize: "13px", lineHeight: "1.45",
    boxShadow: "0 4px 16px rgba(0,0,0,.45)", fontFamily: "system-ui, sans-serif", display: "none",
    whiteSpace: "pre-wrap", wordBreak: "break-word",
  });

  function show(html) { panel.innerHTML = html; panel.style.display = "block"; }

  function describe(attachment) {
    if (attachment === "platform") return "🖥️ platform — está NESTE dispositivo (ex.: Touch ID do Mac). Não precisa do celular nem Bluetooth.";
    if (attachment === "cross-platform") return "📱 cross-platform — está em outro dispositivo (celular/chave). Precisa dele por perto (Bluetooth).";
    return "tipo de authenticator: " + attachment;
  }

  btn.addEventListener("click", function () {
    show("Abrindo o prompt do sistema… confirme com Touch ID, ou escolha o dispositivo.");
    window.postMessage({ __pkcheck: "run" }, "*");
  });

  window.addEventListener("message", function (ev) {
    var d = ev.data;
    if (!d || d.__pkcheck !== "result") return;
    if (d.ok) {
      show(
        "<b style='color:#25D366'>✅ Passkey encontrada</b>\n\n" +
        "Onde está:\n" + describe(d.attachment) + "\n\n" +
        "credential id:\n" + d.id + "\n\ntipo: " + d.type
      );
    } else if (d.name === "NotAllowedError") {
      show("<b style='color:#f15c6d'>❌ Nenhuma passkey usada</b>\n\nVocê cancelou, ou esta conta não tem passkey registrada. (" + d.name + ")");
    } else {
      show("<b style='color:#f15c6d'>⚠️ Erro</b>\n\n" + d.name + ": " + d.message);
    }
  });

  document.documentElement.appendChild(btn);
  document.documentElement.appendChild(panel);
  console.log("[passkey-checker] ativo no web.whatsapp.com");
})();
