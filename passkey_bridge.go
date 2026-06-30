// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BrowserPasskeyAuthenticator implements PasskeyAuthenticator by delegating the WebAuthn ceremony to
// a real browser: the assertion is signed by the passkey already stored in the browser/OS, so no
// private key is ever extracted. It exposes a small HTTP API that a script running on web.whatsapp.com
// polls (see BrowserBridgeScript).
type BrowserPasskeyAuthenticator struct {
	// Timeout bounds how long GetAssertion waits for the browser. Defaults to 2 minutes.
	Timeout time.Duration

	mu      sync.Mutex
	queue   []*pendingPasskeyJob
	counter uint64
}

type pendingPasskeyJob struct {
	id      string
	options []byte
	fetched bool
	result  chan passkeyBridgeResult
}

type passkeyBridgeResult struct {
	assertion *PasskeyAssertion
	err       error
}

// NewBrowserPasskeyAuthenticator creates a bridge authenticator. Serve its Handler (or call
// ListenAndServe) and load BrowserBridgeScript in a logged-in web.whatsapp.com tab.
func NewBrowserPasskeyAuthenticator() *BrowserPasskeyAuthenticator {
	return &BrowserPasskeyAuthenticator{}
}

// GetAssertion implements PasskeyAuthenticator. It hands the request options to the browser and
// blocks until the browser returns a signed assertion (or the context/timeout expires).
func (b *BrowserPasskeyAuthenticator) GetAssertion(ctx context.Context, requestOptions []byte) (*PasskeyAssertion, error) {
	job := &pendingPasskeyJob{
		id:      fmt.Sprintf("job-%d", atomic.AddUint64(&b.counter, 1)),
		options: requestOptions,
		result:  make(chan passkeyBridgeResult, 1),
	}
	b.mu.Lock()
	b.queue = append(b.queue, job)
	b.mu.Unlock()
	defer b.remove(job.id)

	timeout := b.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-job.result:
		return res.assertion, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("timed out waiting for the browser to sign the passkey assertion")
	}
}

func (b *BrowserPasskeyAuthenticator) remove(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, job := range b.queue {
		if job.id == id {
			b.queue = append(b.queue[:i], b.queue[i+1:]...)
			return
		}
	}
}

// Handler returns the HTTP handler exposing /pending (GET) and /assertion (POST). Mount it anywhere,
// or use ListenAndServe.
func (b *BrowserPasskeyAuthenticator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/pending", b.handlePending)
	mux.HandleFunc("/assertion", b.handleAssertion)
	return mux
}

// ListenAndServe serves the bridge HTTP API on the given address (e.g. "127.0.0.1:7799").
func (b *BrowserPasskeyAuthenticator) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, b.Handler())
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func (b *BrowserPasskeyAuthenticator) handlePending(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		return
	}
	b.mu.Lock()
	var job *pendingPasskeyJob
	for _, j := range b.queue {
		if !j.fetched {
			j.fetched = true
			job = j
			break
		}
	}
	b.mu.Unlock()

	if job == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":      job.id,
		"options": string(job.options),
	})
}

func (b *BrowserPasskeyAuthenticator) handleAssertion(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		return
	}
	var body struct {
		ID           string `json:"id"`
		Assertion    string `json:"assertion_json"`
		CredentialID string `json:"credential_id"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	var job *pendingPasskeyJob
	for _, j := range b.queue {
		if j.id == body.ID {
			job = j
			break
		}
	}
	b.mu.Unlock()
	if job == nil {
		http.Error(w, "unknown job", http.StatusNotFound)
		return
	}

	if body.Error != "" {
		job.result <- passkeyBridgeResult{err: fmt.Errorf("browser passkey error: %s", body.Error)}
		w.WriteHeader(http.StatusOK)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body.CredentialID, "="))
	if err != nil {
		http.Error(w, "invalid credential_id", http.StatusBadRequest)
		return
	}
	job.result <- passkeyBridgeResult{assertion: &PasskeyAssertion{
		CredentialID:  credID,
		AssertionJSON: []byte(body.Assertion),
	}}
	w.WriteHeader(http.StatusOK)
}

// BrowserBridgeScript returns the JavaScript to paste in the console of a logged-in web.whatsapp.com
// tab (or wrap in a userscript). baseURL is where the bridge HTTP API is reachable, e.g.
// "http://127.0.0.1:7799".
func BrowserBridgeScript(baseURL string) string {
	return strings.ReplaceAll(browserBridgeScriptTemplate, "__BASE_URL__", baseURL)
}

const browserBridgeScriptTemplate = `(() => {
  const BASE = "__BASE_URL__";
  const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const fromB64url = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); const pad = s.length % 4 ? "=".repeat(4 - s.length % 4) : ""; const bin = atob(s + pad); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
  async function tick() {
    try {
      const r = await fetch(BASE + "/pending");
      if (r.status === 200) {
        const job = await r.json();
        const opts = JSON.parse(job.options);
        if (opts.challenge) opts.challenge = fromB64url(opts.challenge);
        if (Array.isArray(opts.allowCredentials)) opts.allowCredentials.forEach((c) => { if (c.id) c.id = fromB64url(c.id); });
        try {
          const cred = await navigator.credentials.get({ publicKey: opts });
          const assertion = {
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
          await fetch(BASE + "/assertion", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: job.id, assertion_json: JSON.stringify(assertion), credential_id: b64url(cred.rawId) }) });
        } catch (e) {
          await fetch(BASE + "/assertion", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: job.id, error: String(e) }) });
        }
      }
    } catch (e) { /* bridge not reachable yet */ }
    setTimeout(tick, 1500);
  }
  tick();
  console.log("[passkey-bridge] ativo, escutando " + BASE);
})();`
