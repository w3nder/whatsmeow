// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package passkeyauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
)

func TestBrowserPasskeyAuthenticatorBridge(t *testing.T) {
	bridge := NewBrowserPasskeyAuthenticator()
	srv := httptest.NewServer(bridge.Handler())
	defer srv.Close()

	options := []byte(`{"challenge":"Y2hhbGxlbmdl","rpId":"whatsapp.com"}`)
	credID := []byte("the-credential-id")

	type result struct {
		assertion *whatsmeow.PasskeyAssertion
		err       error
	}
	done := make(chan result, 1)
	go func() {
		a, err := bridge.GetAssertion(context.Background(), options)
		done <- result{a, err}
	}()

	// Simulate the browser script: poll /pending, then POST /assertion.
	var job struct {
		ID      string `json:"id"`
		Options string `json:"options"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(srv.URL + "/pending")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&job)
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("no pending job appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job.Options != string(options) {
		t.Errorf("forwarded options = %q, want %q", job.Options, options)
	}

	post, _ := json.Marshal(map[string]string{
		"id":             job.ID,
		"assertion_json": `{"id":"x","type":"public-key"}`,
		"credential_id":  base64.RawURLEncoding.EncodeToString(credID),
	})
	resp, err := http.Post(srv.URL+"/assertion", "application/json", bytes.NewReader(post))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if !bytes.Equal(res.assertion.CredentialID, credID) {
			t.Errorf("credential ID = %q, want %q", res.assertion.CredentialID, credID)
		}
		if string(res.assertion.AssertionJSON) != `{"id":"x","type":"public-key"}` {
			t.Errorf("assertion JSON not forwarded: %s", res.assertion.AssertionJSON)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetAssertion did not return")
	}
}

func TestBrowserBridgeScriptContainsBaseURL(t *testing.T) {
	script := BrowserBridgeScript("http://127.0.0.1:7799")
	if !strings.Contains(script, "http://127.0.0.1:7799") {
		t.Error("script does not contain the base URL")
	}
	if strings.Contains(script, "__BASE_URL__") {
		t.Error("script still has unreplaced placeholder")
	}
}
