// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package passkeyauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func decodeAssertion(t *testing.T, assertionJSON []byte) (authData, clientData, sig []byte) {
	t.Helper()
	var parsed struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(assertionJSON, &parsed); err != nil {
		t.Fatalf("assertion is not valid JSON: %v", err)
	}
	dec := base64.RawURLEncoding.DecodeString
	authData, _ = dec(parsed.Response.AuthenticatorData)
	clientData, _ = dec(parsed.Response.ClientDataJSON)
	sig, _ = dec(parsed.Response.Signature)
	return authData, clientData, sig
}

func TestVirtualAuthenticatorAssertionVerifies(t *testing.T) {
	va, err := NewVirtualAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("a-server-challenge")

	// The real passkey_request_options blob is a JSON PublicKeyCredentialRequestOptions.
	options, _ := json.Marshal(map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"rpId":      "whatsapp.com",
	})
	assertion, err := va.GetAssertion(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}

	authData, clientData, sig := decodeAssertion(t, assertion.AssertionJSON)

	// The challenge inside clientDataJSON must equal the one from the JSON options.
	if !bytes.Contains(clientData, []byte(base64.RawURLEncoding.EncodeToString(challenge))) {
		t.Error("clientDataJSON does not contain the request challenge")
	}

	// The challenge must round-trip into clientDataJSON.
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err = json.Unmarshal(clientData, &cd); err != nil {
		t.Fatal(err)
	}
	if cd.Type != "webauthn.get" {
		t.Errorf("type = %q", cd.Type)
	}
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
		t.Errorf("challenge mismatch")
	}
	if cd.Origin != defaultPasskeyOrigin {
		t.Errorf("origin = %q", cd.Origin)
	}

	// The signature must verify against the credential public key (proves the ceremony is correct).
	clientDataHash := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	if !ecdsa.VerifyASN1(va.PublicKey(), signed[:], sig) {
		t.Fatal("assertion signature did not verify against the credential public key")
	}
}

func TestVirtualAuthenticatorUsesAllowCredentials(t *testing.T) {
	va, err := NewVirtualAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	serverCredID := []byte("server-assigned-credential-id-32")
	options, _ := json.Marshal(map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString([]byte("c")),
		"rpId":      "whatsapp.com",
		"allowCredentials": []map[string]any{
			{"type": "public-key", "id": base64.RawURLEncoding.EncodeToString(serverCredID)},
		},
	})
	assertion, err := va.GetAssertion(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(assertion.CredentialID, serverCredID) {
		t.Errorf("assertion should use the allowCredentials ID, got %q", assertion.CredentialID)
	}
	var parsed struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(assertion.AssertionJSON, &parsed)
	if parsed.ID != base64.RawURLEncoding.EncodeToString(serverCredID) {
		t.Error("assertion JSON id does not match allowCredentials ID")
	}
}

func TestVirtualAuthenticatorMakeCredential(t *testing.T) {
	va, err := NewVirtualAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("registration-challenge")

	credJSON, err := va.MakeCredential(challenge, []byte("user-id"), "user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	if err = json.Unmarshal(credJSON, &parsed); err != nil {
		t.Fatal(err)
	}

	clientData, _ := base64.RawURLEncoding.DecodeString(parsed.Response.ClientDataJSON)
	var cd struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(clientData, &cd)
	if cd.Type != "webauthn.create" {
		t.Errorf("clientData type = %q, want webauthn.create", cd.Type)
	}

	attObj, _ := base64.RawURLEncoding.DecodeString(parsed.Response.AttestationObject)
	if len(attObj) == 0 || attObj[0] != 0xA3 {
		t.Fatalf("attestationObject should start with CBOR map(3) 0xA3, got %x", attObj[:1])
	}
	if !bytes.Contains(attObj, va.CredentialID) {
		t.Error("attestationObject does not embed the credential ID")
	}
	// The COSE key must embed the real public key coordinates.
	x := make([]byte, 32)
	va.PublicKey().X.FillBytes(x)
	if !bytes.Contains(attObj, x) {
		t.Error("attestationObject does not embed the public key X coordinate")
	}
}

func TestVirtualAuthenticatorExportImport(t *testing.T) {
	va, err := NewVirtualAuthenticator()
	if err != nil {
		t.Fatal(err)
	}
	va.UserHandle = []byte("user-123")
	blob, err := va.Export()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ImportVirtualAuthenticator(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.CredentialID, va.CredentialID) {
		t.Error("credential ID changed across export/import")
	}
	if !restored.PublicKey().Equal(va.PublicKey()) {
		t.Error("public key changed across export/import")
	}
}
