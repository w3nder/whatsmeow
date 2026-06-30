// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	defaultPasskeyRPID   = "whatsapp.com"
	defaultPasskeyOrigin = "https://web.whatsapp.com"

	webauthnFlagUserPresent  = 0x01
	webauthnFlagUserVerified = 0x04
	webauthnFlagAttestedData = 0x40
)

// VirtualAuthenticator is a self-contained software WebAuthn authenticator that implements
// PasskeyAuthenticator. It holds an ES256 (P-256) credential and produces assertions in Go,
// so no browser or external authenticator is needed for the assertion ceremony.
//
// The credential must still be registered on the WhatsApp account (the server stores the public
// key); reuse the same VirtualAuthenticator for registration and linking, or import an exported one.
type VirtualAuthenticator struct {
	privateKey   *ecdsa.PrivateKey
	CredentialID []byte
	UserHandle   []byte
	RPID         string
	Origin       string
	signCount    uint32

	// ParseRequestOptions extracts the WebAuthn challenge from the opaque passkey_request_options
	// blob. The blob's serialization is not yet reverse-engineered; the default treats the whole
	// blob as the raw challenge. Override after capturing the real format.
	ParseRequestOptions func(requestOptions []byte) (challenge []byte, err error)
}

// NewVirtualAuthenticator generates a fresh ES256 credential with a random credential ID.
func NewVirtualAuthenticator() (*VirtualAuthenticator, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	credID := make([]byte, 32)
	if _, err = rand.Read(credID); err != nil {
		return nil, err
	}
	return &VirtualAuthenticator{
		privateKey:   priv,
		CredentialID: credID,
		RPID:         defaultPasskeyRPID,
		Origin:       defaultPasskeyOrigin,
	}, nil
}

// GetAssertion implements PasskeyAuthenticator. The passkey_request_options blob is a JSON
// PublicKeyCredentialRequestOptions (challenge and allowCredentials IDs are base64url).
func (va *VirtualAuthenticator) GetAssertion(ctx context.Context, requestOptions []byte) (*PasskeyAssertion, error) {
	if va.ParseRequestOptions != nil {
		challenge, err := va.ParseRequestOptions(requestOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to parse request options: %w", err)
		}
		return va.SignAssertion(challenge)
	}
	challenge, rpID, allowCredentials, err := parseWebAuthnRequestOptions(requestOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request options: %w", err)
	}
	if rpID != "" {
		va.RPID = rpID
	}
	credentialID := va.CredentialID
	if len(allowCredentials) > 0 {
		credentialID = pickCredential(allowCredentials, va.CredentialID)
	}
	return va.signAssertion(challenge, credentialID)
}

func parseWebAuthnRequestOptions(blob []byte) (challenge []byte, rpID string, allowCredentials [][]byte, err error) {
	var opts struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err = json.Unmarshal(blob, &opts); err != nil {
		return nil, "", nil, fmt.Errorf("request options is not JSON: %w", err)
	}
	challenge, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(opts.Challenge, "="))
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid base64url challenge: %w", err)
	}
	for _, cred := range opts.AllowCredentials {
		id, decErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(cred.ID, "="))
		if decErr == nil && len(id) > 0 {
			allowCredentials = append(allowCredentials, id)
		}
	}
	return challenge, opts.RPID, allowCredentials, nil
}

// pickCredential returns the credential the server expects: the authenticator's own ID if the server
// allows it, otherwise the first allowed credential (a single-credential authenticator is that one).
func pickCredential(allowed [][]byte, own []byte) []byte {
	for _, id := range allowed {
		if bytes.Equal(id, own) {
			return own
		}
	}
	return allowed[0]
}

// SignAssertion runs the WebAuthn assertion ceremony over the given challenge.
func (va *VirtualAuthenticator) SignAssertion(challenge []byte) (*PasskeyAssertion, error) {
	return va.signAssertion(challenge, va.CredentialID)
}

func (va *VirtualAuthenticator) signAssertion(challenge, credentialID []byte) (*PasskeyAssertion, error) {
	rpID := va.RPID
	if rpID == "" {
		rpID = defaultPasskeyRPID
	}
	origin := va.Origin
	if origin == "" {
		origin = defaultPasskeyOrigin
	}

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}

	va.signCount++
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, webauthnFlagUserPresent|webauthnFlagUserVerified)
	authData = binary.BigEndian.AppendUint32(authData, va.signCount)

	clientDataHash := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, va.privateKey, signed[:])
	if err != nil {
		return nil, err
	}

	b64 := base64.RawURLEncoding.EncodeToString
	var userHandle any
	if len(va.UserHandle) > 0 {
		userHandle = b64(va.UserHandle)
	}
	assertionJSON, err := json.Marshal(map[string]any{
		"id":    b64(credentialID),
		"rawId": b64(credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        userHandle,
		},
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyAssertion{CredentialID: credentialID, AssertionJSON: assertionJSON}, nil
}

// PublicKey returns the credential's P-256 public key, for registering it on the account.
func (va *VirtualAuthenticator) PublicKey() *ecdsa.PublicKey {
	return &va.privateKey.PublicKey
}

// MakeCredential runs the WebAuthn registration ceremony (navigator.credentials.create) and returns
// the standard PublicKeyCredential JSON (clientDataJSON + attestationObject, "none" attestation).
// Feed this into the WhatsApp passkey enrollment flow so the server stores this credential's public
// key; afterwards GetAssertion on the same VirtualAuthenticator will satisfy the prologue.
func (va *VirtualAuthenticator) MakeCredential(challenge, userID []byte, userName string) ([]byte, error) {
	rpID := va.RPID
	if rpID == "" {
		rpID = defaultPasskeyRPID
	}
	origin := va.Origin
	if origin == "" {
		origin = defaultPasskeyOrigin
	}
	va.UserHandle = userID

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}

	cose := va.coseKey()
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37+16+2+len(va.CredentialID)+len(cose))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, webauthnFlagUserPresent|webauthnFlagUserVerified|webauthnFlagAttestedData)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID (zeroes)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(va.CredentialID)))
	authData = append(authData, va.CredentialID...)
	authData = append(authData, cose...)

	var attObj []byte
	attObj = append(attObj, cborMapHead(3)...)
	attObj = append(attObj, cborText("fmt")...)
	attObj = append(attObj, cborText("none")...)
	attObj = append(attObj, cborText("attStmt")...)
	attObj = append(attObj, cborMapHead(0)...)
	attObj = append(attObj, cborText("authData")...)
	attObj = append(attObj, cborBytes(authData)...)

	b64 := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id":    b64(va.CredentialID),
		"rawId": b64(va.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attObj),
		},
	})
}

// coseKey encodes the credential public key as a COSE_Key (ES256/P-256).
func (va *VirtualAuthenticator) coseKey() []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	va.privateKey.PublicKey.X.FillBytes(x)
	va.privateKey.PublicKey.Y.FillBytes(y)

	var out []byte
	out = append(out, cborMapHead(5)...)
	out = append(out, cborInt(1)...)  // kty
	out = append(out, cborInt(2)...)  // EC2
	out = append(out, cborInt(3)...)  // alg
	out = append(out, cborInt(-7)...) // ES256
	out = append(out, cborInt(-1)...) // crv
	out = append(out, cborInt(1)...)  // P-256
	out = append(out, cborInt(-2)...) // x
	out = append(out, cborBytes(x)...)
	out = append(out, cborInt(-3)...) // y
	out = append(out, cborBytes(y)...)
	return out
}

// Minimal deterministic CBOR encoder for the fixed registration structures (no external dependency).

func cborHead(major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n < 24:
		return []byte{mt | byte(n)}
	case n < 1<<8:
		return []byte{mt | 24, byte(n)}
	case n < 1<<16:
		return []byte{mt | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{mt | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborInt(i int) []byte {
	if i >= 0 {
		return cborHead(0, uint64(i))
	}
	return cborHead(1, uint64(-1-i))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

func cborText(s string) []byte { return append(cborHead(3, uint64(len(s))), s...) }

func cborMapHead(n int) []byte { return cborHead(5, uint64(n)) }

type exportedVirtualAuthenticator struct {
	PrivateKey   []byte `json:"private_key"`
	CredentialID []byte `json:"credential_id"`
	UserHandle   []byte `json:"user_handle,omitempty"`
	RPID         string `json:"rp_id"`
	Origin       string `json:"origin"`
	SignCount    uint32 `json:"sign_count"`
}

// Export serializes the authenticator (including its private key) so it can be persisted and reused.
func (va *VirtualAuthenticator) Export() ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(va.privateKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(exportedVirtualAuthenticator{
		PrivateKey:   pkcs8,
		CredentialID: va.CredentialID,
		UserHandle:   va.UserHandle,
		RPID:         va.RPID,
		Origin:       va.Origin,
		SignCount:    va.signCount,
	})
}

// ImportVirtualAuthenticator restores an authenticator previously serialized with Export.
func ImportVirtualAuthenticator(data []byte) (*VirtualAuthenticator, error) {
	var exp exportedVirtualAuthenticator
	if err := json.Unmarshal(data, &exp); err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(exp.PrivateKey)
	if err != nil {
		return nil, err
	}
	ecKey, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("exported private key is not ECDSA")
	}
	return &VirtualAuthenticator{
		privateKey:   ecKey,
		CredentialID: exp.CredentialID,
		UserHandle:   exp.UserHandle,
		RPID:         exp.RPID,
		Origin:       exp.Origin,
		signCount:    exp.SignCount,
	}, nil
}
