// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"go.mau.fi/util/random"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/gcmutil"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"go.mau.fi/whatsmeow/util/keys"
)

const (
	shortcakeNonceLength            = 32
	shortcakeVerificationCodeLength = 5
	shortcakeEncryptionKeyLength    = 32
	shortcakeGCMIVLength            = 12
	shortcakeEncryptionKeyInfo      = "Pairing Information Encryption Key"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// PasskeyAssertion is the result of the WebAuthn ceremony required by the Shortcake passkey prologue.
type PasskeyAssertion struct {
	CredentialID  []byte
	AssertionJSON []byte
}

// PasskeyAuthenticator supplies the WebAuthn assertion for the Shortcake passkey prologue.
// Implementations need a passkey registered under rpId "whatsapp.com" whose private key they control.
type PasskeyAuthenticator interface {
	GetAssertion(ctx context.Context, requestOptions []byte) (*PasskeyAssertion, error)
}

// PasskeyRegistrar produces a WebAuthn attestation (navigator.credentials.create) for registering a
// new passkey on the account. passkeyauth.VirtualAuthenticator implements it via MakeCredential.
type PasskeyRegistrar interface {
	MakeCredential(challenge, userID []byte, userName string) (attestationResponseJSON []byte, err error)
}

// RegisterPasskey attempts to register a software passkey on the account so the Shortcake prologue can
// be satisfied headlessly (no browser).
//
// SKELETON — NOT YET FUNCTIONAL. The WhatsApp passkey enrollment IQ format is not reverse-engineered
// (those modules are lazy-loaded and were absent from the captured web bundle). The tags below are
// placeholders. Run this on a passkey-rollout account with debug logging and share the logged stanzas
// (the [passkey-register] lines) so the real request/response format can be filled in. See #1185.
func (cli *Client) RegisterPasskey(ctx context.Context, registrar PasskeyRegistrar) error {
	// TODO(passkey-enrollment): confirm the request tag/namespace for fetching creation options.
	cli.Log.Infof("[passkey-register] requesting creation options (placeholder IQ — confirm format)")
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqGet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{{Tag: "passkey_creation_options"}},
	})
	if err != nil {
		cli.Log.Warnf("[passkey-register] creation options IQ failed (expected until format is known): %v", err)
		return fmt.Errorf("passkey enrollment not implemented yet: %w", err)
	}
	cli.Log.Infof("[passkey-register] creation options response:\n%s", resp.String())

	// TODO(passkey-enrollment): parse the real challenge / user.id / user.name from resp.
	var challenge, userID []byte
	var userName string
	if optsNode := resp.GetChildByTag("passkey_creation_options"); optsNode.Tag != "" {
		challenge, _ = optsNode.GetChildByTag("challenge").Content.([]byte)
	}

	attestation, err := registrar.MakeCredential(challenge, userID, userName)
	if err != nil {
		return fmt.Errorf("failed to build attestation: %w", err)
	}
	cli.Log.Infof("[passkey-register] attestation built (%d bytes); submitting (placeholder IQ — confirm format)", len(attestation))

	// TODO(passkey-enrollment): confirm the submit tag/structure (likely a protobuf, not raw JSON).
	subResp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqSet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{Tag: "passkey", Content: []waBinary.Node{
			{Tag: "attestation", Content: attestation},
		}}},
	})
	if err != nil {
		cli.Log.Warnf("[passkey-register] submit IQ failed (expected until format is known): %v", err)
		return fmt.Errorf("passkey enrollment submit failed: %w", err)
	}
	cli.Log.Infof("[passkey-register] submit response:\n%s", subResp.String())
	return nil
}

type shortcakeLinkingState struct {
	keypair        *keys.KeyPair
	companionNonce []byte
	ref            string
	deviceType     waCompanionReg.DeviceProps_PlatformType
}

func (cli *Client) handlePasskeyPrologueRequest(ctx context.Context, node *waBinary.Node) {
	// Verbose capture: dump the raw notification and the request options so the format can be
	// confirmed against real accounts. Share these logs to help debug the passkey flow (#1185).
	cli.Log.Infof("[passkey-debug] passkey_prologue_request received:\n%s", node.String())
	if opts, ok := node.GetChildByTag("passkey_request_options").Content.([]byte); ok {
		cli.Log.Infof("[passkey-debug] passkey_request_options (%d bytes): %s", len(opts), string(opts))
	}

	if cli.PasskeyAuthenticator == nil {
		cli.Log.Warnf("This account requires a passkey to link, but no PasskeyAuthenticator is set. " +
			"whatsmeow cannot create a passkey (the WhatsApp protocol has no enrollment); the assertion " +
			"can only run on the whatsapp.com origin. Open " + PasskeyHelpURL + " in a browser and link " +
			"there, or run with the passkey bridge. See tulir/whatsmeow#1185.")
		cli.dispatchEvent(&events.ShortcakePasskeyRequired{HelpURL: PasskeyHelpURL})
		return
	}
	if err := cli.completePasskeyPrologue(ctx, node); err != nil {
		cli.Log.Errorf("Failed to complete passkey prologue: %v", err)
		cli.dispatchEvent(&events.ShortcakePasskeyRequired{HelpURL: PasskeyHelpURL})
	}
}

// PasskeyHelpURL is shown to the user when an account requires a passkey that whatsmeow cannot
// satisfy headlessly. The assertion can only run on this origin.
const PasskeyHelpURL = "https://web.whatsapp.com"

func (cli *Client) completePasskeyPrologue(ctx context.Context, node *waBinary.Node) error {
	options, _ := node.GetChildByTag("passkey_request_options").Content.([]byte)
	if len(options) == 0 {
		var err error
		options, err = cli.getPasskeyRequestOptions(ctx)
		if err != nil {
			return fmt.Errorf("failed to get passkey request options: %w", err)
		}
	}

	assertion, err := cli.PasskeyAuthenticator.GetAssertion(ctx, options)
	if err != nil {
		return fmt.Errorf("webauthn assertion failed: %w", err)
	}

	ref, err := cli.getShortcakeRef(ctx)
	if err != nil {
		return fmt.Errorf("failed to get shortcake ref: %w", err)
	}

	prologuePayload, state, err := buildShortcakeProloguePayload(ref, waCompanionReg.DeviceProps_CHROME)
	if err != nil {
		return fmt.Errorf("failed to build prologue payload: %w", err)
	}
	cli.shortcakeLinking.Store(state)

	return cli.setPasskeyPrologue(ctx, assertion.CredentialID, assertion.AssertionJSON, prologuePayload, nil)
}

// buildShortcakeProloguePayload generates the companion ephemeral keypair and nonce, and builds the
// ProloguePayload (companion ephemeral identity + commitment hash). The commitment is
// SHA256(companionEphemeralIdentity || companionNonce).
func buildShortcakeProloguePayload(ref string, deviceType waCompanionReg.DeviceProps_PlatformType) ([]byte, *shortcakeLinkingState, error) {
	kp := keys.NewKeyPair()
	nonce := random.Bytes(shortcakeNonceLength)

	ephemeralIdentity, err := proto.Marshal(&waCompanionReg.CompanionEphemeralIdentity{
		PublicKey:  kp.Pub[:],
		DeviceType: &deviceType,
		Ref:        &ref,
	})
	if err != nil {
		return nil, nil, err
	}

	commitment := sha256.Sum256(append(append([]byte{}, ephemeralIdentity...), nonce...))

	payload, err := proto.Marshal(&waCompanionReg.ProloguePayload{
		CompanionEphemeralIdentity: ephemeralIdentity,
		Commitment:                 &waCompanionReg.CompanionCommitment{Hash: commitment[:]},
	})
	if err != nil {
		return nil, nil, err
	}

	state := &shortcakeLinkingState{keypair: kp, companionNonce: nonce, ref: ref, deviceType: deviceType}
	return payload, state, nil
}

func (cli *Client) handleShortcakeContinuation(ctx context.Context, node *waBinary.Node) {
	if err := cli.completeShortcakeContinuation(ctx, node); err != nil {
		cli.Log.Errorf("Failed to handle shortcake continuation: %v", err)
	}
}

func (cli *Client) completeShortcakeContinuation(ctx context.Context, node *waBinary.Node) error {
	state := cli.shortcakeLinking.Load()
	if state == nil {
		return fmt.Errorf("received crsc_continuation without prior passkey prologue state")
	}

	rawIdentity, ok := node.GetChildByTag("primary_ephemeral_identity").Content.([]byte)
	if !ok {
		return fmt.Errorf("crsc_continuation missing primary_ephemeral_identity")
	}
	var primary waCompanionReg.PrimaryEphemeralIdentity
	if err := proto.Unmarshal(rawIdentity, &primary); err != nil {
		return fmt.Errorf("failed to decode PrimaryEphemeralIdentity: %w", err)
	}
	if len(primary.GetPublicKey()) != 32 {
		return fmt.Errorf("PrimaryEphemeralIdentity.publicKey must be 32 bytes")
	}
	if len(primary.GetNonce()) != shortcakeNonceLength {
		return fmt.Errorf("PrimaryEphemeralIdentity.nonce must be %d bytes", shortcakeNonceLength)
	}

	if err := cli.sendCompanionNonce(ctx, state.companionNonce); err != nil {
		return fmt.Errorf("failed to send companion nonce: %w", err)
	}

	code := deriveShortcakeVerificationCode(state.companionNonce, primary.GetPublicKey(), primary.GetNonce())
	encryptionKey, err := deriveShortcakeEncryptionKey(state.keypair.Priv[:], primary.GetPublicKey(), state.deviceType, state.ref)
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %w", err)
	}

	cli.dispatchEvent(&events.ShortcakeVerificationCode{Code: code})

	encryptedPairingRequest, err := cli.buildEncryptedPairingRequest(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to build encrypted pairing request: %w", err)
	}
	return cli.sendEncryptedPairingRequest(ctx, encryptedPairingRequest)
}

// deriveShortcakeVerificationCode returns the human-comparable code shown on both devices:
// Crockford(primaryNonce[:5] XOR SHA256(companionNonce || primaryPublicKey)[:5]).
func deriveShortcakeVerificationCode(companionNonce, primaryPublicKey, primaryNonce []byte) string {
	digest := sha256.Sum256(append(append([]byte{}, companionNonce...), primaryPublicKey...))
	code := make([]byte, shortcakeVerificationCodeLength)
	for i := 0; i < shortcakeVerificationCodeLength; i++ {
		code[i] = primaryNonce[i] ^ digest[i]
	}
	return crockfordBase32(code)
}

// deriveShortcakeEncryptionKey runs ECDH and HKDF to derive the pairing information encryption key.
func deriveShortcakeEncryptionKey(companionPriv, primaryPub []byte, deviceType waCompanionReg.DeviceProps_PlatformType, ref string) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(companionPriv, primaryPub)
	if err != nil {
		return nil, err
	}
	salt := "Companion Pairing " + strconv.Itoa(int(deviceType)) + " with ref " + ref
	return hkdfutil.SHA256(sharedSecret, []byte(salt), []byte(shortcakeEncryptionKeyInfo), shortcakeEncryptionKeyLength), nil
}

func (cli *Client) buildEncryptedPairingRequest(encryptionKey []byte) ([]byte, error) {
	pairingRequest, err := proto.Marshal(&waCompanionReg.PairingRequest{
		CompanionPublicKey:   cli.Store.NoiseKey.Pub[:],
		CompanionIdentityKey: cli.Store.IdentityKey.Pub[:],
		AdvSecret:            cli.Store.AdvSecretKey,
	})
	if err != nil {
		return nil, err
	}
	iv := random.Bytes(shortcakeGCMIVLength)
	encryptedPayload, err := gcmutil.Encrypt(encryptionKey, iv, pairingRequest, nil)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(&waCompanionReg.EncryptedPairingRequest{
		EncryptedPayload: encryptedPayload,
		IV:               iv,
	})
}

func crockfordBase32(data []byte) string {
	var sb strings.Builder
	var buffer uint32
	var bits int
	for _, b := range data {
		buffer = (buffer << 8) | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(crockfordAlphabet[(buffer>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(crockfordAlphabet[(buffer<<uint(5-bits))&0x1f])
	}
	return sb.String()
}

func (cli *Client) getShortcakeRef(ctx context.Context) (string, error) {
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqGet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{{Tag: "ref"}},
	})
	if err != nil {
		return "", err
	}
	refBytes, ok := resp.GetChildByTag("ref").Content.([]byte)
	if !ok {
		return "", fmt.Errorf("GetRef response missing <ref> content")
	}
	return string(refBytes), nil
}

func (cli *Client) getPasskeyRequestOptions(ctx context.Context) ([]byte, error) {
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqGet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{{Tag: "passkey_request_options"}},
	})
	if err != nil {
		return nil, err
	}
	options, ok := resp.GetChildByTag("passkey_request_options").Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("GetPasskeyRequestOptions response missing content")
	}
	return options, nil
}

func (cli *Client) setPasskeyPrologue(ctx context.Context, credentialID, webauthnAssertion, prologuePayload, pairingHandoffProof []byte) error {
	children := []waBinary.Node{
		{Tag: "credential_id", Content: credentialID},
		{Tag: "webauthn_assertion", Content: webauthnAssertion},
		{Tag: "prologue_payload", Content: prologuePayload},
	}
	if len(pairingHandoffProof) > 0 {
		children = append(children, waBinary.Node{Tag: "pairing_handoff_proof", Content: pairingHandoffProof})
	}
	_, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqSet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{{Tag: "passkey_prologue", Content: children}},
	})
	return err
}

func (cli *Client) sendCompanionNonce(ctx context.Context, companionNonce []byte) error {
	_, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqSet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{{Tag: "companion_nonce", Content: companionNonce}},
	})
	return err
}

func (cli *Client) sendEncryptedPairingRequest(ctx context.Context, encryptedPairingRequest []byte) error {
	_, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      iqSet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{{Tag: "encrypted_pairing_request", Content: encryptedPairingRequest}},
	})
	return err
}
