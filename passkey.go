// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"fmt"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/types"
)

// PasskeyAssertion is the result of the WebAuthn ceremony required by the Shortcake passkey prologue.
type PasskeyAssertion struct {
	CredentialID  []byte
	AssertionJSON []byte
}

// PasskeyAuthenticator supplies the credential-bound parts of the Shortcake passkey prologue.
// Implementations need a passkey registered under rpId "whatsapp.com" whose private key they control.
type PasskeyAuthenticator interface {
	GetAssertion(ctx context.Context, requestOptions []byte) (*PasskeyAssertion, error)
	BuildProloguePayload(ctx context.Context, ref string, deviceType waCompanionReg.DeviceProps_PlatformType) ([]byte, error)
}

func (cli *Client) handlePasskeyPrologueRequest(ctx context.Context, node *waBinary.Node) {
	if cli.PasskeyAuthenticator == nil {
		cli.Log.Warnf("Received passkey_prologue_request but no PasskeyAuthenticator is set; linking will time out")
		return
	}
	if err := cli.completePasskeyPrologue(ctx, node); err != nil {
		cli.Log.Errorf("Failed to complete passkey prologue: %v", err)
	}
}

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

	prologuePayload, err := cli.PasskeyAuthenticator.BuildProloguePayload(ctx, ref, waCompanionReg.DeviceProps_CHROME)
	if err != nil {
		return fmt.Errorf("failed to build prologue payload: %w", err)
	}

	return cli.setPasskeyPrologue(ctx, assertion.CredentialID, assertion.AssertionJSON, prologuePayload, nil)
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
		Content: []waBinary.Node{{
			Tag:     "passkey_prologue",
			Content: children,
		}},
	})
	return err
}
