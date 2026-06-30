// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"crypto/sha256"
	"testing"
)

func TestCrockfordBase32(t *testing.T) {
	cases := map[string]string{
		string([]byte{0, 0, 0, 0, 0}):                "00000000",
		string([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}): "ZZZZZZZZ",
	}
	for in, want := range cases {
		if got := crockfordBase32([]byte(in)); got != want {
			t.Errorf("crockfordBase32(% x) = %q, want %q", in, got, want)
		}
	}
	if got := crockfordBase32(make([]byte, shortcakeVerificationCodeLength)); len(got) != 8 {
		t.Errorf("5-byte code should be 8 chars, got %d (%q)", len(got), got)
	}
}

func TestDeriveShortcakeVerificationCode(t *testing.T) {
	companionNonce := make([]byte, shortcakeNonceLength)
	primaryPub := make([]byte, 32)
	primaryNonce := make([]byte, shortcakeNonceLength)

	digest := sha256.Sum256(append(append([]byte{}, companionNonce...), primaryPub...))
	want := make([]byte, shortcakeVerificationCodeLength)
	for i := range want {
		want[i] = primaryNonce[i] ^ digest[i]
	}

	got := deriveShortcakeVerificationCode(companionNonce, primaryPub, primaryNonce)
	if got != crockfordBase32(want) {
		t.Errorf("deriveShortcakeVerificationCode = %q, want %q", got, crockfordBase32(want))
	}
	if len(got) != 8 {
		t.Errorf("verification code should be 8 chars, got %d", len(got))
	}
}
