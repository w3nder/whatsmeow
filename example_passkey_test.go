// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow_test

import (
	"context"
	"fmt"

	"go.mau.fi/whatsmeow"
)

// ExampleBrowserPasskeyAuthenticator shows how to link a device on an account that requires the
// Shortcake passkey prologue, reusing a passkey already stored in the browser/OS (Touch ID, Windows
// Hello, etc.) without extracting any private key.
//
// Steps for the operator:
//  1. Run this program; it serves the bridge HTTP API and prints the helper script.
//  2. Open a logged-in https://web.whatsapp.com tab and paste the printed script in the console.
//  3. Scan the QR code; when the server asks for the passkey, the browser signs it (Touch ID prompt).
func ExampleBrowserPasskeyAuthenticator() {
	// cli is a normal whatsmeow client; see the README for store/Container setup.
	var cli *whatsmeow.Client

	bridge := whatsmeow.NewBrowserPasskeyAuthenticator()
	go func() {
		// Serve on localhost; the browser script polls this address.
		_ = bridge.ListenAndServe("127.0.0.1:7799")
	}()
	cli.PasskeyAuthenticator = bridge

	fmt.Println("Paste this in the web.whatsapp.com console:")
	fmt.Println(whatsmeow.BrowserBridgeScript("http://127.0.0.1:7799"))

	qrChan, _ := cli.GetQRChannel(context.Background())
	_ = cli.Connect()
	for evt := range qrChan {
		switch evt.Event {
		case "code":
			fmt.Println("Scan this QR code:", evt.Code)
		case "success":
			fmt.Println("Device linked (passkey assertion provided by the browser).")
		case "timeout", "error":
			fmt.Println("Linking failed:", evt.Event)
		}
	}
}

// ExampleVirtualAuthenticator shows the fully headless alternative: a software passkey owned by the
// library. The credential must first be registered on the account (use va.MakeCredential / the
// enrollment flow); afterwards persist it with Export and reuse it on every run.
func ExampleVirtualAuthenticator() {
	var cli *whatsmeow.Client

	va, err := whatsmeow.NewVirtualAuthenticator()
	if err != nil {
		panic(err)
	}

	// Persist the authenticator (private key + credential ID) so the same passkey is reused later.
	blob, _ := va.Export()
	_ = blob // store this somewhere safe; restore with whatsmeow.ImportVirtualAuthenticator(blob)

	cli.PasskeyAuthenticator = va

	qrChan, _ := cli.GetQRChannel(context.Background())
	_ = cli.Connect()
	for evt := range qrChan {
		if evt.Event == "success" {
			fmt.Println("Device linked with the virtual passkey.")
		}
	}
}
