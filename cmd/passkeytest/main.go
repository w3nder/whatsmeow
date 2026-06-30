// Command passkeytest links a device with whatsmeow, wiring a passkey authenticator so accounts that
// require the Shortcake passkey prologue can complete linking.
//
// Usage:
//
//	go run ./cmd/passkeytest               # default: headless virtual authenticator (no browser)
//	go run ./cmd/passkeytest -mode bridge  # reuse an existing browser passkey (extension: w3nder/wa-passkey)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mdp/qrterminal/v3"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/passkeyauth"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

const (
	bridgeAddr   = "127.0.0.1:7799"
	virtualStore = "passkey_virtual.json"
)

func main() {
	mode := flag.String("mode", "virtual", "passkey authenticator: virtual (headless) or bridge (browser)")
	flag.Parse()

	ctx := context.Background()

	dbLog := waLog.Stdout("Database", "INFO", true)
	container, err := sqlstore.New(ctx, "sqlite3", "file:passkeytest.db?_foreign_keys=on", dbLog)
	if err != nil {
		panic(err)
	}
	deviceStore, err := container.GetFirstDevice(ctx)
	if err != nil {
		panic(err)
	}

	clientLog := waLog.Stdout("Client", "INFO", true)
	cli := whatsmeow.NewClient(deviceStore, clientLog)

	switch *mode {
	case "bridge":
		setupBridge(cli, clientLog)
	default:
		setupVirtual(cli, clientLog)
	}

	cli.AddEventHandler(func(evt any) {
		switch e := evt.(type) {
		case *events.ShortcakeVerificationCode:
			fmt.Printf("\n>>> Confirme no celular que o código bate: %s\n\n", e.Code)
		case *events.ShortcakePasskeyRequired:
			fmt.Println("\n>>> Esta conta EXIGE passkey. Opções:")
			fmt.Println(">>>  1) Sem browser: remova a passkey no celular (Configurações > Conta > Chaves de acesso).")
			fmt.Printf(">>>  2) Com browser: abra %s e rode com -mode bridge (extensão instalada).\n", e.HelpURL)
		case *events.PairSuccess:
			fmt.Printf("\n>>> Pareado com sucesso: %s\n\n", e.ID)
		}
	})

	if cli.Store.ID == nil {
		qrChan, _ := cli.GetQRChannel(ctx)
		if err = cli.Connect(); err != nil {
			panic(err)
		}
		for evt := range qrChan {
			switch evt.Event {
			case "code":
				fmt.Println("\nEscaneie o QR abaixo no WhatsApp do celular:")
				qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
			case "success":
				fmt.Println("\nLeitura do QR concluída, finalizando pareamento...")
			default:
				fmt.Println("Evento de pareamento:", evt.Event)
			}
		}
	} else {
		if err = cli.Connect(); err != nil {
			panic(err)
		}
		fmt.Println("Já logado, conectado.")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	cli.Disconnect()
}

// setupVirtual wires the headless software passkey. No browser is involved. The credential is
// persisted so the same passkey is reused across runs.
func setupVirtual(cli *whatsmeow.Client, log waLog.Logger) {
	var va *passkeyauth.VirtualAuthenticator
	if blob, err := os.ReadFile(virtualStore); err == nil {
		if va, err = passkeyauth.ImportVirtualAuthenticator(blob); err != nil {
			log.Warnf("Failed to load %s, generating a new one: %v", virtualStore, err)
			va = nil
		}
	}
	if va == nil {
		var err error
		if va, err = passkeyauth.NewVirtualAuthenticator(); err != nil {
			panic(err)
		}
		if blob, err := va.Export(); err == nil {
			_ = os.WriteFile(virtualStore, blob, 0o600)
		}
	}
	cli.PasskeyAuthenticator = va
	fmt.Println("\n=== Modo VIRTUAL (headless, sem browser) ===")
	fmt.Println(">>> A passkey é de software; nenhum browser/extensão é usado.")
	fmt.Println(">>> Obs.: o registro automático (RegisterPasskey) ainda é um stub — em contas que")
	fmt.Println(">>>       exigem passkey, o assertion vai falhar até o enrollment ser implementado.")
	fmt.Println("============================================")
}

// setupBridge wires the browser-backed authenticator and prints the extension instructions.
func setupBridge(cli *whatsmeow.Client, log waLog.Logger) {
	bridge := passkeyauth.NewBrowserPasskeyAuthenticator()
	go func() {
		if err := bridge.ListenAndServe(bridgeAddr); err != nil {
			log.Errorf("Bridge server stopped: %v", err)
		}
	}()
	cli.PasskeyAuthenticator = bridge
	fmt.Println("\n=== Modo BRIDGE (usa o browser) — INSTALE A EXTENSÃO ===")
	fmt.Println(">>> A extensão está no repo: https://github.com/w3nder/wa-passkey (pasta extension/)")
	fmt.Println(">>> chrome://extensions > Modo desenvolvedor > Carregar sem compactação (Load unpacked)")
	fmt.Println(">>> selecione a pasta extension/ do wa-passkey, abra uma aba LOGADA do web.whatsapp.com.")
	fmt.Println("=======================================================")
}
