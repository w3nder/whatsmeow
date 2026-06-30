// Command passkeytest links a device with whatsmeow, wiring the browser passkey bridge so accounts
// that require the Shortcake passkey prologue can complete linking.
//
// Usage:
//  1. go run ./cmd/passkeytest
//  2. Paste the printed script into the console of a logged-in https://web.whatsapp.com tab.
//  3. Scan the QR code shown in the terminal.
package main

import (
	"context"
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

const bridgeAddr = "127.0.0.1:7799"

func main() {
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

	// Browser passkey bridge: an existing browser/OS passkey signs the prologue assertion.
	bridge := passkeyauth.NewBrowserPasskeyAuthenticator()
	go func() {
		if serveErr := bridge.ListenAndServe(bridgeAddr); serveErr != nil {
			clientLog.Errorf("Bridge server stopped: %v", serveErr)
		}
	}()
	cli.PasskeyAuthenticator = bridge

	cli.AddEventHandler(func(evt any) {
		switch e := evt.(type) {
		case *events.ShortcakeVerificationCode:
			fmt.Printf("\n>>> Confirme no celular que o código bate: %s\n\n", e.Code)
		case *events.PairSuccess:
			fmt.Printf("\n>>> Pareado com sucesso: %s\n\n", e.ID)
		}
	})

	fmt.Println("\n=== INSTALE A EXTENSÃO (a CSP do WhatsApp bloqueia colar no console) ===")
	fmt.Println(">>> chrome://extensions > Modo desenvolvedor > Carregar sem compactação (Load unpacked)")
	fmt.Println(">>> selecione a pasta cmd/passkeytest/extension (dentro do repositório).")
	fmt.Println(">>> depois abra/recarregue uma aba LOGADA do web.whatsapp.com.")
	fmt.Println("=====================================================================")

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
