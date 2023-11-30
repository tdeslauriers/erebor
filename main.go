package main

import (
	"log"
	"net/http"
	"os"

	"github.com/tdeslauriers/carapace/standard"
)

func main() {
	pki := &standard.PkiCerts{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
	}

	serverConfig := &standard.ServerPkiConfigurer{Config: pki}
	tlsConfig, err := serverConfig.SetupPki()
	if err != nil {
		log.Fatalln("Failed to set up standard tls server config: ", err)
	}

	server := &standard.Server{
		Address:   ":8443",
		TlsConfig: tlsConfig,
	}

	go func() {

		log.Printf("Starting mTLS server on %s...", server.Address[1:])
		if err := server.Start(); err != http.ErrServerClosed {
			log.Fatalln("Failed to start Erebor Gateway server: ", err)
		}
	}()

	select {}
}
