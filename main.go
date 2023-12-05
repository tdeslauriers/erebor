package main

import (
	"log"
	"net/http"
	"os"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/diagnostics"
)

func main() {
	pki := &connect.Pki{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
	}

	tls, err := connect.NewTLSConfig("standard", pki)
	if err != nil {
		log.Fatalf("Failed to configure tls: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	server := &connect.TlsServer{
		Addr:      ":8443",
		Mux:       mux,
		TlsConfig: tls,
	}

	go func() {

		log.Printf("Starting mTLS server on %s...", server.Addr[1:])
		if err := server.Initialize(); err != http.ErrServerClosed {
			log.Fatalln("Failed to start Erebor Gateway server: ", err)
		}
	}()

	select {}
}
