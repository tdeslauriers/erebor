package main

import (
	"log"
	"net/http"
	"os"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/diagnostics"
)

const (
	EnvCaCert       string = "EREBOR_CA_CERT"
	EnvServerCert   string = "EREBOR_SERVER_CERT"
	EnvServerKey    string = "EREBOR_SERVER_KEY"
	EnvClientCert   string = "EREBOR_CLIENT_CERT"
	EnvClientKey    string = "EREBOR_CLIENT_KEY"
	EnvDbClientCert string = "EREBOR_DB_CLIENT_CERT"
	EnvDbClientKey  string = "EREBOR_DB_CLIENT_KEY"

	// ran s2s authn
	EnvClientIdstring string = "EREBOR_AUTH_CLIENT_ID"
	EnvClientSecret   string = "EREBOR_AUTH_CLIENT_SECRET"

	// db config
	EnvDbUrl      string = "EREBOR_DATABASE_URL"
	EnvDbName     string = "EREBOR_DATABASE_NAME"
	EnvDbUsername string = "EREBOR_DATABASE_USERNAME"
	EnvDbPassword string = "EREBOR_DATABASE_PASSWORD"
)

func main() {
	serverPki := &connect.Pki{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
	}

	tls, err := connect.NewTLSConfig("standard", serverPki)
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
			log.Fatalf("Failed to start Erebor Gateway server: %v", err)
		}
	}()

	select {}
}
