package main

import (
	"encoding/base64"
	"erebor/auth"
	"log"
	"net/http"
	"os"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/diagnostics"
	"github.com/tdeslauriers/carapace/session"
)

const (
	EnvCaCert       string = "EREBOR_CA_CERT"
	EnvServerCert   string = "EREBOR_SERVER_CERT" // external-facing (not mtls)
	EnvServerKey    string = "EREBOR_SERVER_KEY"
	EnvClientCert   string = "EREBOR_CLIENT_CERT"
	EnvClientKey    string = "EREBOR_CLIENT_KEY"
	EnvDbClientCert string = "EREBOR_DB_CLIENT_CERT"
	EnvDbClientKey  string = "EREBOR_DB_CLIENT_KEY"

	// ran s2s authn
	EnvS2sTokenUrl    string = "EREBOR_S2S_AUTH_URL"
	EnvClientIdstring string = "EREBOR_S2S_AUTH_CLIENT_ID"
	EnvClientSecret   string = "EREBOR_S2S_AUTH_CLIENT_SECRET"

	// s2s services
	EnvS2sUserAuthUrl string = "EREBOR_S2S_USER_AUTH_URL"

	// db config
	EnvDbUrl      string = "EREBOR_DATABASE_URL"
	EnvDbName     string = "EREBOR_DATABASE_NAME"
	EnvDbUsername string = "EREBOR_DATABASE_USERNAME"
	EnvDbPassword string = "EREBOR_DATABASE_PASSWORD"
	EnvFieldsKey  string = "EREBOR_FIELD_LEVEL_AES_GCM_KEY"
)

func main() {

	// front end server
	serverPki := &connect.Pki{
		CertFile: os.Getenv(EnvServerCert),
		KeyFile:  os.Getenv(EnvServerKey),
	}

	tls, err := connect.NewTLSConfig("standard", serverPki)
	if err != nil {
		log.Fatalf("Failed to configure tls: %v", err)
	}

	// s2s client
	clientPki := connect.Pki{
		CertFile: os.Getenv(EnvClientCert),
		KeyFile:  os.Getenv(EnvClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	clientConfig := connect.ClientConfig{Config: &clientPki}
	client, err := clientConfig.NewTlsClient()
	if err != nil {
		log.Fatalf("Unable to create Erebor s2s client config: %v", err)
	}

	// db client
	dbClientPki := connect.Pki{
		CertFile: os.Getenv(EnvDbClientCert),
		KeyFile:  os.Getenv(EnvDbClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}
	dbClientConfig := connect.ClientConfig{Config: &dbClientPki}

	// db config
	dbUrl := data.DbUrl{
		Name:     os.Getenv(EnvDbName),
		Addr:     os.Getenv(EnvDbUrl),
		Username: os.Getenv(EnvDbUsername),
		Password: os.Getenv(EnvDbPassword),
	}

	dbConnector := &data.MariaDbConnector{
		TlsConfig:     dbClientConfig,
		ConnectionUrl: dbUrl.Build(),
	}

	repository := data.MariaDbRepository{
		SqlDb: dbConnector,
	}

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(os.Getenv(EnvFieldsKey))
	if err != nil {
		log.Panicf("unable to decode field level encryption key Env var: %v", err)
	}
	cryptor := data.NewServiceAesGcmKey(aes)

	// s2s creds
	cmd := session.S2sCredentials{
		ClientId:     os.Getenv(EnvClientIdstring),
		ClientSecret: os.Getenv(EnvClientSecret),
	}

	// s2s callers
	ranCaller := connect.NewS2sCaller(os.Getenv(EnvS2sTokenUrl), "ran", client)
	shawCaller := connect.NewS2sCaller(os.Getenv(EnvS2sUserAuthUrl), "shaw", client)

	// s2s token provider
	s2sProvider := session.NewS2sTokenProvider(ranCaller, cmd, &repository, cryptor)

	register := auth.NewRegistrationHandler(s2sProvider, shawCaller)
	login := auth.NewLoginHandler(s2sProvider, shawCaller)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/register", register.HandleRegistration)
	mux.HandleFunc("/login", login.HandleLogin)

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
