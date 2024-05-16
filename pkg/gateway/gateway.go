package gateway

import (
	"crypto/tls"
	"encoding/base64"
	"erebor/internal/util"
	"erebor/pkg/auth"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type Gateway interface {
	Run() error
}

func New(config config.Config) (Gateway, error) {

	// front end server
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
	}

	serverTlsConfig, err := connect.NewTlsServerConfig("standard", serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure server tls: %v", err)
	}

	// s2s client
	clientPki := &connect.Pki{
		CertFile: *config.Certs.ClientCert,
		KeyFile:  *config.Certs.ClientKey,
		CaFiles:  []string{*config.Certs.ClientCa},
	}

	clientConfig := connect.NewTlsClientConfig(clientPki)
	client, err := connect.NewTlsClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create s2s client config: %v", err)
	}

	// db client
	dbClientPki := &connect.Pki{
		CertFile: *config.Certs.DbClientCert,
		KeyFile:  *config.Certs.DbClientKey,
		CaFiles:  []string{*config.Certs.DbCaCert},
	}

	dbClientConfig, err := connect.NewTlsClientConfig(dbClientPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure database client tls: %v", err)
	}

	// db config
	dbUrl := data.DbUrl{
		Name:     config.Database.Name,
		Addr:     config.Database.Url,
		Username: config.Database.Username,
		Password: config.Database.Password,
	}

	dbConnector := data.NewSqlDbConnector(dbUrl, dbClientConfig)
	repository := data.NewSqlRepository(dbConnector)

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode field level encryption key Env var: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// s2s creds
	creds := session.S2sCredentials{
		ClientId:     config.ServiceAuth.ClientId,
		ClientSecret: config.ServiceAuth.ClientSecret,
	}

	// retry config for s2s callers
	retry := connect.RetryConfiguration{
		MaxRetries:  5,
		BaseBackoff: 100 * time.Microsecond,
		MaxBackoff:  10 * time.Second,
	}

	// s2s callers
	ranCaller := connect.NewS2sCaller(config.ServiceAuth.Url, "ran", client, retry)
	shawCaller := connect.NewS2sCaller(config.UserAuth.Url, "shaw", client, retry)

	// s2s token provider
	s2sProvider := session.NewS2sTokenProvider(ranCaller, creds, repository, cryptor)

	return &gateway{
		config:           config,
		serverTls:        serverTlsConfig,
		s2sTokenProvider: s2sProvider,
		shawCaller:       shawCaller,
		logger:           slog.Default().With(slog.String(util.ComponentKey, util.ComponentGateway)),
	}, nil
}

type gateway struct {
	config           config.Config
	serverTls        *tls.Config
	s2sTokenProvider session.S2sTokenProvider
	shawCaller       connect.S2sCaller

	logger *slog.Logger
}

var _ Gateway = (*gateway)(nil)

func (g *gateway) Run() error {

	register := auth.NewRegistrationHandler(g.s2sTokenProvider, g.shawCaller)
	login := auth.NewLoginHandler(g.s2sTokenProvider, g.shawCaller)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/register", register.HandleRegistration)
	mux.HandleFunc("/login", login.HandleLogin)

	erebor := &connect.TlsServer{
		Addr:      ":8443",
		Mux:       mux,
		TlsConfig: g.serverTls,
	}

	go func() {

		g.logger.Info(fmt.Sprintf("starting Erebor gateway service on %s...", erebor.Addr[1:]))
		if err := erebor.Initialize(); err != http.ErrServerClosed {
			g.logger.Error("failed to start Erebor gateway service: %v", err)
			os.Exit(1)
		}

	}()
	return nil
}
