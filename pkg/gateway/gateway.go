package gateway

import (
	"crypto/tls"
	"encoding/base64"
	"erebor/internal/util"
	"erebor/pkg/authentication"
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
	CloseDb() error
}

func New(config config.Config) (Gateway, error) {

	// server
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(config.Tls, serverPki).Build()
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
		return nil, fmt.Errorf("failed to configure s2s client config: %v", err)
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

	db, err := data.NewSqlDbConnector(dbUrl, dbClientConfig).Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	repository := data.NewSqlRepository(db)

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key Env var: %v", err)
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

	// login service
	loginService := authentication.NewOuathService(repository, cryptor)

	return &gateway{
		config:           config,
		serverTls:        serverTlsConfig,
		repository:       repository,
		s2sTokenProvider: s2sProvider,
		shawCaller:       shawCaller,
		loginService:     loginService,
		logger:           slog.Default().With(slog.String(util.ComponentKey, util.ComponentGateway)),
	}, nil
}

var _ Gateway = (*gateway)(nil)

type gateway struct {
	config           config.Config
	serverTls        *tls.Config
	repository       data.SqlRepository
	s2sTokenProvider session.S2sTokenProvider
	shawCaller       connect.S2sCaller
	loginService     authentication.OauthService

	logger *slog.Logger
}

func (g *gateway) CloseDb() error {
	if err := g.repository.Close(); err != nil {
		g.logger.Error(err.Error())
		return err
	}
	return nil
}

func (g *gateway) Run() error {

	register := authentication.NewRegistrationHandler(g.s2sTokenProvider, g.shawCaller)
	login := authentication.NewLoginHandler(g.config.SiteUrl, g.s2sTokenProvider, g.shawCaller, g.loginService)

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
			g.logger.Error("failed to start Erebor gateway service: %v", "err", err.Error())
			os.Exit(1)
		}

	}()
	return nil
}
