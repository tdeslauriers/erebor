package gateway

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"erebor/internal/util"
	"erebor/pkg/authentication"
	"erebor/pkg/authentication/oauth"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/schedule"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
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

	// set up indexer to create blind indexes for encrypted data tables
	indexer := data.NewIndexer([]byte(config.Database.IndexSecret))

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key Env var: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// s2s creds
	creds := provider.S2sCredentials{
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
	s2sIdentity := connect.NewS2sCaller(config.ServiceAuth.Url, util.ServiceS2sIdentity, client, retry)
	userIdentity := connect.NewS2sCaller(config.UserAuth.Url, util.ServiceUserIdentity, client, retry)

	// s2s token provider
	s2sToken := provider.NewS2sTokenProvider(s2sIdentity, creds, repository, cryptor)

	// ux session service
	uxSession := uxsession.NewService(repository, indexer, cryptor, s2sToken, userIdentity)

	// oauth service: state, nonce, redirect
	oAuth := oauth.NewService(config.OauthRedirect, repository, cryptor, indexer)

	// format public key for use in jwt verification
	pubPem, err := base64.StdEncoding.DecodeString(config.Jwt.UserVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user jwt-verifying public key: %v", err)
	}
	pubBlock, _ := pem.Decode(pubPem)
	genericPublicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub Block to generic public key: %v", err)
	}
	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	// id token jwt verifier
	identityVerifier := jwt.NewVerifier(config.ServiceName, publicKey)

	// clean up
	cleanup := schedule.NewCleanup(repository)

	return &gateway{
		config:       config,
		serverTls:    serverTlsConfig,
		repository:   repository,
		s2sToken:     s2sToken,
		userIdentity: userIdentity,
		uxSession:    uxSession,
		oAuth:        oAuth,
		verifier:     identityVerifier,
		cryptor:      cryptor,
		cleanup:      cleanup,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageGateway)),
	}, nil
}

var _ Gateway = (*gateway)(nil)

type gateway struct {
	config       config.Config
	serverTls    *tls.Config
	repository   data.SqlRepository
	s2sToken     provider.S2sTokenProvider
	userIdentity connect.S2sCaller
	uxSession    uxsession.Service
	oAuth        oauth.Service
	verifier     jwt.Verifier
	cryptor      data.Cryptor
	cleanup      schedule.Cleanup

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

	// setup handlers
	uxSessionHandler := uxsession.NewHandler(g.uxSession)
	csrfHandler := uxsession.NewCsrfHandler(g.uxSession)

	register := authentication.NewRegistrationHandler(g.config.OauthRedirect, g.uxSession, g.s2sToken, g.userIdentity)

	oauth := oauth.NewHandler(g.oAuth)
	login := authentication.NewLoginHandler(g.uxSession, g.s2sToken, g.userIdentity)
	logout := authentication.NewLogoutHandler(g.uxSession)

	callback := authentication.NewCallbackHandler(g.s2sToken, g.userIdentity, g.oAuth, g.uxSession, g.verifier)

	// setup mux
	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	mux.HandleFunc("/session/anonymous", uxSessionHandler.HandleGetSession)
	mux.HandleFunc("/session/csrf/", csrfHandler.HandleGetCsrf) // trailing slash required for /session/csrf/{session}

	mux.HandleFunc("/register", register.HandleRegistration)

	mux.HandleFunc("/oauth/state", oauth.HandleGetState)
	mux.HandleFunc("/oauth/callback", callback.HandleCallback)
	mux.HandleFunc("/login", login.HandleLogin)
	mux.HandleFunc("/logout", logout.HandleLogout)

	erebor := &connect.TlsServer{
		Addr:      g.config.ServicePort,
		Mux:       mux,
		TlsConfig: g.serverTls,
	}

	go func() {

		g.logger.Info(fmt.Sprintf("starting %s gateway service on %s...", g.config.ServiceName, erebor.Addr[1:]))
		if err := erebor.Initialize(); err != http.ErrServerClosed {
			g.logger.Error(fmt.Sprintf("failed to start %s gateway service", g.config.ServiceName), "err", err.Error())
			os.Exit(1)
		}
	}()

	go g.cleanup.ExpiredAccess()
	go g.cleanup.ExpiredS2s()
	go g.cleanup.ExpiredSession(1)

	return nil
}
