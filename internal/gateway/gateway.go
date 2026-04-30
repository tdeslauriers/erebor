package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"erebor/gen"
	"erebor/internal/authentication"
	"erebor/internal/authentication/oauth"
	"erebor/internal/authentication/uxsession"
	"erebor/internal/clients"
	"erebor/internal/gallery"
	"erebor/internal/permissions"
	"erebor/internal/scheduled"
	"erebor/internal/scopes"
	"erebor/internal/tasks"
	"erebor/internal/user"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Gateway interface {
	Run(ctx context.Context) error
	Close() error
}

func New(config *config.Config) (Gateway, error) {

	// server certs
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(config.Tls, serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure server tls: %v", err)
	}

	// s2s client certs
	clientPki := &connect.Pki{
		CertFile: *config.Certs.ClientCert,
		KeyFile:  *config.Certs.ClientKey,
		CaFiles:  []string{*config.Certs.ClientCa},
	}

	clientConfig := connect.NewTlsClientConfig(clientPki)

	// standard http client
	client, err := connect.NewTlsClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure s2s client config: %v", err)
	}

	// db client certs
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

	// set up indexer to create blind indexes for encrypted data tables
	indexer, err := data.NewIndexer([]byte(config.Database.IndexSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to create data indexer: %v", err)
	}

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key Env var: %v", err)
	}

	cryptor, err := data.NewServiceAesGcmKey(aes)
	if err != nil {
		return nil, fmt.Errorf("failed to create field level encryption service: %v", err)
	}

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

	// callers
	s2s := connect.NewS2sCaller(config.ServiceAuth.Url, util.ServiceS2s, client, retry)
	iam := connect.NewS2sCaller(config.UserAuth.Url, util.ServiceIdentity, client, retry)
	task := connect.NewS2sCaller(config.Tasks.Url, util.ServiceTasks, client, retry)
	gallery := connect.NewS2sCaller(config.Gallery.Url, util.ServiceGallery, client, retry)

	// s2s token provider
	tkn := provider.NewS2sTokenProvider(s2s, creds, db, cryptor)

	// ux session service
	sn := uxsession.NewService(&config.OauthRedirect, db, indexer, cryptor, tkn, iam)

	// profile grpc client
	// set up tls
	tlsCfg, err := clientConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build grpc tls config: %v", err)
	}

	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCreds := credentials.NewTLS(tlsCfg)

	// instatiate profile service grpc client connection
	profileConn, err := grpc.NewClient(
		config.Profiles.Url,
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithChainUnaryInterceptor(
			exo.UnaryClientWithTelemetry(slog.Default()),
			authentication.NewAuthInterceptor(tkn, sn).Unary(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile grpc client connection: %v", err)
	}

	// profiles grpc client
	profileClient := gen.NewProfilesClient(profileConn)

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

	return &gateway{
		config:      *config,
		serverTls:   serverTlsConfig,
		repository:  db,
		tknProvider: tkn,
		s2s:         s2s,
		iam:         iam,
		task:        task,
		gallery:     gallery,
		profileConn: profileConn,
		profiles:    profileClient,
		uxSession:   sn,
		oAuth:       oauth.NewService(config.OauthRedirect, db, cryptor, indexer),
		verifier:    jwt.NewVerifier(config.ServiceName, publicKey),
		pat:         pat.NewVerifier(util.ServiceS2s, s2s, tkn),
		cryptor:     cryptor,
		cleanup:     scheduled.NewService(db, tkn, iam, gallery, profileClient),

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageGateway)).
			With(slog.String(util.ComponentKey, util.ComponentGateway)),
	}, nil
}

var _ Gateway = (*gateway)(nil)

type gateway struct {
	config      config.Config
	serverTls   *tls.Config
	repository  *sql.DB
	tknProvider provider.S2sTokenProvider
	s2s         *connect.S2sCaller
	iam         *connect.S2sCaller
	task        *connect.S2sCaller
	gallery     *connect.S2sCaller
	profileConn *grpc.ClientConn
	profiles    gen.ProfilesClient
	uxSession   uxsession.Service
	oAuth       oauth.Service
	verifier    jwt.Verifier
	pat         pat.Verifier
	cryptor     data.Cryptor
	cleanup     scheduled.Service

	logger *slog.Logger
}

func (g *gateway) Close() error {

	// close database connection
	if err := g.repository.Close(); err != nil {
		g.logger.Error(err.Error())
		return err
	}

	// close the grpc connections
	if g.profileConn != nil {
		if err := g.profileConn.Close(); err != nil {
			g.logger.Error("failed to close profile service grpc connection", "err", err.Error())
			return err
		}
	}

	return nil
}

func (g *gateway) Run(ctx context.Context) error {

	// setup mux
	mux := http.NewServeMux()

	// health check
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	// anonymous sessions
	uxSessionHandler := uxsession.NewHandler(g.uxSession)
	mux.HandleFunc("/session/anonymous", uxSessionHandler.HandleGetSession)

	// csrf
	csrfHandler := uxsession.NewCsrfHandler(g.uxSession)
	mux.HandleFunc("/session/csrf/", csrfHandler.HandleGetCsrf) // trailing slash required for /session/csrf/{session}

	// user registation
	register := authentication.NewRegistrationHandler(
		g.config.OauthRedirect,
		g.uxSession,
		g.tknProvider,
		g.iam,
		g.gallery,
		g.profileConn,
	)
	mux.HandleFunc("/register", register.HandleRegistration)

	// oauth state
	oauth := oauth.NewHandler(g.oAuth)
	mux.HandleFunc("/oauth/state", oauth.HandleGetState)

	// oauth callback
	callback := authentication.NewCallbackHandler(
		g.tknProvider,
		g.iam,
		g.profiles,
		g.oAuth,
		g.uxSession,
		g.verifier,
	)
	mux.HandleFunc("/oauth/callback", callback.HandleCallback)

	// login
	login := authentication.NewLoginHandler(g.uxSession, g.tknProvider, g.iam)
	mux.HandleFunc("/login", login.HandleLogin)

	// logout
	logout := authentication.NewLogoutHandler(g.uxSession)
	mux.HandleFunc("/logout", logout.HandleLogout)

	// user, profile, pw
	accounts := user.NewHandler(
		g.uxSession,
		g.tknProvider,
		g.iam,
		g.task,
		g.gallery,
		g.profiles,
	)
	mux.HandleFunc("/profile", accounts.HandleProfile)
	mux.HandleFunc("/reset", accounts.HandleReset)
	mux.HandleFunc("/users/{slug...}", accounts.HandleUsers)
	mux.HandleFunc("/users/scopes", accounts.HandleScopes)
	mux.HandleFunc("/users/permissions", accounts.HandlePermissions)

	// user addresses
	addresses := user.NewAddressHandler(
		g.uxSession,
		g.tknProvider,
		g.profileConn,
	)
	mux.HandleFunc("/addresses", addresses.HandleAddress)

	// user phones
	phones := user.NewPhoneHandler(
		g.uxSession,
		g.tknProvider,
		g.profileConn,
	)
	mux.HandleFunc("/phones", phones.HandlePhones)

	// scopes
	scope := scopes.NewHandler(g.uxSession, g.tknProvider, g.s2s)
	mux.HandleFunc("/scopes/{slug...}", scope.HandleScopes)

	// permissions
	pm := permissions.NewHandler(g.uxSession, g.tknProvider, g.task, g.gallery)
	mux.HandleFunc("/permissions/{slug...}", pm.HandlePermissions)

	// clients/s2s
	client := clients.NewHandler(g.uxSession, g.tknProvider, g.s2s)
	mux.HandleFunc("/clients/{slug...}", client.HandleClients) // POST is /clients/register
	mux.HandleFunc("/clients/reset", client.HandleReset)
	mux.HandleFunc("/clients/scopes", client.HandleScopes)
	mux.HandleFunc("/clients/generate/pat", client.HandleGeneratePat)

	// tasks/allowances
	task := tasks.NewHandler(g.uxSession, g.tknProvider, g.iam, g.task)
	mux.HandleFunc("/account", task.HandleAccount)
	mux.HandleFunc("/allowances/{slug...}", task.HandleAllowances)
	mux.HandleFunc("/templates/{slug...}", task.HandleTemplates)
	mux.HandleFunc("/tasks", task.HandleTasks)

	// gallery/images/pics
	glry := gallery.NewHandler(g.uxSession, g.tknProvider, g.gallery, g.pat)
	mux.HandleFunc("/albums/{slug...}", glry.HandleAlbums)
	mux.HandleFunc("/images/{slug...}", glry.HandleImage)
	mux.HandleFunc("/images/notify/upload", glry.HandleImageUploadNotification)
	mux.HandleFunc("/images/permissions", glry.HandlePermissions)

	erebor := &connect.TlsServer{
		Addr:      g.config.ServicePort,
		Mux:       mux,
		TlsConfig: g.serverTls,
	}

	go func() {

		g.logger.Info(fmt.Sprintf("starting %s gateway service on %s...", g.config.ServiceName, erebor.Addr[1:]))
		if err := erebor.Initialize(); err != http.ErrServerClosed {
			g.logger.Error(fmt.Sprintf("failed to start %s gateway service: %v", g.config.ServiceName, err.Error()))
			os.Exit(1)
		}
	}()

	g.cleanup.ExpiredAccess(ctx)
	g.cleanup.ExpiredS2s(ctx)
	g.cleanup.ExpiredSession(ctx, 1)
	g.cleanup.ReconcileGalleryAccounts()
	g.cleanup.ReconcileProfileAccounts()

	return nil
}
