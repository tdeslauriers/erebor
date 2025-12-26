package uxsession

import (
	"context"
	"database/sql"
	"erebor/internal/util"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// TokenService is performs build and persistance operations on access tokens,
// particularly in relation to the authenticated uxsession.
type TokenService interface {

	// GetAccessToken retrieves the access token record from the database, decrypts the access and refresh tokens,
	// and returns the struct.  If the access token is expired, it will use an active refesh token to retrieve a new access token.
	// Note: will return an error if the provided session is not found, not authenticated, or revoked.
	GetAccessToken(ctx context.Context, session string) (string, error)

	// PeristToken creates a new AccessToken record, performs field level encryption for db record,
	// persists it to the database, and returns the struct.
	PersistToken(access *provider.UserAuthorization) (*AccessToken, error)

	// PersistXref persists the xref between the authenticated uxsession and the access token.
	PersistXref(xref SessionAccessXref) error
}

// NewTokenService creates a new instance of the TokenService interface, returning a concrete implementation.
func NewTokenService(
	cfg *config.OauthRedirect,
	db *sql.DB,
	indexer data.Indexer,
	cryptor data.Cryptor,
	s2sProvider provider.S2sTokenProvider,
	identity *connect.S2sCaller,
) TokenService {
	return &tokenService{
		cfg:         cfg,
		db:          NewTokenRepository(db),
		indexer:     indexer,
		cryptor:     cryptor,
		s2sProvider: s2sProvider,
		identity:    identity,
		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentSession)),
	}
}

// service is the concrete implementation of the Service interface.
type tokenService struct {
	cfg         *config.OauthRedirect // needed to populate client id for refresh requests
	db          TokenRepository
	indexer     data.Indexer
	cryptor     data.Cryptor
	s2sProvider provider.S2sTokenProvider
	identity    *connect.S2sCaller

	logger *slog.Logger
}

// GetAccessToken retrieves the access token record from the database, decrypts the access and refresh tokens,
// and returns the struct.  If the access token is expired, it will use an active refesh token to retrieve a new access token.
func (s *tokenService) GetAccessToken(ctx context.Context, session string) (string, error) {

	// get telemetry from context -> set up logger
	logger := s.logger
	telemetry, ok := ctx.Value(connect.TelemetryKey).(*connect.Telemetry)
	if ok && telemetry != nil {
		logger = logger.With(telemetry.TelemetryFields()...)
	} else {
		logger.Warn("failed to retrieve telemetry from context for GetAccessToken")
	}

	// lightweight input validation: redundant, but good practice
	if len(session) < 16 || len(session) > 64 {
		return "", errors.New(ErrInvalidSession)
	}

	// re generate session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return "", fmt.Errorf("%s from provided session token: %v", ErrGenIndex, err)
	}

	// look up access tokens tied to uxSession from db by session index
	tokens, err := s.db.FindAccessTokensBySession(index)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve access token records for session token: %v", err)
	}

	// if there are no tokens, return an error
	// this should be caught above, but good practice to check
	if len(tokens) == 0 {
		return "", errors.New(ErrSessionNotFound)
	}

	// if there is only one session returned, check for empty/default values in access token fields
	// this means the session is not authenticated or has no access token records, ie, fields were null.
	if len(tokens) == 1 {
		if tokens[0].AccessToken == "" || tokens[0].RefreshToken == "" {
			return "", errors.New(ErrAccessTokenNotFound)
		}
	}

	// return the first token that passes all checks.  If none pass, function will ultimately return error.
	for _, token := range tokens {

		// session checks are returns not continues because same value in all records
		// check if session listed as authenticated: this is a convenience value only, but should not be false
		if !token.SessionAuthenticated {
			return "", errors.New(ErrSessionNotAuthenticated)
		}

		// check if session is revoked
		if token.SessionRevoked {
			return "", errors.New(ErrSessionRevoked)
		}

		// chcek if session token is expired
		if token.SessionCreatedAt.Add(1 * time.Hour).Before(time.Now().UTC()) {
			return "", errors.New(ErrAccessTokenExpired)
		}

		// token checks are continues because not unique
		// check if null access token due to empty xref == session has no attached access token records
		if token.AccessToken == "" {
			logger.Error(ErrAccessTokenNotFound)
			continue
		}

		// check if access token is revoked
		if token.AccessRevoked {
			logger.Error(ErrAccessTokenRevoked)
			continue
		}

		// check if access token is expired
		if token.AccessExpires.Before(time.Now().UTC()) {
			logger.Error(ErrAccessTokenExpired)
			continue
		}

		// checks have passed: decrypt and return first available access token
		access, err := s.cryptor.DecryptServiceData(token.AccessToken)
		if err != nil {
			// this failure needs to be a continue, because possible for other access tokens to be decrypted successfully
			logger.Error(ErrDecryptAccessToken, "err", err.Error())
			continue
		}

		return string(access), nil
	}

	logger.Info("session token has no valid access tokens: attempting refresh")

	// look for a valid refresh token and retrieve a new access token
	for _, token := range tokens {

		// check if null refresh token due to empty xref == session has no attached access token records
		if token.RefreshToken == "" {
			logger.Error(ErrRefreshNotFound)
			continue
		}

		// check if refresh token is revoked
		if token.RefreshRevoked {
			logger.Error(ErrAccessTokenRevoked)
			continue
		}

		// check if refresh token is claimed
		if token.RefreshClaimed {
			logger.Error(ErrRefreshTokenClaimed)
			continue
		}

		// check if refresh token is expired
		if token.RefreshExpires.Before(time.Now().UTC()) {
			logger.Error(ErrRefreshTokenExpired)

			// TODO: opportunistically delete expired refresh token from db
			continue
		}

		// checks have passed: decrypt and return first available refresh token
		refresh, err := s.cryptor.DecryptServiceData(token.RefreshToken)
		if err != nil {
			// this failure needs to be a continue, because possible for other refresh tokens to be decrypted successfully
			logger.Error(ErrDecryptRefreshToken, "err", err.Error())
			continue
		}

		// get s2s token for identity service
		s2sToken, err := s.s2sProvider.GetServiceToken(ctx, util.ServiceIdentity)
		if err != nil {
			logger.Error("failed to get s2s token for identity service refresh endpoint", "err", err.Error())
			continue
		}

		cmd := types.UserRefreshCmd{
			RefreshToken: string(refresh),
			ClientId:     s.cfg.CallbackClientId,
		}

		// use refresh token to get new access token
		access, err := connect.PostToService[types.UserRefreshCmd, provider.UserAuthorization](
			ctx,
			s.identity,
			"/refresh",
			s2sToken,
			"",
			cmd,
		)
		if err != nil {
			logger.Error("failed to call identity service refresh endpoint for session token", "err", err.Error())
			continue
		}

		// persist and clean up concurrently for immediate access token return
		// persist new token
		go func() {
			persist, err := s.PersistToken(&access)
			if err != nil {
				logger.Error("failed to persist new access token for refresh request", "err", err.Error())
				return
			}

			// save cross reference to session
			xref := SessionAccessXref{
				UxsessionId:   token.UxsessionId,
				AccessTokenId: persist.Id,
			}

			if err := s.PersistXref(xref); err != nil {
				logger.Error("failed to persist uxsession_accesstoken xref record for refresh request", "err", err.Error())
				return
			}

			logger.Info(fmt.Sprintf("new access token persisted for session token xxxxx-%s", session[len(session)-6:]))
		}()

		// delete vs mark as claimed: identity service will not allow a refresh token to be used more than once
		go func() {

			if err := s.db.DeleteUxsessionAccessTknXref(token.AccessTokenId); err != nil {
				logger.Error("failed to delete xref for claimed refresh token", "err", err.Error())
				return
			}

			if err := s.db.DeleteAccessToken(token.AccessTokenId); err != nil {
				logger.Error("failed to delete access token for claimed refresh token", "err", err.Error())
				return
			}
		}()

		return access.AccessToken, nil
	}

	return "", errors.New(ErrAccessRefreshNotFound)
}

// PeristToken creates a new AccessToken record, performs field level encryption for db record,
// persists it to the database, and returns the struct.
// Note: this interface is implemented by the service struct in session_serivic.go
func (s *tokenService) PersistToken(access *provider.UserAuthorization) (*AccessToken, error) {

	// create primary key for access token
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s for access token: %v", ErrGenPrimaryKey, err)
	}

	// create new access token record
	persist := AccessToken{
		Id:             id.String(),
		AccessToken:    access.AccessToken, // encrypted above
		AccessExpries:  access.AccessTokenExpires,
		AccessRevoked:  false,
		RefreshToken:   access.Refresh, // encrypted above
		RefreshExpires: access.RefreshExpires,
		RefreshRevoked: false,
		RefreshClaimed: false,
	}

	// encrypt access and refresh tokens
	if err := s.fieldLevelEncrypt(&persist); err != nil {
		return nil, errors.New(err.Error())
	}

	// persist to database
	if err := s.db.InsertAccessToken(persist); err != nil {
		return nil, fmt.Errorf("failed to persist access token: %v", err)
	}

	return &persist, nil
}

// fieldLevelEncrypt is a helper function which encrypts the access and refresh tokens
// and can be updated to encrypt other fields as needed.
func (s *tokenService) fieldLevelEncrypt(access *AccessToken) error {

	var (
		wgEncrypt      sync.WaitGroup
		errEncryptChan = make(chan error, 2)

		encryptedAccess  string
		encryptedRefresh string
	)

	wgEncrypt.Add(2)
	go s.encrypt(access.AccessToken, ErrEncryptAccessToken, &encryptedAccess, errEncryptChan, &wgEncrypt)
	go s.encrypt(access.RefreshToken, ErrEncryptRefreshToken, &encryptedRefresh, errEncryptChan, &wgEncrypt)

	wgEncrypt.Wait()
	close(errEncryptChan)

	if len(errEncryptChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errEncryptChan {
			builder.WriteString(err.Error())
			if count < len(errEncryptChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return fmt.Errorf("failed to encrypt access/refresh tokens: %v", builder.String())

	}

	// replace access and refresh tokens with encrypted values
	access.AccessToken = encryptedAccess
	access.RefreshToken = encryptedRefresh

	return nil
}

// encrypt is a helper function which abstracts the encryption process for concurency operations readability
func (h *tokenService) encrypt(plaintext, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	enc, err := h.cryptor.EncryptServiceData([]byte(plaintext))
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*encrypted = enc
}

// PersistXref persists the xref between the authenticated uxsession and the access token.
func (s *tokenService) PersistXref(xref SessionAccessXref) error {

	// lightweight input validation: redundant, but good practice
	if xref.UxsessionId == "" || len(xref.UxsessionId) > 64 {
		return fmt.Errorf("failed to persist uxsession_accesstoken xref: %v", ErrInvalidSessionId)
	}

	if xref.AccessTokenId == "" || len(xref.AccessTokenId) > 64 {
		return fmt.Errorf("failed to persist uxsessionaccess_token xref: %v", ErrInvalidAccessTokenId)
	}

	// persist to database
	if err := s.db.InsertUxsessionAccessTknXref(xref); err != nil {
		return fmt.Errorf("failed to persist uxsession_accesstoken xref: %v", err)
	}

	return nil
}
