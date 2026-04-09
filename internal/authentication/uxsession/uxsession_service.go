package uxsession

import (
	"context"
	"database/sql"
	"erebor/internal/util"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

// SessionService is the interface for handling ux session specific operations.
type SessionService interface {
	// Build creates a new seesion record, persisting it to the database, and returns
	// the struct.  It builds both authenticated and unauthenticated sessions.
	// However, the authentication designation in the struct is just a convenience,
	// the presesnce of Access and Refresh tokens is the real indicator of authentication status.
	// If no access tokens exist, user will be redirected to login page.
	Build(st UxSessionType) (*UxSession, error)

	// GetValidSession returns the session struct for a given session token if
	// it is valid, ie, not revoked or exired, otherwise returns an error.
	GetValidSession(session string) (*UxSession, error)

	// IsValid checks if the session is valid, ie, not revoked, not expired, etc.
	IsValid(session string) (bool, error)

	// RevokeSession revokes the session.
	RevokeSession(session string) error

	// DestroySession deletes the session from the database and removes
	// all associated tokens, oauth state, xref records, etc.
	DestroySession(ctx context.Context, session string) error
}

// NewService creates a new instance of the container Session Service interface and returns a pointer to its concrete implementation.
func NewSessionService(
	cfg *config.OauthRedirect,
	db *sql.DB,
	i data.Indexer,
	c data.Cryptor,
	p provider.S2sTokenProvider,
	call *connect.S2sCaller,
) SessionService {
	return &uxSession{
		cfg:         cfg,
		db:          NewSessionRepository(db),
		indexer:     i,
		cryptor:     c,
		s2sProvider: p,
		identity:    call,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentSession)),
	}
}

var _ SessionService = (*uxSession)(nil)

// service is the concrete implementation of the Service interface.
type uxSession struct {
	cfg         *config.OauthRedirect // needed to populate client id for refresh requests
	db          SessionRepository
	indexer     data.Indexer
	cryptor     data.Cryptor
	s2sProvider provider.S2sTokenProvider
	identity    *connect.S2sCaller

	logger *slog.Logger
}

// Build creates a new seesion record, persisting it to the database, and returns the struct.  It builds both authenticated and unauthenticated sessions.
// However, the authentication designation in the struct is just a convenience, the presesnce of Access and Refresh tokens is the real indicator of authentication status.
// If no access tokens exist, user will be redirected to login page.
func (s *uxSession) Build(st UxSessionType) (*UxSession, error) {

	var (
		wg sync.WaitGroup

		id             uuid.UUID
		token          uuid.UUID
		index          string
		encryptedToken string
		csrf           uuid.UUID
		encryptedCsrf  string

		errChan = make(chan error, 3)
	)

	// create primary key
	wg.Add(1)
	go func(id *uuid.UUID, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("%s: %v", ErrGenSessionUuid, err)
			return
		}
		*id = i
	}(&id, errChan, &wg)

	// create session token
	wg.Add(1)
	go func(token *uuid.UUID, index, encrypted *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		t, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("%s: %v", ErrGenSessionToken, err)
			return
		}

		*token = t

		// create session index for later retrieval
		i, err := s.indexer.ObtainBlindIndex(t.String())
		if err != nil {
			ch <- fmt.Errorf("%s: %v", ErrGenIndex, err)
			return
		}

		*index = i

		// encrypt session token
		e, err := s.cryptor.EncryptServiceData([]byte(t.String()))
		if err != nil {
			ch <- fmt.Errorf("%s: %v", ErrEncryptSession, err)
			return
		}

		*encrypted = e

	}(&token, &index, &encryptedToken, errChan, &wg)

	// create csrf token
	wg.Add(1)
	go func(csrf *uuid.UUID, encrypted *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		c, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("%s: %v", ErrGenCsrfToken, err)
			return
		}

		*csrf = c

		// encrypt csrf token
		e, err := s.cryptor.EncryptServiceData([]byte(c.String()))
		if err != nil {
			ch <- fmt.Errorf("%s: %v", ErrEncryptCsrf, err)
			return
		}

		*encrypted = e

	}(&csrf, &encryptedCsrf, errChan, &wg)

	wg.Wait()
	close(errChan)

	// check for errors
	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errChan {
			builder.WriteString(err.Error())
			if count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return nil, fmt.Errorf("failed to build session: %s", builder.String())
	}

	curretnTime := time.Now().UTC()

	persist := UxSession{
		Id:            id.String(),
		Index:         index,
		SessionToken:  encryptedToken,
		CsrfToken:     encryptedCsrf,
		CreatedAt:     data.CustomTime{Time: curretnTime},
		Authenticated: bool(st),
		Revoked:       false,
	}

	if err := s.db.InsertUxSession(persist); err != nil {
		return nil, err
	}

	return &UxSession{
		Id:            id.String(),
		Index:         index,
		SessionToken:  token.String(),
		CsrfToken:     csrf.String(),
		CreatedAt:     data.CustomTime{Time: curretnTime},
		Authenticated: bool(st),
		Revoked:       false,
	}, nil
}

// GetValidSession returns the session struct for a given session token if
// it is valid, ie, not revoked or exired, otherwise returns an error.
func (s *uxSession) GetValidSession(session string) (*UxSession, error) {

	return s.getValidSession(session)
}

// getValidSession returns the session struct for a given session token if
// it is valid, ie, not revoked or exired, otherwise returns an error.  It is a helper function for GetValidSession and GetSessionData, which both call this function to get the session struct before doing additional work.
func (s *uxSession) getValidSession(session string) (*UxSession, error) {

	// light weight input validation
	if len(session) < 16 || len(session) > 64 {
		return nil, errors.New(ErrInvalidSession)
	}

	// build session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return nil, fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	// look up uxSession from db by index
	uxSession, err := s.db.FindSession(index)
	if err != nil {
		return nil, err
	}

	// check if session is revoked
	if uxSession.Revoked {
		return nil, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionRevoked)
	}

	// check if session is expired
	if uxSession.CreatedAt.UTC().Add(1 * time.Hour).Before(time.Now().UTC()) {
		return nil, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionExpired)
	}

	// check if authenticated
	// Note: this is a convenience field, the real indicator is if access tokens are
	// associated with the session
	// just a quick sanity check only
	// if !uxSession.Authenticated {
	// 	return nil, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionNotAuthenticated)
	// }

	var (
		wg        sync.WaitGroup
		sessionCh = make(chan string, 1)
		csrfCh    = make(chan string, 1)

		errCh = make(chan error, 2)
	)

	wg.Add(1)
	go func(encrypted string, sessionCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// decrypt session token
		token, err := s.cryptor.DecryptServiceData(uxSession.SessionToken)
		if err != nil {
			errCh <- fmt.Errorf("%s for session id %s: %v", ErrDecryptSession, uxSession.Id, err)
			return
		}

		sessionCh <- string(token)
	}(uxSession.SessionToken, sessionCh, errCh, &wg)

	wg.Add(1)
	go func(encrypted string, csrfCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// need to decyrpt csrf token for caller to verify it against user provided csrf
		csrf, err := s.cryptor.DecryptServiceData(uxSession.CsrfToken)
		if err != nil {
			errCh <- fmt.Errorf("%s for session id %s: %v", ErrDecryptCsrf, uxSession.Id, err)
			return
		}

		csrfCh <- string(csrf)
	}(uxSession.CsrfToken, csrfCh, errCh, &wg)

	wg.Wait()
	close(sessionCh)
	close(csrfCh)
	close(errCh)

	// check for errors
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to decrypt session data for session id %s: %v", uxSession.Id, errors.Join(errs...))
	}

	// check for empty strings which would indicate decryption failure, and thus invalid session
	// check for decryption failure (channel closed without value) or empty decrypted token
	sessionToken, ok := <-sessionCh
	if !ok || sessionToken == "" {
		return nil, fmt.Errorf("session id %s: %s", uxSession.Id, "session token decryption failed")
	}
	uxSession.SessionToken = sessionToken

	// check for decryption failure (channel closed without value) or empty decrypted csrf
	csrfToken, ok := <-csrfCh
	if !ok || csrfToken == "" {
		return nil, fmt.Errorf("session id %s: %s", uxSession.Id, "csrf token decryption failed")
	}
	uxSession.CsrfToken = csrfToken

	return uxSession, nil
}

// IsValid checks if the session is valid, ie, not revoked, not expired, etc.
func (s *uxSession) IsValid(session string) (bool, error) {

	_, err := s.getValidSession(session)
	if err != nil {
		return false, err
	}

	return true, nil
}

// RevokeSession revokes the session
// Note: does not revoke access tokens or refresh tokens, that is done in the identity service
func (s *uxSession) RevokeSession(session string) error {

	// light weight input validation
	if len(session) < 16 || len(session) > 64 {
		return errors.New(ErrInvalidSession)
	}

	// build session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	if err := s.db.UpdateRevoked(index, true); err != nil {
		return fmt.Errorf("failed to revoke session xxxxxx-%s: %v", session[len(session)-6:], err)
	}

	return nil
}

// DestroySession deletes the session from the database and removes all associated tokens, oauth state, xref records, etc.
func (s *uxSession) DestroySession(ctx context.Context, session string) error {

	// get telemtry from context
	telemetry, ok := connect.GetTelemetryFromContext(ctx)
	if !ok {
		s.logger.Warn("failed to extract telemetry from context of DestroySession call")
	}

	// add telemtry fields to logger if exists
	telemetryLogger := s.logger
	if telemetry != nil {
		telemetryLogger = telemetryLogger.With(telemetry.TelemetryFields()...)
	}

	// add telemetryLogger to context for call stack
	ctx = context.WithValue(ctx, connect.TelemetryLoggerKey, telemetryLogger)

	// light weight input validation
	if len(session) < 16 || len(session) > 64 {
		return errors.New(ErrInvalidSession)
	}

	// build session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	// look up session by index
	uxSession, err := s.db.FindSession(index)
	if err != nil {
		return fmt.Errorf("failed to look up session xxxxxx-%s: %v", session[len(session)-6:], err)
	}

	// get xref records
	var (
		wgXrefs sync.WaitGroup
		errChan = make(chan error, 2)
	)

	wgXrefs.Add(2)
	go s.removeAccessTokens(ctx, uxSession.Id, errChan, &wgXrefs)
	go s.removeOauthFlow(uxSession.Id, errChan, &wgXrefs)

	wgXrefs.Wait()
	close(errChan)

	errCount := len(errChan)
	if errCount > 0 {
		var builder strings.Builder
		count := 0
		for err := range errChan {
			builder.WriteString(err.Error())
			if count < errCount-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return fmt.Errorf("failed to remove xrefs for authenticated(%t) session id %s: %s", uxSession.Authenticated, uxSession.Id, builder.String())
	}

	// delete session
	if err := s.db.DeleteSession(index); err != nil {
		return fmt.Errorf("failed to delete authenticated(%t) session id %s: %v", uxSession.Authenticated, uxSession.Id, err)
	}

	telemetryLogger.Info(fmt.Sprintf("successfully deleted authenticated(%t) session id %s", uxSession.Authenticated, uxSession.Id))

	return nil
}

// removeAccessTokens is a helper function to remove access tokens from the db if they exist and
// call the identity service to destroy the refresh token(s).
// Note: if no records exist, it will not push an error to the error channel, but will still decrement the wait group, and return.
func (s *uxSession) removeAccessTokens(ctx context.Context, sessionId string, errChan chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// get logger from context
	telemetryLogger, ok := ctx.Value(connect.TelemetryLoggerKey).(*slog.Logger)
	if !ok {
		s.logger.Warn("failed to extract telemetryLogger from context of removeAccessTokens call")
		telemetryLogger = s.logger // set to default logger if not found in context
	}

	// find live access tokens for session in db
	live, err := s.db.FindLiveAccessTokens(sessionId)
	if err != nil {
		errChan <- err
		return
	}

	if len(live) == 0 {
		telemetryLogger.Info(fmt.Sprintf("session id %s has no access/refresh tokens to remove", sessionId))
		return
	}

	// get s2s token for calling identity service
	s2sToken, err := s.s2sProvider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		errChan <- fmt.Errorf("session id xxxxxx-%s - failed to retreive s2s token to call identity service: %v", sessionId[len(sessionId)-6:], err)
		return
	}

	// remove xref records
	var (
		xrefWg      sync.WaitGroup
		xrefErrChan = make(chan error, len(live)) // buffer size of number of live tokens since in worst case we could have an error for each token
	)

	for _, token := range live {
		// remove xref records
		xrefWg.Add(1)
		go func(id int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			if err := s.db.DeleteSessionAccessXref(id); err != nil {
				ch <- fmt.Errorf("%s id %d: %v", ErrDeleteUxsessionAccesstokenXref, id, err)
			}

			telemetryLogger.Info(fmt.Sprintf("successfully removed uxsession_accesstoken xref id %d", id))
		}(token.Id, xrefErrChan, &xrefWg)
	}

	// need to wait until xrefs deleted or foreign key constraint will prevent deletion of access token(s)
	xrefWg.Wait()
	close(xrefErrChan)

	// check for xref deletion errors before proceeding to delete access tokens and call identity service to destroy refresh tokens
	if len(xrefErrChan) > 0 {
		var errs []error
		for err := range xrefErrChan {
			errs = append(errs, err)
		}
		errChan <- fmt.Errorf("failed to delete session_access_token xrefs for session id %s: %v", sessionId, errors.Join(errs...))
		return
	}

	// remove access tokens and call identity service to destroy refresh tokens
	var (
		accessTokenWg sync.WaitGroup
		accessErrChan = make(chan error, len(live)) // buffer size of number of live tokens since in worst case we could have an error for each token
	)

	for _, token := range live {

		// delete access token from local db
		accessTokenWg.Add(1) // adding to primary wait group
		go func(id string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			if err := s.db.DeleteAccessToken(id); err != nil {
				ch <- fmt.Errorf("%s id/jti %s: %v", ErrDeleteAccessToken, id, err)
				return
			}

			telemetryLogger.Info(fmt.Sprintf("successfully removed access token id/jti %s", id))
		}(token.AccessTokenId, accessErrChan, &accessTokenWg)

		// call identity service to destroy refresh token
		accessTokenWg.Add(1) // adding to primary wait group
		go func(encrypted, jti, s2sBearer string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			// decrypt refresh token
			refresh, err := s.cryptor.DecryptServiceData(encrypted)
			if err != nil {
				ch <- fmt.Errorf("failed to decrypt refresh token for access token id/jti %s: %v", jti, err)
				return
			}

			// send cmd to identity service to destroy refresh token
			_, err = connect.PostToService[types.DestroyRefreshCmd, struct{}](
				ctx,
				s.identity,
				"/refresh/destroy",
				s2sBearer,
				"",
				types.DestroyRefreshCmd{DestroyRefreshToken: string(refresh)},
			)
			if err != nil {
				ch <- fmt.Errorf("call to identity service /refresh/destroy endpoint failed: %v", err)
				return
			}

			telemetryLogger.Info(fmt.Sprintf("successfully destroyed refresh token xxxxxx-%s", refresh[len(refresh)-6:]))
		}(token.RefreshToken, token.AccessTokenId, s2sToken, accessErrChan, &accessTokenWg)
	}

	accessTokenWg.Wait()
	close(accessErrChan)

	// check for access token deletion and identity service call errors
	if len(accessErrChan) > 0 {
		var errs []error
		for err := range accessErrChan {
			errs = append(errs, err)
		}
		errChan <- fmt.Errorf("failed to delete access tokens and/or destroy refresh tokens for session id %s: %v", sessionId, errors.Join(errs...))
		return
	}
}

// removeOauthFlow is a helper function to remove oauthflow and uxsession_oauthflow records from the db if they exist.
func (s *uxSession) removeOauthFlow(sessionId string, errChan chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// get session oauth xref records from db
	oauthXref, err := s.db.FindSessionOauthXrefs(sessionId)
	if err != nil {
		errChan <- err
		return
	}

	if len(oauthXref) == 0 {
		s.logger.Info(fmt.Sprintf("session id %s has no oauth flows to remove", sessionId))
		return
	}

	// remove oauth flow records
	var (
		xrefWg      sync.WaitGroup
		xrefErrChan = make(chan error, len(oauthXref))
	)

	// remove xref records
	for _, xref := range oauthXref {
		// using the primary wait group
		xrefWg.Add(1)
		go func(id int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			if err := s.db.DeleteSessionOauthXref(id); err != nil {
				ch <- fmt.Errorf("%s id %d: %v", ErrDeleteUxsessionOauthflowXref, id, err)
				return
			}

			s.logger.Info(fmt.Sprintf("successfully removed oauth flow id %d", id))
		}(xref.Id, xrefErrChan, &xrefWg)
	}

	// need to wait until xrefs deleted or foreign key constraint will prevent deletion of oauth flow(s)
	xrefWg.Wait()
	close(xrefErrChan)

	// check for xref deletion errors before proceeding to delete oauth flows
	if len(xrefErrChan) > 0 {
		var errs []error
		for err := range xrefErrChan {
			errs = append(errs, err)
		}
		errChan <- fmt.Errorf("failed to delete session_oauthflow xrefs for session id %s: %v", sessionId, errors.Join(errs...))
		return
	}

	var (
		oauthWg      sync.WaitGroup
		oauthErrChan = make(chan error, len(oauthXref))
	)

	for _, xref := range oauthXref {
		oauthWg.Add(1) // adding to primary wait group
		go func(id string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			if err := s.db.DeleteOauthflow(id); err != nil {
				ch <- fmt.Errorf("%s id %s: %v", ErrDeleteOauthExchange, id, err)
				return
			}

			s.logger.Info(fmt.Sprintf("successfully removed oauthflow id %s", id))
		}(xref.OauthExchangeId, oauthErrChan, &oauthWg)
	}

	oauthWg.Wait()
	close(oauthErrChan)

	// check for oauth flow deletion errors
	if len(oauthErrChan) > 0 {
		var errs []error
		for err := range oauthErrChan {
			errs = append(errs, err)
		}
		errChan <- fmt.Errorf("failed to delete oauthflow records for session id %s: %v", sessionId, errors.Join(errs...))
		return
	}
}

// SessionErrService is the interface for handling ux session service and
// its underlying interfaces errors in a consistent way
type SessionErrService interface {

	// HandleSessionErr is a helper function to handle session errors in a consistent way
	HandleSessionErr(err error, w http.ResponseWriter)
}

// NewSessionErrService creates a new instance of the SessionErrService interface and returns a pointer to its concrete implementation.
func NewSessionErrService() SessionErrService {
	return &errService{}
}

var _ SessionErrService = (*errService)(nil)

type errService struct{}

// helper function to handle session errors in a consistent way
// HandleSessionErr implements the ErrService interface
func (s *errService) HandleSessionErr(err error, w http.ResponseWriter) {

	switch {
	case strings.Contains(err.Error(), ErrInvalidSession):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrInvalidSession,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrInvalidCsrf):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionRevoked):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionRevoked,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionExpired):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionNotFound,
		}
		e.SendJsonErr(w)
	case strings.Contains(err.Error(), ErrSessionNotAuthenticated):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionNotAuthenticated,
		}
		e.SendJsonErr(w)
	case strings.Contains(err.Error(), ErrCsrfMismatch):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrCsrfMismatch,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrAccessRefreshNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrAccessRefreshNotFound,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrAccessTokenNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrAccessTokenNotFound,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrAccessTokenExpired):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrAccessTokenExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrAccessTokenRevoked):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrAccessTokenRevoked,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrRefreshNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrRefreshNotFound,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrRefreshTokenExpired):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrRefreshTokenExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrRefreshTokenClaimed):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrRefreshTokenClaimed,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrRefreshTokenRevoked):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrRefreshTokenRevoked,
		}
		e.SendJsonErr(w)
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
