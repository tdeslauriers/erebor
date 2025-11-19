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

// container interface for multiple task specific interfaces
type Service interface {
	SessionService
	CsrfService
	TokenService
	SessionErrService
}

// SessionService is the interface for handling ux session specific operations.
type SessionService interface {
	// Build creates a new seesion record, persisting it to the database, and returns
	// the struct.  It builds both authenticated and unauthenticated sessions.
	// However, the authentication designation in the struct is just a convenience,
	// the presesnce of Access and Refresh tokens is the real indicator of authentication status.
	// If no access tokens exist, user will be redirected to login page.
	Build(st UxSessionType) (*UxSession, error)

	// IsValid checks if the session is valid, ie, not revoked, not expired, etc.
	IsValid(session string) (bool, error)

	// RevokeSession revokes the session.
	RevokeSession(session string) error

	// DestroySession deletes the session from the database and removes
	// all associated tokens, oauth state, xref records, etc.
	DestroySession(ctx context.Context, session string) error
}

// SessionErrService is the interface for handling ux session service and
// its underlying interfaces errors in a consistent way
type SessionErrService interface {

	// HandleSessionErr is a helper function to handle session errors in a consistent way
	HandleSessionErr(err error, w http.ResponseWriter)
}

// NewService creates a new instance of the container Session Service interface and returns a pointer to its concrete implementation.
func NewService(
	cfg *config.OauthRedirect,
	db data.SqlRepository,
	i data.Indexer,
	c data.Cryptor,
	p provider.S2sTokenProvider,
	call *connect.S2sCaller,
) Service {
	return &service{
		cfg:         cfg,
		db:          db,
		indexer:     i,
		cryptor:     c,
		s2sProvider: p,
		identity:    call,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentSession)),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface.
type service struct {
	cfg         *config.OauthRedirect // needed to populate client id for refresh requests
	db          data.SqlRepository
	indexer     data.Indexer
	cryptor     data.Cryptor
	s2sProvider provider.S2sTokenProvider
	identity    *connect.S2sCaller

	logger *slog.Logger
}

// Build creates a new seesion record, persisting it to the database, and returns the struct.  It builds both authenticated and unauthenticated sessions.
// However, the authentication designation in the struct is just a convenience, the presesnce of Access and Refresh tokens is the real indicator of authentication status.
// If no access tokens exist, user will be redirected to login page.
func (s *service) Build(st UxSessionType) (*UxSession, error) {

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

	qry := `INSERT INTO uxsession (uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, persist); err != nil {
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

// IsValid checks if the session is valid, ie, not revoked, not expired, etc.
func (s *service) IsValid(session string) (bool, error) {

	// light weight input validation
	if len(session) < 16 || len(session) > 64 {
		return false, errors.New(ErrInvalidSession)
	}

	// build session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return false, fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	// look up uxSession from db by index
	var uxSession UxSession
	qry := "SELECT uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?"
	if err := s.db.SelectRecord(qry, &uxSession, index); err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("session xxxxxx-%s - %s: %v", session[len(session)-6:], ErrSessionNotFound, err)
		}
		return false, err
	}

	// check if session is revoked
	if uxSession.Revoked {
		return false, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionRevoked)
	}

	// check if session is expired
	if uxSession.CreatedAt.UTC().Add(1 * time.Hour).Before(time.Now().UTC()) {
		return false, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionExpired)
	}

	return true, nil
}

// RevokeSession revokes the session
// Note: does not revoke access tokens or refresh tokens, that is done in the identity service
func (s *service) RevokeSession(session string) error {

	// light weight input validation
	if len(session) < 16 || len(session) > 64 {
		return errors.New(ErrInvalidSession)
	}

	// build session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	qry := "UPDATE uxsession SET revoked = ? WHERE session_index = ?"
	if err := s.db.UpdateRecord(qry, true, index); err != nil {
		return fmt.Errorf("failed to revok session xxxxxx-%s: %v", session[len(session)-6:], err)
	}

	return nil
}

// DestroySession deletes the session from the database and removes all associated tokens, oauth state, xref records, etc.
func (s *service) DestroySession(ctx context.Context, session string) error {

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
	var uxSession UxSession
	qry := "SELECT uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?"
	if err := s.db.SelectRecord(qry, &uxSession, index); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("session xxxxxx-%s - %s: %v", session[len(session)-6:], ErrSessionNotFound, err)
		}
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
	qry = "DELETE FROM uxsession WHERE session_index = ?"
	if err := s.db.DeleteRecord(qry, index); err != nil {
		return fmt.Errorf("failed to delete authenticated(%t) session id %s: %v", uxSession.Authenticated, uxSession.Id, err)
	}

	telemetryLogger.Info(fmt.Sprintf("successfully deleted authenticated(%t) session id %s", uxSession.Authenticated, uxSession.Id))

	return nil
}

// removeAccessTokens is a helper function to remove access tokens from the db if they exist and
// call the identity service to destroy the refresh token(s).
// Note: if no records exist, it will not push an error to the error channel, but will still decrement the wait group, and return.
func (s *service) removeAccessTokens(ctx context.Context, sessionId string, errChan chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// get logger from context
	telemetryLogger, ok := ctx.Value("telemetryLogger").(*slog.Logger)
	if !ok {
		s.logger.Warn("failed to extract telemetryLogger from context of removeAccessTokens call")
		telemetryLogger = s.logger // set to default logger if not found in context
	}

	live := make([]LiveAccessToken, 0, 32) // should be more than enough for most cases
	qry := `SELECT
				ua.id,
				ua.uxsession_uuid,
				ua.accesstoken_uuid,
				a.refresh_token
				FROM uxsession_accesstoken ua
					LEFT OUTER JOIN accesstoken a ON ua.accesstoken_uuid = a.uuid
				WHERE ua.uxsession_uuid = ?
					AND (
						a.access_expires > UTC_TIMESTAMP()
						OR (a.refresh_expires > UTC_TIMESTAMP()
							AND a.refresh_claimed = FALSE)
						)`
	if err := s.db.SelectRecords(qry, &live, sessionId); err != nil {
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
	var wgXref sync.WaitGroup
	for _, token := range live {
		// remove xref records
		wgXref.Add(1)
		go func(id int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			qry := "DELETE FROM uxsession_accesstoken WHERE id = ?"
			if err := s.db.DeleteRecord(qry, id); err != nil {
				ch <- fmt.Errorf("%s id %d: %v", ErrDeleteUxsessionAccesstokenXref, id, err)
			}

			telemetryLogger.Info(fmt.Sprintf("successfully removed uxsession_accesstoken xref id %d", id))
		}(token.Id, errChan, &wgXref)
	}

	// need to wait until xrefs deleted or foreign key constraint will prevent deletion of access token(s)
	wgXref.Wait()
	// errors collected to primary error channel

	for _, token := range live {

		// delete access token from local db
		wg.Add(1) // adding to primary wait group
		go func(id string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			qry := "DELETE FROM accesstoken WHERE uuid = ?"
			if err := s.db.DeleteRecord(qry, id); err != nil {
				ch <- fmt.Errorf("%s id/jti %s: %v", ErrDeleteAccessToken, id, err)
				return
			}

			telemetryLogger.Info(fmt.Sprintf("successfully removed access token id/jti %s", id))
		}(token.AccessTokenId, errChan, wg)

		// call identity service to destroy refresh token
		wg.Add(1) // adding to primary wait group
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
		}(token.RefreshToken, token.AccessTokenId, s2sToken, errChan, wg)
	}
}

// removeOauthFlow is a helper function to remove oauthflow and uxsession_oauthflow records from the db if they exist.
func (s *service) removeOauthFlow(sessionId string, errChan chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	oauthXref := make([]UxsesionOauthFlow, 0, 32)
	qry := "SELECT id, uxsession_uuid, oauthflow_uuid FROM uxsession_oauthflow WHERE uxsession_uuid = ?"
	if err := s.db.SelectRecords(qry, &oauthXref, sessionId); err != nil {
		errChan <- err
		return
	}

	if len(oauthXref) == 0 {
		s.logger.Info(fmt.Sprintf("session id %s has no oauth flows to remove", sessionId))
		return
	}

	// remove oauth flow records
	var wgXref sync.WaitGroup

	// remove xref records
	for _, xref := range oauthXref {
		// using the primary wait group
		wgXref.Add(1)
		go func(id int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			qry := "DELETE FROM uxsession_oauthflow WHERE id = ?"
			if err := s.db.DeleteRecord(qry, id); err != nil {
				ch <- fmt.Errorf("%s id %d: %v", ErrDeleteUxsessionOauthflowXref, id, err)
				return
			}

			s.logger.Info(fmt.Sprintf("successfully removed oauth flow id %d", id))
		}(xref.Id, errChan, &wgXref)
	}
	// need to wait until xrefs deleted or foreign key constraint will prevent deletion of oauth flow(s)
	wgXref.Wait()
	// errors collected to primary error channel

	for _, xref := range oauthXref {
		wg.Add(1) // adding to primary wait group
		go func(id string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			qry := "DELETE FROM oauthflow WHERE uuid = ?"
			if err := s.db.DeleteRecord(qry, id); err != nil {
				ch <- fmt.Errorf("%s id %s: %v", ErrDeleteOauthExchange, id, err)
				return
			}

			s.logger.Info(fmt.Sprintf("successfully removed oauthflow id %s", id))
		}(xref.OauthExchangeId, errChan, wg)
	}
}

// helper function to handle session errors in a consistent way
// HandleSessionErr implements the ErrService interface
func (s *service) HandleSessionErr(err error, w http.ResponseWriter) {

	switch {
	case strings.Contains(err.Error(), ErrInvalidSession):
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
