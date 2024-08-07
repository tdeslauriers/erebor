package uxsession

import (
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
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
)

// frontend only every sees session and csrf tokens,
// the rest of theses fields are internal metadata for the gateway
type UxSession struct {
	Id            string          `json:"id,omitempty" db:"uuid"`
	Index         string          `json:"session_index,omitempty" db:"session_index"`
	SessionToken  string          `json:"session_token" db:"session_token"`
	CsrfToken     string          `json:"csrf_token,omitempty" db:"csrf_token"`
	CreatedAt     data.CustomTime `json:"created_at" db:"created_at"`
	Authenticated bool            `json:"authenticated" db:"authenticated"` // convenience field, not used for actual auth decisions
	Revoked       bool            `json:"revoked,omitempty" db:"revoked"`
}

type UxSessionType bool

const (
	Anonymous     UxSessionType = false
	Authenticated UxSessionType = true
)

type SessionService interface {
	// Build creates a new seesion record, persisting it to the database, and returns the struct.  It builds both authenticated and unauthenticated sessions.
	// However, the authentication designation in the struct is just a convenience, the presesnce of Access and Refresh tokens is the real indicator of authentication status.
	// If no access tokens exist, user will be redirected to login page.
	Build(UxSessionType) (*UxSession, error)

	// GetCsrf returns a csrf token for the given session id.
	GetCsrf(session string) (*UxSession, error)

	// ValidateCsrt validates the csrf token provided is attached to the session token.
	IsValidCsrf(session, csrf string) (bool, error)

	// RevokeSession revokes the session and all associated access tokens if they exist.
	// Note: this will often be used to revoke the anonymous session upon successful login.
	RevokeSession(session string) error
}

type SessionErrService interface {
	// HandleSessionErr is a helper function to handle session errors in a consistent way
	HandleSessionErr(err error, w http.ResponseWriter)
}

type Service interface {
	SessionService
	TokenService
	SessionErrService
}

func NewService(db data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		db:      db,
		indexer: i,
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentUxSession)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db      data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

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
		e, err := s.cryptor.EncryptServiceData(t.String())
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
		e, err := s.cryptor.EncryptServiceData(c.String())
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

	curretnTime := time.Now()

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

	// only returning values needed by FE
	return &UxSession{
		SessionToken:  token.String(),
		CreatedAt:     data.CustomTime{Time: curretnTime},
		Authenticated: bool(st),
	}, nil
}

// implements GetCsrf of Service interface
func (s *service) GetCsrf(session string) (*UxSession, error) {

	// light weight input validation (not checking if session id is valid or well-formed)
	if len(session) < 16 || len(session) > 64 {
		return nil, errors.New(ErrInvalidSession)
	}

	// re generate session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return nil, fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	// look up uxSession from db by index
	var uxSession UxSession
	qry := "SELECT uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?"
	if err := s.db.SelectRecord(qry, &uxSession, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session xxxxxx-%s - %s: %v", session[len(session)-6:], ErrSessionNotFound, err)
		}
		return nil, err
	}

	// check if session is revoked before decyption:
	if uxSession.Revoked {
		return nil, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionRevoked)
	}

	// check if session is expired before decryption:
	if uxSession.CreatedAt.Add(1 * time.Hour).Before(time.Now().UTC()) {
		return nil, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionExpired)
	}

	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 2)

		sessionToken string
		csrfToken    string
	)

	wg.Add(2)
	go s.decrypt(uxSession.SessionToken, &sessionToken, errChan, &wg)
	go s.decrypt(uxSession.CsrfToken, &csrfToken, errChan, &wg)

	wg.Wait()
	close(errChan)

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
		return nil, fmt.Errorf("failed to get csrf token: %s", builder.String())
	}

	return &UxSession{
		SessionToken:  sessionToken,
		CsrfToken:     csrfToken,
		CreatedAt:     uxSession.CreatedAt,
		Authenticated: uxSession.Authenticated,
	}, nil
}

func (s *service) decrypt(encrypted string, decrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	d, err := s.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("failed to decrypt: %v", err)
		return
	}

	*decrypted = d
}

// implements ValidateCsrf of Service interface
// csrf tokens are single use, so this function will delete the token from the db after validation
// and assign a new one (asyncronously, so the user doesn't have to wait for the db write to complete)
func (s *service) IsValidCsrf(session, csrf string) (bool, error) {

	// light weight input validation)
	if len(session) < 16 || len(session) > 64 {
		return false, errors.New(ErrInvalidSession)
	}

	if len(csrf) < 16 || len(csrf) > 64 {
		return false, errors.New(ErrInvalidCsrf)
	}

	// regenerate index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return false, fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	var uxSession UxSession
	qry := "SELECT uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?"
	if err := s.db.SelectRecord(qry, &uxSession, index); err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("session xxxxxx-%s - %s: %v", session[len(session)-6:], ErrSessionNotFound, err)
		}
		return false, err
	}

	// check if session is revoked before decryption:
	if uxSession.Revoked {
		return false, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionRevoked)
	}

	// check if session is expired before decryption:
	if uxSession.CreatedAt.Add(time.Hour).Before(time.Now().UTC()) {
		return false, fmt.Errorf("session id %s: %s", uxSession.Id, ErrSessionExpired)
	}

	// decrypt csrf token
	decrypted, err := s.cryptor.DecryptServiceData(uxSession.CsrfToken)
	if err != nil {
		return false, fmt.Errorf("%s - %s: %v", uxSession.Id, ErrDecryptCsrf, err)
	}

	// check if csrf token matches
	// return error if not
	if decrypted != csrf {
		return false, fmt.Errorf("session id %s - xxxxxx-%s vs xxxxxx-%s: %s", uxSession.Id, decrypted[len(decrypted)-6:], csrf[len(csrf)-6:], ErrCsrfMismatch)
	}

	// generate a new csrf token and persist it to the db
	// perist concurrently so returns immediately on validation
	// if this fails, the old csrf token will still be valid
	// for the length of the session which is only an hour.
	go func() {

		csrf, err := uuid.NewRandom()
		if err != nil {
			s.logger.Error(fmt.Sprintf("session id %s - failed to generated replacement csrf token: %s", uxSession.Id, ErrGenCsrfToken))
			return
		}

		encryptedCsrf, err := s.cryptor.EncryptServiceData(csrf.String())
		if err != nil {
			s.logger.Error(fmt.Sprintf("session id %s - failed to encrypt replacement csrf token: %s", uxSession.Id, ErrEncryptCsrf))
			return
		}

		// update db
		qry := "UPDATE uxsession SET csrf_token = ? WHERE session_index = ?"
		if err := s.db.UpdateRecord(qry, encryptedCsrf, index); err != nil {
			s.logger.Error(fmt.Sprintf("session id %s - failed to update (replace used) csrf token in db", uxSession.Id), "err", err.Error())
			return
		}

		// log success
		s.logger.Info(fmt.Sprintf("session id %s - successfully updated/replaced csrf token in db", uxSession.Id))
	}()

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

// helper function to handle session errors in a consistent way
// HandleSessionErr implements the ErrService interface
func (s *service) HandleSessionErr(err error, w http.ResponseWriter) {

	switch {
	case strings.Contains(err.Error(), ErrInvalidSession):
	case strings.Contains(err.Error(), ErrInvalidCsrf):
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
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
	case strings.Contains(err.Error(), ErrCsrfMismatch):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrCsrfMismatch,
		}
		e.SendJsonErr(w)
		return
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get csrf token",
		}
		e.SendJsonErr(w)
		return
	}
}
