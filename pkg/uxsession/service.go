package uxsession

import (
	"database/sql"
	"erebor/internal/util"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
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

type Service interface {
	// Build creates a new seesion record, persisting it to the database, and returns the struct.  It builds both authenticated and unauthenticated sessions.
	// However, the authentication designation in the struct is just a convenience, the presesnce of Access and Refresh tokens is the real indicator of authentication status.
	// If no access tokens exist, user will be redirected to login page.
	Build(UxSessionType) (*UxSession, error)

	// GetCsrf returns a csrf token for the given session id.
	GetCsrf(session string) (*UxSession, error)

	// ValidateCsrt validates the csrf token provided is attached to the session token.
	IsValidCsrf(session, csrf string) (bool, error)
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

const (
	// 422
	ErrInvalidSession = "invalid or not well formed session token"
	ErrInvalidCsrf    = "invalid or not well formed csrf token"

	// 401
	ErrSessionRevoked  = "session is revoked"
	ErrSessionExpired  = "session is expired"
	ErrSessionNotFound = "session not found"

	ErrCsrfMismatch = "decryped csrf token does not match csrf provided"

	// 500
	ErrGenSessionUuid         = "failed to generate session uuid"
	ErrGenSessionToken        = "failed to generate session token"
	ErrGenIndex        string = "failed to generate session index"
	ErrGenCsrfToken           = "failed to generate csrf token"

	ErrEncryptSession = "failed to encrypt session token"
	ErrEncryptCsrf    = "failed to encrypt csrf token"

	ErrDecryptSession = "failed to decrypt session token"
	ErrDecryptCsrf    = "failed to decrypt csrf token"
)

func (s *service) Build(st UxSessionType) (*UxSession, error) {

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrGenSessionUuid, err)
	}

	// session token
	token, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s %v", ErrGenSessionToken, err)
	}

	encryptedToken, err := s.cryptor.EncryptServiceData(token.String())
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrEncryptSession, err)
	}

	// create session index for later retrieval
	index, err := s.indexer.ObtainBlindIndex(token.String())
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrGenIndex, err)
	}

	// csrf token
	csrf, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrGenCsrfToken, err)
	}

	encryptedCsrf, err := s.cryptor.EncryptServiceData(csrf.String())
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrDecryptCsrf, err)
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

	// decrypt session token
	sessionToken, err := s.cryptor.DecryptServiceData(uxSession.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("sesion id %s - %s: %v", uxSession.Id, ErrDecryptSession, err)
	}

	// decrypt csrf token
	csrfToken, err := s.cryptor.DecryptServiceData(uxSession.CsrfToken)
	if err != nil {
		return nil, fmt.Errorf("session id %s - %s: %v", uxSession.Id, ErrDecryptCsrf, err)
	}

	return &UxSession{
		SessionToken:  sessionToken,
		CsrfToken:     csrfToken,
		CreatedAt:     uxSession.CreatedAt,
		Authenticated: uxSession.Authenticated,
	}, nil
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
			s.logger.Error(fmt.Sprintf("session id %s - replace used csrf token: %s", uxSession.Id, ErrGenCsrfToken))
			return
		}

		encryptedCsrf, err := s.cryptor.EncryptServiceData(csrf.String())
		if err != nil {
			s.logger.Error(fmt.Sprintf("session id %s - replace used csrf token: %s", uxSession.Id, ErrEncryptCsrf))
			return
		}

		// update db
		qry := "UPDATE uxsession SET csrf_token = ? WHERE session_index = ?"
		if err := s.db.UpdateRecord(qry, encryptedCsrf, index); err != nil {
			s.logger.Error(fmt.Sprintf("session id %s - failed to update (replace used) csrf token in db", uxSession.Id), "err", err.Error())
			return
		}

		// log success
		s.logger.Info(fmt.Sprintf("session id %s - successfully updated csrf token in db", session))
	}()

	return true, nil
}
