package uxsession

import (
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
	ErrInvalidSessionId = "invalid or not well formed session id"

	// 401
	ErrSessionRevoked = "session is revoked"
	ErrSessionExpired = "session is expired"
	ErrTokenMismatch  = "decrypted session token does not match session provided"

	// 500
	ErrGenSessionUuid  = "failed to generate session uuid"
	ErrGenSessionToken = "failed to generate session token"
	ErrGenIndex        = "failed to generate session index"
	ErrGenCsrfToken    = "failed to generate csrf token"

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
		return nil, errors.New(ErrInvalidSessionId)
	}

	// re generate session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return nil, err
	}

	// look up uxSession from db by index
	var uxSession UxSession
	qry := "SELECT uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?"
	if err := s.db.SelectRecord(qry, &uxSession, index); err != nil {
		return nil, err
	}

	// check if session is revoked before decyption:
	if uxSession.Revoked {
		return nil, errors.New(ErrSessionRevoked)
	}

	// check if session is expired before decryption:
	if uxSession.CreatedAt.Add(time.Hour).Before(time.Now()) {
		return nil, errors.New(ErrSessionExpired)
	}

	// decrypt session token
	sessionToken, err := s.cryptor.DecryptServiceData(uxSession.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrDecryptSession, err)
	}
	// check if decrypted session token matches session provided
	if sessionToken != session {
		// this should never happen
		return nil, errors.New(ErrTokenMismatch)
	}

	// decrypt csrf token
	csrfToken, err := s.cryptor.DecryptServiceData(uxSession.CsrfToken)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrDecryptCsrf, err)
	}

	return &UxSession{
		SessionToken:  sessionToken,
		CsrfToken:     csrfToken,
		CreatedAt:     uxSession.CreatedAt,
		Authenticated: uxSession.Authenticated,
	}, nil
}
