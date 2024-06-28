package csrf

import (
	"erebor/internal/util"
	"erebor/pkg/uxsession"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
)

type Service interface {

	// GetCsrf returns a csrf token for the given session id.
	GetCsrf(sessionToken string) (*uxsession.UxSession, error)
}

func NewService(db data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		db:      db,
		indexer: i,
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentCsrf)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	db      data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

// errors
const (
	// 422
	ErrInvalidSessionId string = "invalid or not well formed session id"

	// 401
	ErrSessionRevoked = "session is revoked"
	ErrSessionExpired = "session is expired"
	ErrTokenMismatch = "decrypted session token does not match session provided"

	// 500
	ErrDecryptSession = "failed to decrypt session token"
	ErrDecryptCsrf    = "failed to decrypt csrf token"
)

// implements GetCsrf of Service interface
func (s *service) GetCsrf(session string) (*uxsession.UxSession, error) {

	// light weight input validation (not checking if session id is valid or well-formed)
	if len(session) < 16 || len(session) > 64 {
		return nil, errors.New("invalid or not well formed session id")
	}

	// re generate session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return nil, err
	}

	// look up uxSession from db by index
	var uxSession uxsession.UxSession
	qry := "SELECT uuid, seesion_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?"
	if err := s.db.SelectRecord(qry, &uxSession, index); err != nil {
		return nil, err
	}

	// check if session is revoked before decyption:
	if uxSession.Revoked {
		return nil, errors.New("session is revoked")
	}

	// check session is not expired
	if uxSession.CreatedAt.Add(time.Hour).Before(time.Now()) {
		return nil, errors.New("session is expired")
	}

	// decrypt session token
	sessionToken, err := s.cryptor.DecryptServiceData(uxSession.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session token: %v", err)
	}
	if sessionToken != session {
		// this should never happen
		return nil, errors.New("decrypted session token does not match session provided")
	}

	// decrypt csrf token
	csrfToken, err := s.cryptor.DecryptServiceData(uxSession.CsrfToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt csrf token: %v", err)
	}

	return &uxsession.UxSession{
		SessionToken:  sessionToken,
		CsrfToken:     csrfToken,
		CreatedAt:     uxSession.CreatedAt,
		Authenticated: uxSession.Authenticated,
	}, nil
}
