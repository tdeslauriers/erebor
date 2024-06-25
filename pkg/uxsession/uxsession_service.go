package uxsession

import (
	"erebor/internal/util"
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

type UxSessionService interface {
	// Build creates a new seesion record, persisting it to the database, and returns the struct.  It builds both authenticated and unauthenticated sessions.
	// However, the authentication designation in the struct is just a convenience, the presesnce of Access and Refresh tokens is the real indicator of authentication status.
	// If no access tokens exist, user will be redirected to login page.
	Build(UxSessionType) (*UxSession, error)
}

func NewUxSessionService(db data.SqlRepository, i data.Indexer, c data.Cryptor) UxSessionService {
	return &uxSessionService{
		db:      db,
		indexer: i,
		cryptor: c,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageSession)).With(slog.String(util.ComponentKey, util.ComponentUxSession)),
	}
}

var _ UxSessionService = (*uxSessionService)(nil)

type uxSessionService struct {
	db      data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

func (s *uxSessionService) Build(st UxSessionType) (*UxSession, error) {

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session uuid: %v", err)
	}

	// session token
	token, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %v", err)
	}

	encryptedToken, err := s.cryptor.EncryptServiceData(token.String())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt session token: %v", err)
	}

	// create session index for later retrieval
	index, err := s.indexer.ObtainBlindIndex(token.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create session index: %v", err)
	}

	// csrf token
	csrf, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate csrf token: %v", err)
	}

	encryptedCsrf, err := s.cryptor.EncryptServiceData(csrf.String())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt csrf token: %v", err)
	}

	curretnTime := time.Now()

	persist := &UxSession{
		Id:            id.String(),
		Index:         index,
		SessionToken:  encryptedToken,
		CsrfToken:     encryptedCsrf,
		CreatedAt:     data.CustomTime{Time: curretnTime},
		Authenticated: bool(st),
		Revoked:       false,
	}

	// tradeoff: opted to no block the response waiting for the db to persist the session record.  If the db fails, the session will be lost.
	go func() {
		qry := `INSERT INTO session (uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)`
		if err := s.db.InsertRecord(qry, persist); err != nil {
			s.logger.Error("failed to persist session record", "err", err.Error())
		}
	}()

	// only returning values needed by FE
	return &UxSession{
		SessionToken:  token.String(),
		CreatedAt:     data.CustomTime{Time: curretnTime},
		Authenticated: bool(st),
	}, nil
}
