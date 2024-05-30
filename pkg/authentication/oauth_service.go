package authentication

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
)

type OauthExchange struct {
	Id          string          `json:"id,omitempty" db:"id"`
	Nonce       string          `json:"nonce" db:"nonce"`
	State       string          `json:"state" db:"state"`
	RedirectUrl string          `json:"redirect_url" db:"redirect_url"`
	CreatedAt   data.CustomTime `json:"created_at" db:"created_at"`
}

type OauthService interface {
	Create(redirect string) (*OauthExchange, error)
	Valiadate(oauth OauthExchange) error
}

// NewOauthService creates a new instance of the login service
func NewOauthService(db data.SqlRepository, cryptor data.Cryptor) OauthService {
	return &oauthService{
		db:      db,
		cryptor: cryptor,
	}
}

var _ OauthService = (*oauthService)(nil)

type oauthService struct {
	db      data.SqlRepository
	cryptor data.Cryptor
}

// CreateOauthExchange creates a new oauth exchange record, persisting it to the database,
// and returns the struct for use by the login handler to send to authentication service
func (s *oauthService) Create(redirect string) (*OauthExchange, error) {

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange uuid: %v", err)
	}

	nonce, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange nonce uuid: %v", err)
	}
	encryptedNonce, err := s.cryptor.EncyptServiceData(nonce.String())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange nonce for storage: %v", err)
	}

	state, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange state uuid: %v", err)
	}
	encryptedState, err := s.cryptor.EncyptServiceData(state.String())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange state for storage: %v", err)
	}

	encryptedRedirect, err := s.cryptor.EncyptServiceData(redirect)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange redirect url for storage: %v", err)
	}

	currentTime := time.Now()

	persist := OauthExchange{
		Id:          id.String(),
		Nonce:       encryptedNonce,
		State:       encryptedState,
		RedirectUrl: encryptedRedirect,
		CreatedAt:   data.CustomTime{Time: currentTime},
	}
	qry := `INSERT INTO oauthflow (uuid, nonce, state, redirect_url, created_at) VALUES (?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, persist); err != nil {
		return nil, fmt.Errorf("failed to persist oauth exchange record: %v", err)
	}

	return &OauthExchange{
		Nonce:       nonce.String(),
		State:       state.String(),
		RedirectUrl: redirect,
		CreatedAt:   data.CustomTime{Time: currentTime},
	}, nil
}

func (s *oauthService) Valiadate(oauth OauthExchange) error {
	return nil
}
