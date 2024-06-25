package authentication

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type OauthExchange struct {
	Id           string          `json:"id,omitempty" db:"uuid"`
	StateIndex   string          `json:"state_index,omitempty" db:"state_index"`
	ResponseType string          `json:"response_type" db:"response_type"`
	Nonce        string          `json:"nonce" db:"nonce"`
	State        string          `json:"state" db:"state"`
	ClientId     string          `json:"client_id" db:"client_id"`
	RedirectUrl  string          `json:"redirect_url" db:"redirect_url"`
	CreatedAt    data.CustomTime `json:"created_at" db:"created_at"`
}

type OauthService interface {
	// Build creates a new oauth exchange record, persisting it to the database,
	// and returns the struct for use by the login handler to send to authentication service
	Build() (*OauthExchange, error)

	// Valiadate validates the oauth exchange variables returned from the client to the callback url
	// against the values stored in the database to ensure the exchange is valid/untampered
	Valiadate(exchange OauthExchange) error
}

// NewOauthService creates a new instance of the login service
func NewOauthService(oauth config.OauthRedirect, db data.SqlRepository, cryptor data.Cryptor, indexer data.Indexer) OauthService {
	return &oauthService{
		oauth:   oauth,
		db:      db,
		cryptor: cryptor,
		indexer: indexer,
	}
}

var _ OauthService = (*oauthService)(nil)

type oauthService struct {
	oauth   config.OauthRedirect
	db      data.SqlRepository
	cryptor data.Cryptor
	indexer data.Indexer
}

// Build implementation of the OauthService interface
func (s *oauthService) Build() (*OauthExchange, error) {

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange uuid: %v", err)
	}

	encryptedResponseType, err := s.cryptor.EncryptServiceData(string(session.AuthCode)) // responseType "enum" value TODO: rename to AuthCodeType
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange response type for storage: %v", err)
	}

	nonce, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange nonce uuid: %v", err)
	}
	encryptedNonce, err := s.cryptor.EncryptServiceData(nonce.String())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange nonce for storage: %v", err)
	}

	state, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange state uuid: %v", err)
	}
	encryptedState, err := s.cryptor.EncryptServiceData(state.String())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange state for storage: %v", err)
	}

	// index the state for later retrieval
	index, err := s.indexer.ObtainBlindIndex(state.String())
	if err != nil {
		return nil, fmt.Errorf("failed to generate oauth exchange state index for persistence: %v", err)
	}

	encryptedClientId, err := s.cryptor.EncryptServiceData(s.oauth.CallbackClientId)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange callback client id for storage: %v", err)
	}

	encryptedRedirect, err := s.cryptor.EncryptServiceData(s.oauth.CallbackUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt oauth exchange callback/redirect url for storage: %v", err)
	}

	currentTime := time.Now()

	persist := OauthExchange{
		Id:           id.String(),
		StateIndex:   index,
		ResponseType: encryptedResponseType,
		Nonce:        encryptedNonce,
		State:        encryptedState,
		ClientId:     encryptedClientId,
		RedirectUrl:  encryptedRedirect,
		CreatedAt:    data.CustomTime{Time: currentTime},
	}
	qry := `INSERT INTO oauthflow (uuid, state_index, response_type, nonce, state, client_id, redirect_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, persist); err != nil {
		return nil, fmt.Errorf("failed to persist oauth exchange record: %v", err)
	}

	return &OauthExchange{
		ResponseType: string(session.AuthCode),
		Nonce:        nonce.String(),
		State:        state.String(),
		ClientId:     s.oauth.CallbackClientId,
		RedirectUrl:  s.oauth.CallbackUrl,
		CreatedAt:    data.CustomTime{Time: currentTime},
	}, nil
}

// Valiadate implementation of the OauthService interface
func (s *oauthService) Valiadate(exchange OauthExchange) error {
	return nil
}
