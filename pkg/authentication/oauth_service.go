package authentication

import (
	"database/sql"
	"erebor/pkg/uxsession"
	"errors"
	"fmt"
	"strings"
	"sync"
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

	// Obtain returns the oauth exchange record associated with the uxsession from the database if it exists.
	// If one does not exist, it will build one, persist it, and return the newly created record.
	Obtain(uxsession string) (*OauthExchange, error)

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

type UxsesionOauthFlow struct {
	Id              int    `json:"id,omitempty" db:"id"`
	UxsessionId     string `json:"uxsession_id,omitempty" db:"uxsession_uuid"`
	OauthExchangeId string `json:"oauth_exchange_id,omitempty" db:"oauthflow_uuid"`
}

// Obtain implementation of the OauthService interface
func (s *oauthService) Obtain(sessionToken string) (*OauthExchange, error) {

	if len(sessionToken) < 16 || len(sessionToken) > 64 {
		return nil, fmt.Errorf("invalid session token length: %d", len(sessionToken))
	}

	// recreate session token index
	index, err := s.indexer.ObtainBlindIndex(sessionToken)
	if err != nil {
		return nil, fmt.Errorf("%s for session lookup: %v", uxsession.ErrGenIndex, err)
	}

	// check if the oauth exchange record already exists
	var exchange OauthExchange
	qry := `
	SELECT 
	 	o.uuid, 
		o.state_index, 
		o.response_type, 
		o.nonce, o.state, 
		o.client_id, 
		o.redirect_url, 
		o.created_at
	FROM oauthflow o 
		LEFT OUTER JOIN uxsession_oauthflow uo ON o.uuid = uo.oauthflow_uuid
		LEFT OUTER JOIN uxsession u ON uo.uxsession_uuid = u.uuid
	WHERE u.session_index = ?
		AND u.revoked = false`
	// it is possible this will yeield multiple records, but we only need one, SelectRecord will return the first row found
	if err := s.db.SelectRecord(qry, &exchange, index); err != nil {
		if err == sql.ErrNoRows {

			var wgRecords sync.WaitGroup
			lookupId := make(chan string, 1)
			persist := make(chan OauthExchange, 1)
			errs := make(chan error, 2)

			// look up the session
			wgRecords.Add(1)
			go func() {
				defer wgRecords.Done()

				var session uxsession.UxSession
				qry := `SELECT uuid, session_index, session_token, csrf_token, created_at, authenticated, revoked FROM uxsession WHERE session_index = ?`
				if err := s.db.SelectRecord(qry, &session, index); err != nil {
					if err == sql.ErrNoRows {
						e := fmt.Errorf("session token xxxxxx-%s: %v", sessionToken[len(sessionToken)-6:], uxsession.ErrSessionNotFound)
						errs <- e
					} else {
						errs <- err
					}
				}
				// check if session is revoked
				if session.Revoked {
					e := fmt.Errorf("session id %s: %s", session.Id, uxsession.ErrSessionRevoked)
					errs <- e
				}

				lookupId <- session.Id
			}()

			// build the oauth exchange record
			wgRecords.Add(1)
			go func() {
				defer wgRecords.Done()
				ouath, err := s.build()
				if err != nil {
					e := fmt.Errorf("failed to build oauth and persist exchange record for session token xxxxxx-%s: %v", sessionToken[len(sessionToken)-6:], err)
					errs <- e
				}
				persist <- *ouath
			}()

			go func() {
				wgRecords.Wait()
				close(lookupId)
				close(persist)
				close(errs)
			}()

			if len(errs) > 0 {
				// if there are errors, return/exit the function
				var builder strings.Builder
				count := 0
				for e := range errs {
					builder.WriteString(e.Error())
					if len(errs) > 1 && count < len(errs)-1 {
						builder.WriteString("; ")
					}
					count++
				}
				return nil, errors.New(builder.String())
			} else {

				sessionId := <-lookupId
				exchange := <-persist

				xref := UxsesionOauthFlow{
					Id:              0,
					UxsessionId:     sessionId,
					OauthExchangeId: exchange.Id,
				}
				// create the relationship between the session and the oauth exchange record and return the exchange
				qry := `INSERT INTO uxsession_oauthflow (uxsession_uuid, oauthflow_uuid) VALUES (?, ?, ?)`
				if err := s.db.InsertRecord(qry, xref); err != nil {
					return nil, fmt.Errorf("failed to create uxsession_oauthflow xref record between uxsession %s and oathflow %s: %v", sessionId, exchange.Id, err)
				}

				return &exchange, nil
			}

		} else {
			return nil, fmt.Errorf("exchange record lookup failed for session token xxxxxx-%s: %v", sessionToken[len(sessionToken)-6:], err)
		}
	}

	return &exchange, nil
}

// build creates a new oauth exchange record, persisting it to the database,
// and returns the struct
func (s *oauthService) build() (*OauthExchange, error) {

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
