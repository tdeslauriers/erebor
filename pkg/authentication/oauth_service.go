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

const (

	// 500 Internal Server Error
	ErrGenOauthUuid = "failed to generate oauth exchange uuid"
	ErrGenNonce     = "failed to generate oauth exchange nonce"
	ErrGenState     = "failed to generate oauth exchange state"
	ErrGenIndex     = "failed to encrypt oauth exchange nonce for storage"

	ErrEncryptResponseType        = "failed to encrypt oauth exchange response type for storage"
	ErrEncryptNonce               = "failed to encrypt oauth exchange nonce for storage"
	ErrEncryptState               = "failed to encrypt oauth exchange state for storage"
	ErrEncryptCallbackClientId    = "failed to encrypt oauth exchange callback client id for storage"
	ErrEncryptCallbackRedirectUrl = "failed to encrypt oauth exchange callback redirect url for storage"

	ErrLookupOauthExchange = "failed to look up oauth exchange record" // sql error/problem => NOT zero results

	ErrPersistOauthExchange = "failed to build/persist oauth exchange record"
	ErrPersistXref          = "failed to persist uxsession_oauthflow xref record"
)

// Obtain implementation of the OauthService interface
func (s *oauthService) Obtain(sessionToken string) (*OauthExchange, error) {

	if len(sessionToken) < 16 || len(sessionToken) > 64 {
		return nil, errors.New(uxsession.ErrInvalidSession)
	}

	// recreate session token index
	index, err := s.indexer.ObtainBlindIndex(sessionToken)
	if err != nil {
		return nil, fmt.Errorf("%s for session lookup: %v", uxsession.ErrGenIndex, err)
	}

	// check if the oauth exchange record already exists
	var exchange OauthExchange
	qry := `SELECT 
				o.uuid, 
				o.state_index, 
				o.response_type, 
				o.nonce, 
				o.state, 
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
						e := fmt.Errorf("session token xxxxxx-%s: %s", sessionToken[len(sessionToken)-6:], uxsession.ErrSessionNotFound)
						errs <- e
					} else {
						errs <- err
					}
				}
				// check if session is revoked
				if session.Revoked {
					e := fmt.Errorf("session id %s - session token xxxxxx-%s: %s", session.Id, sessionToken[len(sessionToken)-6:], uxsession.ErrSessionRevoked)
					errs <- e
				}

				// check if session is expired
				if session.CreatedAt.Add(time.Hour).Before(time.Now().UTC()) {
					e := fmt.Errorf("session id %s - session token xxxxxx-%s: %s", session.Id, sessionToken[len(sessionToken)-6:], uxsession.ErrSessionExpired)
					errs <- e
				}

				lookupId <- session.Id
			}()

			// build/persist the oauth exchange record
			wgRecords.Add(1)
			go func() {
				defer wgRecords.Done()
				
				ouath, err := s.build()
				if err != nil {
					// all error options for this are 500 errors
					e := fmt.Errorf("%s for session token xxxxxx-%s: %v", ErrPersistOauthExchange, sessionToken[len(sessionToken)-6:], err)
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
					return nil, fmt.Errorf("%s between uxsession %s and oathflow %s: %v", ErrPersistXref, sessionId, exchange.Id, err)
				}

				// successfully persisted oauth exchange record and associated with the session
				return &OauthExchange{
					ResponseType: exchange.ResponseType,
					Nonce:        exchange.Nonce,
					State:        exchange.State,
					ClientId:     exchange.ClientId,
					RedirectUrl:  exchange.RedirectUrl,
					CreatedAt:    exchange.CreatedAt,
				}, nil
			}

		} else {
			return nil, fmt.Errorf("%s for session token xxxxxx-%s: %v", ErrLookupOauthExchange, sessionToken[len(sessionToken)-6:], err)
		}
	}

	return &OauthExchange{
		ResponseType: exchange.ResponseType,
		Nonce:        exchange.Nonce,
		State:        exchange.State,
		ClientId:     exchange.ClientId,
		RedirectUrl:  exchange.RedirectUrl,
		CreatedAt:    exchange.CreatedAt,
	}, nil
}

// build creates a new oauth exchange record, persisting it to the database,
// and returns the struct
func (s *oauthService) build() (*OauthExchange, error) {

	// use concurrent goroutines to build the oauth exchange record
	// because lots of random data is being generated + several crypto operations
	var wgExchange sync.WaitGroup
	errChan := make(chan error, 9)

	idChan := make(chan uuid.UUID, 1)

	encRespTypeChan := make(chan string, 1)

	nonceChan := make(chan uuid.UUID, 1)
	encNonceChan := make(chan string, 1)

	stateChan := make(chan uuid.UUID, 1)
	indexChan := make(chan string, 1)
	encStateChan := make(chan string, 1)

	encClientIdChan := make(chan string, 1)

	encRedirectChan := make(chan string, 1)

	// create the oauth exchange record uuid
	wgExchange.Add(1)
	go func() {
		defer wgExchange.Done()
		id, err := uuid.NewRandom()
		if err != nil {
			errChan <- fmt.Errorf("%s %v", ErrGenOauthUuid, err)
		}
		idChan <- id
	}()

	// encrypt the response type
	wgExchange.Add(1)
	go func() {
		defer wgExchange.Done()
		encryptedResponseType, err := s.cryptor.EncryptServiceData(string(session.AuthCode)) // responseType "enum" value TODO: rename to AuthCodeType
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptResponseType, err)
		}
		encRespTypeChan <- encryptedResponseType
	}()

	// create and encrypt the nonce
	wgExchange.Add(1)
	go func() {
		defer wgExchange.Done()

		nonce, err := uuid.NewRandom()
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrGenNonce, err)
		}
		nonceChan <- nonce

		encryptedNonce, err := s.cryptor.EncryptServiceData(nonce.String())
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptNonce, err)
		}
		encNonceChan <- encryptedNonce
	}()

	// create and encrypt the state
	// create the index for the state
	wgExchange.Add(1)
	go func() {
		defer wgExchange.Done()

		state, err := uuid.NewRandom()
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrGenState, err)
		}
		stateChan <- state

		// create index for the state
		index, err := s.indexer.ObtainBlindIndex(state.String())
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrGenIndex, err)
		}
		indexChan <- index

		encryptedState, err := s.cryptor.EncryptServiceData(state.String())
		if err != nil {
			errChan <- fmt.Errorf("%s %v", ErrEncryptState, err)
		}
		encStateChan <- encryptedState
	}()

	// encrypt the client id
	wgExchange.Add(1)
	go func() {
		defer wgExchange.Done()

		encryptedClientId, err := s.cryptor.EncryptServiceData(s.oauth.CallbackClientId)
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptCallbackClientId, err)
		}
		encClientIdChan <- encryptedClientId
	}()

	// encrypt the redirect url
	wgExchange.Add(1)
	go func() {
		defer wgExchange.Done()

		encryptedRedirect, err := s.cryptor.EncryptServiceData(s.oauth.CallbackUrl)
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptCallbackRedirectUrl, err)
		}
		encRedirectChan <- encryptedRedirect
	}()

	go func() {
		wgExchange.Wait()
		close(errChan)
	}()

	// aggregate any errors and return
	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if len(errChan) > 1 && count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		// return all errors as a single error: all are 500s
		// exit the function
		return nil, errors.New(builder.String())
	}

	id := <-idChan
	encryptedResponseType := <-encRespTypeChan
	nonce := <-nonceChan
	encryptedNonce := <-encNonceChan
	state := <-stateChan
	encryptedState := <-encStateChan
	index := <-indexChan
	encryptedClientId := <-encClientIdChan
	encryptedRedirect := <-encRedirectChan

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
		Id:           id.String(),
		StateIndex:   index,
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
