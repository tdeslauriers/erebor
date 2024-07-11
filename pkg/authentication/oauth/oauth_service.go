package oauth

import (
	"database/sql"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
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
	"github.com/tdeslauriers/carapace/pkg/session/types"
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
	Valiadate(oauth types.AuthCodeCmd) error
}

type OauthErrService interface {
	// HandleOauthnErr is a helper function to handle oauth service errors in a consistent way
	HandleServiceErr(err error, w http.ResponseWriter)
}

type Service interface {
	OauthService
	OauthErrService
}

// NewService creates a new instance of the login service
func NewService(o config.OauthRedirect, db data.SqlRepository, c data.Cryptor, i data.Indexer) Service {
	return &service{
		oauth:   o,
		db:      db,
		cryptor: c,
		indexer: i,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentOauth)),
	}
}

var _ Service = (*service)(nil)

type service struct {
	oauth   config.OauthRedirect
	db      data.SqlRepository
	cryptor data.Cryptor
	indexer data.Indexer

	logger *slog.Logger
}

type UxsesionOauthFlow struct {
	Id              int    `json:"id,omitempty" db:"id"`
	UxsessionId     string `json:"uxsession_id,omitempty" db:"uxsession_uuid"`
	OauthExchangeId string `json:"oauth_exchange_id,omitempty" db:"oauthflow_uuid"`
}

const (

	// 400 Bad Request
	ErrInvalidAuthCodeCmd = "invalid auth code request"

	// 401 Unauthorized
	ErrResponseTypeMismatch = "response type mismatch"
	ErrStateCodeMismatch    = "state value mismatch"
	ErrNonceMismatch        = "nonce value mismatch"
	ErrClientIdMismatch     = "client id mismatch"
	ErrRedirectUrlMismatch  = "redirect url mismatch"

	// 500 Internal Server Error
	ErrGenOauthUuid = "failed to generate oauth exchange uuid"
	ErrGenNonce     = "failed to generate oauth exchange nonce"
	ErrGenState     = "failed to generate oauth exchange state"

	ErrGenSessionIndex = "failed to generate session lookup index"

	ErrEncryptResponseType        = "failed to encrypt oauth exchange response type for storage"
	ErrEncryptNonce               = "failed to encrypt oauth exchange nonce for storage"
	ErrEncryptState               = "failed to encrypt oauth exchange state for storage"
	ErrEncryptCallbackClientId    = "failed to encrypt oauth exchange callback client id for storage"
	ErrEncryptCallbackRedirectUrl = "failed to encrypt oauth exchange callback redirect url for storage"

	ErrDecryptResponseType = "failed to decrypt oauth exchange response type"
	ErrDecryptNonce        = "failed to decrypt oauth exchange nonce"
	ErrDecryptState        = "failed to decrypt oauth exchange state"
	ErrDecryptClientId     = "failed to decrypt oauth exchange client id"
	ErrDecryptRedirectUrl  = "failed to decrypt oauth exchange redirect/callback url"

	ErrLookupOauthExchange = "failed to look up oauth exchange record" // sql error/problem => NOT zero results

	ErrPersistOauthExchange = "failed to build/persist oauth exchange record"
	ErrPersistXref          = "failed to persist uxsession_oauthflow xref record"
)

// Obtain implementation of the OauthService interface
func (s *service) Obtain(sessionToken string) (*OauthExchange, error) {

	if len(sessionToken) < 16 || len(sessionToken) > 64 {
		return nil, errors.New(uxsession.ErrInvalidSession)
	}

	// recreate session token index
	index, err := s.indexer.ObtainBlindIndex(sessionToken)
	if err != nil {
		return nil, fmt.Errorf("%s for session lookup: %v", uxsession.ErrGenIndex, err)
	}

	// check if the oauth exchange record already exists
	qry := OauthBySession
	var check OauthSessionCheck
	if err := s.db.SelectRecord(qry, &check, index); err != nil {
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
				qry := `INSERT INTO uxsession_oauthflow (id, uxsession_uuid, oauthflow_uuid) VALUES (?, ?, ?)`
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

	// oauth exchange already exists
	// check if session revoked
	if check.UxsessionRevoked {
		return nil, fmt.Errorf("session token %s - xxxxxx-%s: %s", check.UxsessionUuid, sessionToken[len(sessionToken)-6:], uxsession.ErrSessionRevoked)
	}

	// check if session expired
	if check.UxsessionCreatedAt.Add(time.Hour).Before(time.Now().UTC()) {
		return nil, fmt.Errorf("session token %s - xxxxxx-%s: %s", check.UxsessionUuid, sessionToken[len(sessionToken)-6:], uxsession.ErrSessionExpired)
	}

	// decrypt all field-level-encrypted values for return object
	exchange, err := s.decryptExchange(check)
	if err != nil {
		return nil, fmt.Errorf("%s for session token xxxxxx-%s: %v", ErrLookupOauthExchange, sessionToken[len(sessionToken)-6:], err)
	}

	// return the ouath exchange record
	return exchange, nil
}

// build is a helper funciton that creates a new oauth exchange record,
// persists it to the database, and returns the struct
func (s *service) build() (*OauthExchange, error) {

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
		encryptedResponseType, err := s.cryptor.EncryptServiceData(string(types.AuthCode)) // responseType "enum" value TODO: rename to AuthCodeType
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
			errChan <- fmt.Errorf("%s: %v", ErrGenSessionIndex, err)
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
		ResponseType: string(types.AuthCode),
		Nonce:        nonce.String(),
		State:        state.String(),
		ClientId:     s.oauth.CallbackClientId,
		RedirectUrl:  s.oauth.CallbackUrl,
		CreatedAt:    data.CustomTime{Time: currentTime},
	}, nil
}

// Valiadate implementation of the OauthService interface
func (s *service) Valiadate(oauth types.AuthCodeCmd) error {

	// input validation -> redundant because also performed by handler
	if err := oauth.ValidateCmd(); err != nil {
		return fmt.Errorf("%s for session xxxxxx-%s: %v", ErrInvalidAuthCodeCmd, oauth.Session[len(oauth.Session)-6:], err)
	}

	// generate index blind index from session
	index, err := s.indexer.ObtainBlindIndex(oauth.Session)
	if err != nil {
		return fmt.Errorf("%s for session xxxxxx-%s: %v", ErrGenSessionIndex, oauth.Session[len(oauth.Session)-6:], err)
	}

	// look up the oauth exchange record
	query := OauthBySession
	var check OauthSessionCheck
	if err := s.db.SelectRecord(query, &check, index); err != nil {
		if err == sql.ErrNoRows {
			return errors.New(uxsession.ErrSessionNotFound)
		} else {
			return fmt.Errorf("%s for session xxxxxx-%s: %v", ErrLookupOauthExchange, oauth.Session[len(oauth.Session)-6:], err)
		}
	}

	// check if the session is revoked before decrypting the exchange record
	if check.UxsessionRevoked {
		return fmt.Errorf("session token %s - xxxxxx-%s: %s", check.UxsessionUuid, oauth.Session[len(oauth.Session)-6:], uxsession.ErrSessionRevoked)
	}

	// check if the session is expired before decrypting the exchange record
	if check.UxsessionCreatedAt.Add(time.Hour).Before(time.Now().UTC()) {
		return fmt.Errorf("session token %s - xxxxxx-%s: %s", check.UxsessionUuid, oauth.Session[len(oauth.Session)-6:], uxsession.ErrSessionExpired)
	}

	// decrypt the exchange record
	exchange, err := s.decryptExchange(check)
	if err != nil {
		return fmt.Errorf("%s for session xxxxxx-%s: %v", ErrLookupOauthExchange, oauth.Session[len(oauth.Session)-6:], err)
	}

	// validate the exchange record against the client request
	if exchange.ResponseType != string(oauth.ResponseType) {
		return fmt.Errorf("session xxxxxx-%s - %s - client: %s vs db record: %s", oauth.Session[len(oauth.Session)-6:], ErrResponseTypeMismatch, oauth.ResponseType, exchange.ResponseType)
	}

	if exchange.State != oauth.State {
		return fmt.Errorf("session xxxxxx-%s: %s - client: xxxxx-%s vs db record: xxxxxx-%s", oauth.Session[len(oauth.Session)-6:], ErrStateCodeMismatch, oauth.State[len(oauth.State)-6:], exchange.State[len(exchange.State)-6:])
	}

	if exchange.Nonce != oauth.Nonce {
		return fmt.Errorf("session xxxxxx-%s: %s - client: xxxxxx-%s vs db record: xxxxxx-%s", oauth.Session[len(oauth.Session)-6:], ErrNonceMismatch, oauth.Nonce[len(oauth.Nonce)-6:], exchange.Nonce[len(exchange.Nonce)-6:])
	}

	if exchange.ClientId != oauth.ClientId {
		return fmt.Errorf("failed to validate client id for session xxxxxx-%s: %s", oauth.Session[len(oauth.Session)-6:], ErrClientIdMismatch)
	}

	if exchange.RedirectUrl != oauth.Redirect {
		return fmt.Errorf("failed to validate redirect url for session xxxxxx-%s: %s", oauth.Session[len(oauth.Session)-6:], ErrRedirectUrlMismatch)
	}

	return nil
}

// decryptExchange is a helper function that decrypts the encrypted fields
// of the OauthSessionCheck struct and returns an OauthExchange struct
func (s *service) decryptExchange(d OauthSessionCheck) (*OauthExchange, error) {

	wg := sync.WaitGroup{}

	rtChan := make(chan string, 1)       // response type
	nonceChan := make(chan string, 1)    // nonce
	stateChan := make(chan string, 1)    // state
	clientIdChan := make(chan string, 1) // client id
	callbackChan := make(chan string, 1) // callback url

	errChan := make(chan error, 5) // errors

	// decrypt the response type
	wg.Add(1)
	go func() {
		defer wg.Done()

		rt, err := s.cryptor.DecryptServiceData(d.ResponseType)
		if err != nil {
			errChan <- fmt.Errorf("%s for oauthflow id %s: %v", ErrDecryptResponseType, d.OauthflowUuid, err)
		}
		rtChan <- rt
	}()

	// decrypt the nonce
	wg.Add(1)
	go func() {
		defer wg.Done()

		n, err := s.cryptor.DecryptServiceData(d.Nonce)
		if err != nil {
			errChan <- fmt.Errorf("%s for oauthflow id %s: %v", ErrDecryptNonce, d.OauthflowUuid, err)
		}
		nonceChan <- n
	}()

	// decrypt the state
	wg.Add(1)
	go func() {
		defer wg.Done()

		st, err := s.cryptor.DecryptServiceData(d.State)
		if err != nil {
			errChan <- fmt.Errorf("%s for oauthflow id %s: %v", ErrDecryptState, d.OauthflowUuid, err)
		}
		stateChan <- st
	}()

	// decrypt the client id
	wg.Add(1)
	go func() {
		defer wg.Done()

		cid, err := s.cryptor.DecryptServiceData(d.ClientId)
		if err != nil {
			errChan <- fmt.Errorf("%s for oauthflow id %s: %v", ErrDecryptClientId, d.OauthflowUuid, err)
		}
		clientIdChan <- cid
	}()

	// decrypt the callback url
	wg.Add(1)
	go func() {
		defer wg.Done()

		cb, err := s.cryptor.DecryptServiceData(d.RedirectUrl)
		if err != nil {
			errChan <- fmt.Errorf("%s for oauthflow id %s: %v", ErrDecryptRedirectUrl, d.OauthflowUuid, err)
		}
		callbackChan <- cb
	}()

	// wait for all decryption goroutines to finish
	go func() {
		wg.Wait()

		close(rtChan)
		close(nonceChan)
		close(stateChan)
		close(clientIdChan)
		close(callbackChan)

		close(errChan)
	}()

	// check for any errors and return
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
		return nil, errors.New(builder.String())
	}

	// return the ouath exchange record
	return &OauthExchange{
		Id:           d.OauthflowUuid,
		ResponseType: <-rtChan,
		Nonce:        <-nonceChan,
		State:        <-stateChan,
		ClientId:     <-clientIdChan,
		RedirectUrl:  <-callbackChan,
		CreatedAt:    d.OauthflowCreatedAt,
	}, nil
}

// HandleSessionErr implementation of the OauthErrService interface
func (s *service) HandleServiceErr(err error, w http.ResponseWriter) {

	switch {
	case strings.Contains(err.Error(), uxsession.ErrInvalidSession):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    uxsession.ErrInvalidSession,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), uxsession.ErrSessionNotFound):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrSessionNotFound,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), uxsession.ErrSessionRevoked):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrSessionRevoked,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), uxsession.ErrSessionExpired):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrSessionExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrResponseTypeMismatch):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrResponseTypeMismatch,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrStateCodeMismatch):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrStateCodeMismatch,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrNonceMismatch):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrNonceMismatch,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrClientIdMismatch):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrClientIdMismatch,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrRedirectUrlMismatch):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrRedirectUrlMismatch,
		}
		e.SendJsonErr(w)
		return
	default: // majority errors for this service are internal server errors
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error: unable to retrieve oauth exchange data",
		}
		e.SendJsonErr(w)
		return
	}
}
