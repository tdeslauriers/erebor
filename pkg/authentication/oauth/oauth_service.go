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

type Service interface {
	OauthService
	OauthErrService
}

// NewService creates a new instance of the login service
func NewService(o config.OauthRedirect, db data.SqlRepository, c data.Cryptor, i data.Indexer) Service {
	return &service{
		oAuth:   o,
		db:      db,
		cryptor: c,
		indexer: i,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentOauth)),
	}
}

type OauthService interface {

	// Obtain returns the oauth exchange record associated with the uxsession from the database if it exists.
	// If one does not exist, it will build one, persist it, and return the newly created record.
	Obtain(uxsession string) (*OauthExchange, error)

	// Valiadate validates the oauth exchange variables returned from the client to the callback url
	// against the values stored in the database to ensure the exchange is valid/untampered
	Validate(oauth types.AuthCodeCmd) error
}

type OauthErrService interface {
	// HandleOauthnErr is a helper function to handle oauth service errors in a consistent way
	HandleServiceErr(err error, w http.ResponseWriter)
}

var _ Service = (*service)(nil)

type service struct {
	oAuth   config.OauthRedirect
	db      data.SqlRepository
	cryptor data.Cryptor
	indexer data.Indexer

	logger *slog.Logger
}

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
	qry := `
		SELECT 
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
			AND u.revoked = false
			AND u.created_at > UTC_TIMESTAMP() - INTERVAL 1 HOUR
			AND o.created_at > UTC_TIMESTAMP() - INTERVAL 1 HOUR` // check revoked and expiries

	var exchange OauthExchange
	if err := s.db.SelectRecord(qry, &exchange, index); err != nil {
		if err == sql.ErrNoRows {

			var wgRecords sync.WaitGroup
			errs := make(chan error, 2)

			var (
				sessionId string
				persisted OauthExchange
			)

			// look up the session
			wgRecords.Add(1)
			go func(id *string, errs chan error, wg *sync.WaitGroup) {
				defer wg.Done()

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

				*id = session.Id
			}(&sessionId, errs, &wgRecords)

			// build/persist the oauth exchange record
			wgRecords.Add(1)
			go func(ex *OauthExchange, errs chan error, wg *sync.WaitGroup) {
				defer wg.Done()

				ouath, err := s.build()
				if err != nil {
					// all error options for this are 500 errors
					e := fmt.Errorf("%s for session token xxxxxx-%s: %v", ErrPersistOauthExchange, sessionToken[len(sessionToken)-6:], err)
					errs <- e
				}
				*ex = *ouath
			}(&persisted, errs, &wgRecords)

			wgRecords.Wait()
			close(errs)

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

				xref := UxsesionOauthFlow{
					Id:              0,
					UxsessionId:     sessionId,
					OauthExchangeId: persisted.Id,
				}

				// create the relationship between the session and the oauth exchange record and return the exchange
				qry := `INSERT INTO uxsession_oauthflow (id, uxsession_uuid, oauthflow_uuid) VALUES (?, ?, ?)`
				if err := s.db.InsertRecord(qry, xref); err != nil {
					return nil, fmt.Errorf("%s between uxsession %s and oathflow %s: %v", ErrPersistXref, sessionId, persisted.Id, err)
				}

				// successfully persisted oauth exchange record and associated with the session
				return &OauthExchange{
					ResponseType: persisted.ResponseType,
					Nonce:        persisted.Nonce,
					State:        persisted.State,
					ClientId:     persisted.ClientId,
					RedirectUrl:  persisted.RedirectUrl,
				}, nil
			}

		} else {
			return nil, fmt.Errorf("%s for session token xxxxxx-%s: %v", ErrLookupOauthExchange, sessionToken[len(sessionToken)-6:], err)
		}
	}

	// oauth exchange already exists
	// decrypt all field-level-encrypted values for return object
	oauth, err := s.decryptExchange(exchange)
	if err != nil {
		return nil, fmt.Errorf("%s id %s associated with session token xxxxxx-%s: %v", ErrDecryptOauthExchange, exchange.Id, sessionToken[len(sessionToken)-6:], err)
	}

	// set uuid to "" for the return object because unnecessary
	oauth.Id = ""

	// set created_at time to zero value for the return object because unnecessary
	oauth.CreatedAt = data.CustomTime{}

	// return the ouath exchange record
	return oauth, nil
}

// build is a helper funciton that creates a new oauth exchange record,
// persists it to the database, and returns the struct
func (s *service) build() (*OauthExchange, error) {

	// use concurrent goroutines to build the oauth exchange record
	// because lots of random data is being generated + several crypto operations
	var wgExchange sync.WaitGroup
	errChan := make(chan error, 9)

	var (
		id                    uuid.UUID
		encryptedResponseType string
		nonce                 uuid.UUID
		encryptedNonce        string
		state                 uuid.UUID
		index                 string
		encryptedState        string
		encryptedClientId     string
		encryptedRedirect     string
	)

	// create the oauth exchange record uuid
	wgExchange.Add(1)
	go func(id *uuid.UUID, errChan chan error, wg *sync.WaitGroup) {
		defer wg.Done()
		i, err := uuid.NewRandom()
		if err != nil {
			errChan <- fmt.Errorf("%s %v", ErrGenOauthUuid, err)
			return
		}
		*id = i
	}(&id, errChan, &wgExchange)

	// encrypt the response type
	wgExchange.Add(1)
	go func(encrypted *string, errChan chan error, wg *sync.WaitGroup) {
		defer wgExchange.Done()
		cipher, err := s.cryptor.EncryptServiceData(string(types.AuthCode)) // responseType "enum" value TODO: rename to AuthCodeType
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", cipher, err)
		}
		*encrypted = cipher
	}(&encryptedResponseType, errChan, &wgExchange)

	// create and encrypt the nonce
	wgExchange.Add(1)
	go func(nonce *uuid.UUID, encrypted *string, errChan chan error, wg *sync.WaitGroup) {
		defer wgExchange.Done()

		n, err := uuid.NewRandom()
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrGenNonce, err)
		}
		*nonce = n

		cipher, err := s.cryptor.EncryptServiceData(nonce.String())
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptNonce, err)
		}
		*encrypted = cipher
	}(&nonce, &encryptedNonce, errChan, &wgExchange)

	// create and encrypt the state
	// create the index for the state
	wgExchange.Add(1)
	go func(state *uuid.UUID, index *string, encrypted *string, errChan chan error, wg *sync.WaitGroup) {
		defer wgExchange.Done()

		st, err := uuid.NewRandom()
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrGenState, err)
		}
		*state = st

		i, err := s.indexer.ObtainBlindIndex(state.String())
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrGenSessionIndex, err)
		}
		*index = i

		cipher, err := s.cryptor.EncryptServiceData(state.String())
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptState, err)
		}
		*encrypted = cipher
	}(&state, &index, &encryptedState, errChan, &wgExchange)

	// encrypt the client id
	wgExchange.Add(1)
	go func(encrypted *string, errChan chan error, wg *sync.WaitGroup) {
		defer wgExchange.Done()
		cipher, err := s.cryptor.EncryptServiceData(s.oAuth.CallbackClientId)
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptCallbackClientId, err)
		}
		*encrypted = cipher
	}(&encryptedClientId, errChan, &wgExchange)

	// encrypt the redirect url
	wgExchange.Add(1)
	go func(encrypted *string, errChan chan error, wg *sync.WaitGroup) {
		defer wgExchange.Done()
		cipher, err := s.cryptor.EncryptServiceData(s.oAuth.CallbackUrl)
		if err != nil {
			errChan <- fmt.Errorf("%s: %v", ErrEncryptCallbackRedirectUrl, err)
		}
		*encrypted = cipher
	}(&encryptedRedirect, errChan, &wgExchange)

	wgExchange.Wait()
	close(errChan)

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
		ClientId:     s.oAuth.CallbackClientId,
		RedirectUrl:  s.oAuth.CallbackUrl,
		CreatedAt:    data.CustomTime{Time: currentTime},
	}, nil
}

// Valiadate implementation of the OauthService interface
func (s *service) Validate(cmd types.AuthCodeCmd) error {

	// input validation -> redundant because also performed by handler
	if err := cmd.ValidateCmd(); err != nil {
		return fmt.Errorf("%s: %v", ErrInvalidAuthCodeCmd, err)
	}

	// generate index blind index from session
	index, err := s.indexer.ObtainBlindIndex(cmd.Session)
	if err != nil {
		return fmt.Errorf("%s for session xxxxxx-%s: %v", ErrGenSessionIndex, cmd.Session[len(cmd.Session)-6:], err)
	}

	// look up the oauth exchange record
	query := `
		SELECT 
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
			AND u.revoked = false
			AND u.created_at > NOW() - INTERVAL 1 HOUR
			AND o.created_at > NOW() - INTERVAL 1 HOUR` // check revoked and expiries

	var check OauthExchange
	if err := s.db.SelectRecord(query, &check, index); err != nil {
		if err == sql.ErrNoRows {
			return errors.New(uxsession.ErrSessionNotFound)
		} else {
			return fmt.Errorf("session xxxxxx-%s is %s: %v", cmd.Session[len(cmd.Session)-6:], ErrInvalidSessionToken, err)
		}
	}

	// decrypt the exchange record
	exchange, err := s.decryptExchange(check)
	if err != nil {
		return fmt.Errorf("%s for session xxxxxx-%s: %v", ErrLookupOauthExchange, cmd.Session[len(cmd.Session)-6:], err)
	}

	// validate the exchange record against the client request
	if exchange.ResponseType != string(cmd.ResponseType) {
		return fmt.Errorf("session xxxxxx-%s - %s - client: %s vs db record: %s", cmd.Session[len(cmd.Session)-6:], ErrResponseTypeMismatch, cmd.ResponseType, exchange.ResponseType)
	}

	if exchange.State != cmd.State {
		return fmt.Errorf("session xxxxxx-%s: %s - client: xxxxx-%s vs db record: xxxxxx-%s", cmd.Session[len(cmd.Session)-6:], ErrStateCodeMismatch, cmd.State[len(cmd.State)-6:], exchange.State[len(exchange.State)-6:])
	}

	if exchange.Nonce != cmd.Nonce {
		return fmt.Errorf("session xxxxxx-%s: %s - client: xxxxxx-%s vs db record: xxxxxx-%s", cmd.Session[len(cmd.Session)-6:], ErrNonceMismatch, cmd.Nonce[len(cmd.Nonce)-6:], exchange.Nonce[len(exchange.Nonce)-6:])
	}

	if exchange.ClientId != cmd.ClientId {
		return fmt.Errorf("failed to validate client id for session xxxxxx-%s: %s", cmd.Session[len(cmd.Session)-6:], ErrClientIdMismatch)
	}

	if exchange.RedirectUrl != cmd.Redirect {
		return fmt.Errorf("failed to validate redirect url for session xxxxxx-%s: %s", cmd.Session[len(cmd.Session)-6:], ErrRedirectUrlMismatch)
	}

	return nil
}

// decryptExchange is a helper function that decrypts the encrypted fields
// of the OauthExchange record returned from database calls.
func (s *service) decryptExchange(encrypted OauthExchange) (*OauthExchange, error) {

	var wg sync.WaitGroup
	errChan := make(chan error, 5) // errors

	var (
		responseType string
		nonce        string
		state        string
		clientId     string
		callbackUrl  string
	)

	// decrypt the response type
	wg.Add(1)
	go s.decrypt(encrypted.ResponseType, ErrDecryptResponseType, &responseType, errChan, &wg)

	// decrypt the nonce
	wg.Add(1)
	go s.decrypt(encrypted.Nonce, ErrDecryptNonce, &nonce, errChan, &wg)

	// decrypt the state
	wg.Add(1)
	go s.decrypt(encrypted.State, ErrDecryptState, &state, errChan, &wg)

	// decrypt the client id
	wg.Add(1)
	go s.decrypt(encrypted.ClientId, encrypted.Id, &clientId, errChan, &wg)

	// decrypt the callback url
	wg.Add(1)
	go s.decrypt(encrypted.RedirectUrl, ErrDecryptRedirectUrl, &callbackUrl, errChan, &wg)

	// wait for all decryption goroutines to finish
	wg.Wait()
	close(errChan)

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
		Id:           encrypted.Id, // not encrypted in the database
		ResponseType: responseType,
		Nonce:        nonce,
		State:        state,
		ClientId:     clientId,
		RedirectUrl:  callbackUrl,
		CreatedAt:    encrypted.CreatedAt, // not encrypted in the database
	}, nil
}

func (s *service) decrypt(encrypted, errDecrypt string, decrypted *string, errChan chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	d, err := s.cryptor.DecryptServiceData(encrypted)
	if err != nil {

		errChan <- fmt.Errorf("%s: %v", errDecrypt, err)
	}
	*decrypted = d
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
	case strings.Contains(err.Error(), ErrInvalidSessionToken):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrInvalidSessionToken,
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
