package uxsession

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CsrfService interface provides methods for handling csrf tokens.
type CsrfService interface {

	// GetCsrf returns a csrf token for the given session id.
	GetCsrf(session string) (*UxSession, error)

	// ValidateCsrt validates the csrf token provided is attached to the session token.
	IsValidCsrf(session, csrf string) (bool, error)
}

// implements GetCsrf of CsrfService interface
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

	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 2)

		sessionToken string
		csrfToken    string
	)

	wg.Add(2)
	go s.decrypt(uxSession.SessionToken, &sessionToken, errChan, &wg)
	go s.decrypt(uxSession.CsrfToken, &csrfToken, errChan, &wg)

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errChan {
			builder.WriteString(err.Error())
			if count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return nil, fmt.Errorf("failed to get csrf token: %s", builder.String())
	}

	return &UxSession{
		SessionToken:  sessionToken,
		CsrfToken:     csrfToken,
		CreatedAt:     uxSession.CreatedAt,
		Authenticated: uxSession.Authenticated,
	}, nil
}

// IsValidCsrf implements ValidateCsrf of Service interface
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

	return true, nil
}

// decrypt is a helper function to abstract away the field level string decryption process
func (s *service) decrypt(encrypted string, decrypted *string, ch chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	d, err := s.cryptor.DecryptServiceData(encrypted)
	if err != nil {
		ch <- fmt.Errorf("failed to decrypt: %v", err)
		return
	}

	*decrypted = d
}