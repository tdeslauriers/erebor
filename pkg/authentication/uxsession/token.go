package uxsession

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// TokenService is performs build and persistance operations on access tokens,
// particularly in relation to the authenticated uxsession.
type TokenService interface {
	// Build creates a new AccessToken record, persisting it to the database, and returns the struct.
	PersistToken(access *provider.UserAuthorization) (*AccessToken, error)

	// PersistXref persists the xref between the authenticated uxsession and the access token.
	PersistXref(xref SessionAccessXref) error
}

// this interface is implemented by the service object in serivic.go
// I am breaking this out to an interface for readability and to make it easier to test
func (s *service) PersistToken(access *provider.UserAuthorization) (*AccessToken, error) {

	// create primary key for access token
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s for access token: %v", ErrGenPrimaryKey, err)
	}

	// create new access token record
	persist := AccessToken{
		Id:             id.String(),
		AccessToken:    access.AccessToken, // encrypted above
		AccessExpries:  access.AccessTokenExpires,
		AccessRevoked:  false,
		RefreshToken:   access.Refresh, // encrypted above
		RefreshExpires: access.RefreshExpires,
		RefreshRevoked: false,
		RefreshClaimed: false,
	}

	// encrypt access and refresh tokens
	if err := s.fieldLevelEncrypt(&persist); err != nil {
		return nil, errors.New(err.Error())
	}

	qry := `INSERT INTO accesstoken (uuid, access_token, access_expires, access_revoked, refresh_token, refresh_expires, refresh_revoked, refresh_claimed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, persist); err != nil {
		return nil, fmt.Errorf("failed to persist access token: %v", err)
	}

	return &persist, nil
}

// fieldLevelEncrypt is a helper function which encrypts the access and refresh tokens
// and can be updated to encrypt other fields as needed.
func (s *service) fieldLevelEncrypt(access *AccessToken) error {

	var (
		wgEncrypt      sync.WaitGroup
		errEncryptChan = make(chan error, 2)

		encryptedAccess  string
		encryptedRefresh string
	)

	wgEncrypt.Add(2)
	go s.encrypt(access.AccessToken, ErrEncryptAccessToken, &encryptedAccess, errEncryptChan, &wgEncrypt)
	go s.encrypt(access.RefreshToken, ErrEncryptRefreshToken, &encryptedRefresh, errEncryptChan, &wgEncrypt)

	wgEncrypt.Wait()
	close(errEncryptChan)

	if len(errEncryptChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errEncryptChan {
			builder.WriteString(err.Error())
			if count < len(errEncryptChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return fmt.Errorf("failed to encrypt access/refresh tokens: %v", builder.String())

	}

	// replace access and refresh tokens with encrypted values
	access.AccessToken = encryptedAccess
	access.RefreshToken = encryptedRefresh

	return nil
}

// encrypt is a helper function which encrypts the plaintext string and returns the encrypted string.
func (h *service) encrypt(plaintext, errMsg string, encrypted *string, ch chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	enc, err := h.cryptor.EncryptServiceData(plaintext)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	*encrypted = enc
}

// PersistXref persists the xref between the authenticated uxsession and the access token.
func (s *service) PersistXref(xref SessionAccessXref) error {

	// lightweight input validation: redundant, but good practice
	if xref.UxsessionId == "" || len(xref.UxsessionId) > 64 {
		return fmt.Errorf("failed to persist uxsession_access_token xref: %v", ErrInvalidSessionId)
	}

	if xref.AccessTokenId == "" || len(xref.AccessTokenId) > 64 {
		return fmt.Errorf("failed to persist uxsession_access_token xref: %v", ErrInvalidAccessTokenId)
	}

	qry := `INSERT INTO uxsession_accesstoken (id, uxsession_uuid, accesstoken_uuid) VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		return fmt.Errorf("failed to persist uxsession_access_token xref: %v", err)
	}

	return nil
}
