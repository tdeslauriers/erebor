package uxsession

import (
	"database/sql"
	"erebor/internal/util"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// TokenService is performs build and persistance operations on access tokens,
// particularly in relation to the authenticated uxsession.
type TokenService interface {
	// GetAccessToken retrieves the access token record from the database, decrypts the access and refresh tokens,
	// and returns the struct.  If the access token is expired, it will use an active refesh token to retrieve a new access token.
	// Note: will return an error if the provided session is not found, not authenticated, or revoked.
	GetAccessToken(session string) (string, error)

	// PeristToken creates a new AccessToken record, performs field level encryption for db record,
	// persists it to the database, and returns the struct.
	PersistToken(access *provider.UserAuthorization) (*AccessToken, error)

	// PersistXref persists the xref between the authenticated uxsession and the access token.
	PersistXref(xref SessionAccessXref) error
}

// GetAccessToken retrieves the access token record from the database, decrypts the access and refresh tokens,
// and returns the struct.  If the access token is expired, it will use an active refesh token to retrieve a new access token.
func (s *service) GetAccessToken(session string) (string, error) {

	// lightweight input validation: redundant, but good practice
	if len(session) < 16 || len(session) > 64 {
		return "", errors.New(ErrInvalidSession)
	}

	// re generate session index
	index, err := s.indexer.ObtainBlindIndex(session)
	if err != nil {
		return "", fmt.Errorf("%s from provided session token xxxxxx-%s: %v", ErrGenIndex, session[len(session)-6:], err)
	}

	// look up uxSession from db by index
	// Note: the coalesce function is used to return defaults for null values.  Revoked and expired checks are set to trigger their errors
	// in the checks below just to make double sure if the session is untenticated a token will n ever be tried.
	// checks are also done for empty strings which would indicate an unauthenticated session.
	qry := `SELECT 
				u.uuid AS uxsession_uuid, 
				u.created_at, 
				u.authenticated, 
				u.revoked,
				COALESCE(a.uuid, '') AS accesstoken_uuid,
				COALESCE(a.access_token, '') AS access_token,
				COALESCE(a.access_expires, '1970-01-01 00:00:00') AS access_expires,
				COALESCE(a.access_revoked, true) AS access_revoked,
				COALESCE(a.refresh_token, '') AS refresh_token,
				COALESCE(a.refresh_expires, '1970-01-01 00:00:00') AS refresh_expires,
				COALESCE(a.refresh_revoked, true) AS refresh_revoked,
				COALESCE(a.refresh_claimed, true) AS refresh_claimed
			FROM uxsession u
				LEFT OUTER JOIN uxsession_accesstoken ua ON u.uuid = ua.uxsession_uuid
				LEFT OUTER JOIN accesstoken a ON ua.accesstoken_uuid = a.uuid
			WHERE u.session_index = ?` // checks for revoked, expired, etc., done progarmmatically for error handling
	var tokens []UxsessionAccesstoken
	if err := s.db.SelectRecords(qry, &tokens, index); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("%s - session token xxxxxx-%s: %v", ErrSessionNotFound, session[len(session)-6:], err)
		}
		return "", fmt.Errorf("failed to retrieve access token records for session token xxxxxx-%s: %v", session[len(session)-6:], err)
	}

	fmt.Printf("tokens: %+v\n", tokens)

	// if there are no tokens, return an error
	// this should be caught above, but good practice to check
	if len(tokens) == 0 {
		return "", fmt.Errorf("%s - session token xxxxxx-%s", ErrSessionNotFound, session[len(session)-6:])
	}

	// if there is only one session returned, check for empty/default values in access token fields
	// this means the session is not authenticated or has no access token records, ie, fields were null.
	if len(tokens) == 1 {
		if tokens[0].AccessToken == "" || tokens[0].RefreshToken == "" {
			return "", fmt.Errorf("%s - session token xxxxxx-%s", ErrAccessTokenNotFound, session[len(session)-6:])
		}
	}

	// return the first token that passes all checks.  If none pass, function will ultimately return error.
	for _, token := range tokens {

		// session checks are returns not continues because same value in all records
		// check if session listed as authenticated: this is a convenience value only, but should not be false
		if !token.SessionAuthenticated {
			return "", fmt.Errorf("%s - session token xxxxxx-%s", ErrSessionNotAuthenticated, session[len(session)-6:])
		}

		// check if session is revoked
		if token.SessionRevoked {
			return "", fmt.Errorf("%s - session token xxxxxx-%s", ErrSessionRevoked, session[len(session)-6:])
		}

		// chcek if session token is expired
		if token.SessionCreatedAt.Add(1 * time.Hour).Before(time.Now().UTC()) {
			return "", fmt.Errorf("%s - session token xxxxxx-%s", ErrAccessTokenExpired, session[len(session)-6:])
		}

		// token checks are continues because not unique
		// check if null access token due to empty xref == session has no attached access token records
		if token.AccessToken == "" {
			s.logger.Error(fmt.Sprintf("%s - session token xxxxx-%s", ErrAccessTokenNotFound, session[len(session)-6:]))
			continue
		}

		// check if access token is revoked
		if token.AccessRevoked {
			s.logger.Error(fmt.Sprintf("%s - %s tied to session token xxxxx-%s", ErrAccessTokenRevoked, token.AccessTokenId, session[len(session)-6:]))
			continue
		}

		// check if access token is expired
		if token.AccessExpires.Before(time.Now().UTC()) {
			s.logger.Error(fmt.Sprintf("%s - accesstoken uuid %s, session token xxxxx-%s", ErrAccessTokenExpired, token.AccessTokenId, session[len(session)-6:]))
			continue
		}

		// checks have passed: decrypt and return first available access token
		access, err := s.cryptor.DecryptServiceData(token.AccessToken)
		if err != nil {
			// this failure needs to be a continue, because possible for other access tokens to be decrypted successfully
			s.logger.Error(fmt.Sprintf("%s (uuid %s) tied to session token xxxxx-%s", ErrDecryptAccessToken, token.AccessTokenId, session[len(session)-6:]), "err", err.Error())
			continue
		}

		return access, nil
	}

	s.logger.Info(fmt.Sprintf("session token xxxxxx-%s has no valid access tokens: attempting refresh", session[len(session)-6:]))

	// look for a valid refresh token and retrieve a new access token
	for _, token := range tokens {

		// check if null refresh token due to empty xref == session has no attached access token records
		if token.RefreshToken == "" {
			s.logger.Error(fmt.Sprintf("%s for session token xxxxx-%s", ErrRefreshNotFound, session[len(session)-6:]))
			continue
		}

		// check if refresh token is revoked
		if token.RefreshRevoked {
			s.logger.Error(fmt.Sprintf("%s (uuid %s) tied to session token xxxxx-%s", ErrAccessTokenRevoked, token.AccessTokenId, session[len(session)-6:]))
			continue
		}

		// check if refresh token is claimed
		if token.RefreshClaimed {
			s.logger.Error(fmt.Sprintf("%s (uuid %s) tied to session token xxxxx-%s", ErrRefreshTokenClaimed, token.AccessTokenId, session[len(session)-6:]))
			continue
		}

		// check if refresh token is expired
		if token.RefreshExpires.Before(time.Now().UTC()) {
			s.logger.Error(fmt.Sprintf("%s (uuid %s) tied to session token xxxxx-%s", ErrRefreshTokenExpired, token.AccessTokenId, session[len(session)-6:]))

			// TODO: opportunistically delete expired refresh token from db
			continue
		}

		// checks have passed: decrypt and return first available refresh token
		refresh, err := s.cryptor.DecryptServiceData(token.RefreshToken)
		if err != nil {
			// this failure needs to be a continue, because possible for other refresh tokens to be decrypted successfully
			s.logger.Error(fmt.Sprintf("%s (uuid %s) tied to session token xxxxx-%s", ErrDecryptRefreshToken, token.AccessTokenId, session[len(session)-6:]), "err", err.Error())
			continue
		}

		// get s2s token for identity service
		s2sToken, err := s.s2sProvider.GetServiceToken(util.ServiceUserIdentity)
		if err != nil {
			s.logger.Error("failed to get s2s token for identity service refresh endpoint", "err", err.Error())
			continue
		}

		cmd := types.UserRefreshCmd{
			RefreshToken: refresh,
			ClientId:     s.cfg.CallbackClientId,
		}

		// use refresh token to get new access token
		var access provider.UserAuthorization
		if err := s.userIdentity.PostToService("/refresh", s2sToken, "", cmd, &access); err != nil {
			s.logger.Error("call to identity service refresh endpoint failed", "err", err.Error())
			continue
		}

		// persist and clean up concurrently for immediate access token return
		// persist new token
		go func() {
			persist, err := s.PersistToken(&access)
			if err != nil {
				s.logger.Error("failed to persist new access token for refresh request", "err", err.Error())
				return
			}

			// save cross reference to session
			xref := SessionAccessXref{
				UxsessionId:   token.UxsessionId,
				AccessTokenId: persist.Id,
			}

			if err := s.PersistXref(xref); err != nil {
				s.logger.Error("failed to persist uxsession_accesstoken xref record for refresh request", "err", err.Error())
				return
			}

			s.logger.Info(fmt.Sprintf("new access token persisted for session token xxxxx-%s", session[len(session)-6:]))
		}()

		// delete vs mark as claimed: identity service will not allow a refresh token to be used more than once
		go func() {
			qry := "DELETE FROM uxsession_accesstoken WHERE accesstoken_uuid = ?"
			if err := s.db.DeleteRecord(qry, token.AccessTokenId); err != nil {
				s.logger.Error(fmt.Sprintf("failed to delete xref for claimed refresh (uuid %s) tied to session (uuid %s ) xxxxx-%s", token.AccessTokenId, token.UxsessionId, session[len(session)-6:]), "err", err.Error())
				return
			}

			qry = "DELETE FROM accesstoken WHERE uuid = ?"
			if err := s.db.DeleteRecord(qry, token.AccessTokenId); err != nil {
				s.logger.Error(fmt.Sprintf("failed to delete access token for claimed refresh (uuid %s) tied to session (uuid %s ) xxxxx-%s", token.AccessTokenId, token.UxsessionId, session[len(session)-6:]), "err", err.Error())
				return
			}
		}()

		return access.AccessToken, nil
	}

	return "", fmt.Errorf("%s for session token xxxxxx-%s", ErrAccessRefreshNotFound, session[len(session)-6:])
}

// PeristToken creates a new AccessToken record, performs field level encryption for db record,
// persists it to the database, and returns the struct.
// Note: this interface is implemented by the service struct in session_serivic.go
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

// encrypt is a helper function which abstracts the encryption process for concurency operations readability
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
		return fmt.Errorf("failed to persist uxsession_accesstoken xref: %v", ErrInvalidSessionId)
	}

	if xref.AccessTokenId == "" || len(xref.AccessTokenId) > 64 {
		return fmt.Errorf("failed to persist uxsessionaccess_token xref: %v", ErrInvalidAccessTokenId)
	}

	qry := `INSERT INTO uxsession_accesstoken (id, uxsession_uuid, accesstoken_uuid) VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		return fmt.Errorf("failed to persist uxsession_accesstoken xref (uxsession id: %s - accesstoken id: %s ): %v", xref.UxsessionId, xref.AccessTokenId, err)
	}

	return nil
}
