package oauth

import (
	"errors"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (

	// 400 Bad Request
	ErrInvalidAuthCodeCmd = "invalid auth code request"
	ErrInvalidSession     = "missing or not well-formed session token"
	ErrInvalidNavEndpoint = "invalid nav endpoint"
	ErrInvalidState       = "invalid oauth state variable"

	// 401 Unauthorized
	ErrSessionNotFound      = "session not found"
	ErrSessionRevoked       = "session revoked"
	ErrSessionExpired       = "session expired"
	ErrResponseTypeMismatch = "response type mismatch"
	ErrStateCodeMismatch    = "state value mismatch"
	ErrNonceMismatch        = "nonce value mismatch"
	ErrClientIdMismatch     = "client id mismatch"
	ErrRedirectUrlMismatch  = "redirect url mismatch"
	ErrOauthExchangeExpired = "oauth exchange record expired"

	// 422 Unprocessable Entity
	ErrSessionAuthenticated = "session is authenticated"

	// 500 Internal Server Error
	ErrGenOauthUuid      = "failed to generate oauth exchange uuid"
	ErrGenNonce          = "failed to generate oauth exchange nonce"
	ErrGenState          = "failed to generate oauth exchange state"
	ErrMarshalOauthState = "failed to marshal oauth state to json bytes"
	ErrBase64OauthState  = "failed to base64 encode oauth state"

	ErrGenSessionIndex = "failed to generate session lookup index"

	ErrEncryptResponseType        = "failed to encrypt oauth exchange response type for storage"
	ErrEncryptNonce               = "failed to encrypt oauth exchange nonce for storage"
	ErrEncryptState               = "failed to encrypt oauth exchange state for storage"
	ErrEncryptCallbackClientId    = "failed to encrypt oauth exchange callback client id for storage"
	ErrEncryptCallbackRedirectUrl = "failed to encrypt oauth exchange callback redirect url for storage"

	ErrDecryptOauthExchange = "failed to decrypt oauth exchange record"
	ErrDecryptResponseType  = "failed to decrypt oauth exchange response type"
	ErrDecryptNonce         = "failed to decrypt oauth exchange nonce"
	ErrDecryptState         = "failed to decrypt oauth exchange state"
	ErrDecryptClientId      = "failed to decrypt oauth exchange client id"
	ErrDecryptRedirectUrl   = "failed to decrypt oauth exchange redirect/callback url"

	ErrLookupOauthExchange = "failed to look up oauth exchange record" // sql error/problem => NOT zero results
	ErrLookupUxSession     = "failed to look up uxsession record"      // sql error/problem => NOT zero results

	ErrPersistOauthExchange = "failed to build/persist oauth exchange record"
	ErrPersistXref          = "failed to persist uxsession_oauthflow xref record"
)

// OauthCmd is a model for an oauth command as it is expected to be received from the client.
type OauthCmd struct {
	SessionToken string `json:"session_token"`
	NavEndpoint  string `json:"nav_endpoint"`
}

// ValidateCmd validates the oauth command.
// SessionTokon will be a uuid or similar
// NavEndpoint will be a url from the client site
func (c *OauthCmd) ValidateCmd() error {
	if len(c.SessionToken) < 16 || len(c.SessionToken) > 64 {
		return errors.New(ErrInvalidSession)
	}

	if len(c.NavEndpoint) < 1 || len(c.NavEndpoint) > 256 {
		return errors.New(ErrInvalidNavEndpoint)
	}

	return nil
}

// OauthState is a struct containing the state (a random string), and the endpoint to redirect the user to after the oauth flow.
// NOTE: the database does not store the endpoint, only the state variable.
type OauthState struct {
	Csrf        string `json:"state_csrf"`
	NavEndpoint string `json:"nav_endpoint"`
}

// ValidateState performs light weight validation on the oauth state.
func (s *OauthState) ValidateState() error {

	if len(s.Csrf) < 16 || len(s.Csrf) > 64 {
		return errors.New(ErrInvalidState)
	}

	if len(s.NavEndpoint) < 1 || len(s.NavEndpoint) > 256 {
		return errors.New(ErrInvalidNavEndpoint)
	}

	return nil
}

// OauthExchange is a model for an oauth exchange in the database.
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

// OauthSession is a model for an oauth session as it is expected to be returned from a database query.
type OauthSession struct {
	UxsessionId        string          `db:"uxsession_uuid"`
	UxsessionCreatedAt data.CustomTime `db:"uxsession_created_at"`
	Authenticated      bool            `db:"authenticated"`
	Revoked            bool            `db:"revoked"`

	OauthId        string          `db:"oauth_uuid"`
	ResponseType   string          `db:"response_type"`
	Nonce          string          `db:"nonce"`
	State          string          `db:"state"`
	ClientId       string          `db:"client_id"`
	RedirectUrl    string          `db:"redirect_url"`
	OauthCreatedAt data.CustomTime `db:"oauth_created_at"`
}

// AuthCodeCmd is a struct to hold incoming authcode and session values
// that are forwaded to the callback endpoint gateway as part of
// the oauth2 authorization code flow.
// Note: is is possibe session value will be empty if session token is sent as a cookie header.
type AuthCodeCmd struct {
	Session string `json:"session,omitempty"`

	AuthCode     string             `json:"auth_code"`
	ResponseType types.ResponseType `json:"response_type"`
	State        string             `json:"state"`
	Nonce        string             `json:"nonce"`
	ClientId     string             `json:"client_id"`
	Redirect     string             `json:"redirect"`
}

// ValidateCmd conducts light-weight validation of incoming authcode and session values
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd *AuthCodeCmd) ValidateCmd() error {

	if validate.TooShort(cmd.Session, 16) || validate.TooLong(cmd.Session, 64) {
		return fmt.Errorf("invalid session: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(string(cmd.ResponseType), 4) || validate.TooLong(string(cmd.ResponseType), 8) {
		return fmt.Errorf("invalid response type: must be between %d and %d characters", 4, 8)
	}

	if validate.TooShort(cmd.State, 16) || validate.TooLong(cmd.State, 254) {
		return fmt.Errorf("invalid state: must be between %d and %d characters", 16, 254)
	}

	if validate.TooShort(cmd.Nonce, 16) || validate.TooLong(cmd.Nonce, 64) {
		return fmt.Errorf("invalid nonce: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 64) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.Redirect, 6) || validate.TooLong(cmd.Redirect, 2048) {
		return fmt.Errorf("invalid redirect: must be between %d and %d characters", 16, 2048)
	}

	return nil

}


