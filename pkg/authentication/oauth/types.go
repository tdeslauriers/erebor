package oauth

import (
	"errors"

	"github.com/tdeslauriers/carapace/pkg/data"
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
	State       string `json:"state"`
	NavEndpoint string `json:"nav_endpoint"`
}

// ValidateState performs light weight validation on the oauth state.
func (s *OauthState) ValidateState() error {

	if len(s.State) < 16 || len(s.State) > 64 {
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
