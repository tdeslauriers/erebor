package oauth

import "github.com/tdeslauriers/carapace/pkg/data"

const (

	// 400 Bad Request
	ErrInvalidAuthCodeCmd = "invalid auth code request"

	// 401 Unauthorized
	ErrInvalidSessionToken  = "revoked, expired, or missing session token"
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

	ErrDecryptOauthExchange = "failed to decrypt oauth exchange record"
	ErrDecryptResponseType  = "failed to decrypt oauth exchange response type"
	ErrDecryptNonce         = "failed to decrypt oauth exchange nonce"
	ErrDecryptState         = "failed to decrypt oauth exchange state"
	ErrDecryptClientId      = "failed to decrypt oauth exchange client id"
	ErrDecryptRedirectUrl   = "failed to decrypt oauth exchange redirect/callback url"

	ErrLookupOauthExchange = "failed to look up oauth exchange record" // sql error/problem => NOT zero results

	ErrPersistOauthExchange = "failed to build/persist oauth exchange record"
	ErrPersistXref          = "failed to persist uxsession_oauthflow xref record"
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
