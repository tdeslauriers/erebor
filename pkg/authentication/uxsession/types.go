package uxsession

import "github.com/tdeslauriers/carapace/pkg/data"

const (
	// 422
	ErrInvalidSession = "invalid or not well formed session token"
	ErrInvalidCsrf    = "invalid or not well formed csrf token"

	// 401
	ErrSessionRevoked  = "session is revoked"
	ErrSessionExpired  = "session is expired"
	ErrSessionNotFound = "session not found"

	ErrCsrfMismatch = "decryped csrf token does not match csrf provided"

	// 500
	ErrGenPrimaryKey          = "failed to generate primary key"
	ErrGenSessionUuid         = "failed to generate session uuid"
	ErrGenSessionToken        = "failed to generate session token"
	ErrGenIndex        string = "failed to generate session index"
	ErrGenCsrfToken           = "failed to generate csrf token"

	ErrEncryptSession      = "failed to encrypt session token"
	ErrEncryptCsrf         = "failed to encrypt csrf token"
	ErrEncryptAccessToken  = "failed to encrypt access token"
	ErrEncryptRefreshToken = "failed to encrypt refresh token"

	ErrDecryptSession      = "failed to decrypt session token"
	ErrDecryptCsrf         = "failed to decrypt csrf token"
	ErrDecryptAccessToken  = "failed to decrypt access token"
	ErrDecryptRefreshToken = "failed to decrypt refresh token"

	// returns a 500 because these values are not user provided -> system error
	ErrInvalidSessionId     = "invalid or not well formed session id"
	ErrInvalidAccessTokenId = "invalid or not well formed access token id"
)

// AccessToken is a model for the database record that persists
// the encrypted access and refresh tokens and their respective metadata.
type AccessToken struct {
	Id             string          `json:"id,omitempty" db:"uuid"`
	AccessToken    string          `json:"access_token" db:"access_token"`
	AccessExpries  data.CustomTime `json:"access_expires" db:"access_expires"`
	AccessRevoked  bool            `json:"access_revoked" db:"access_revoked"` // will still be valid token, helper logic for service not to return/use
	RefreshToken   string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
	RefreshRevoked bool            `json:"refresh_revoked" db:"refresh_revoked"` // will still be valid token (needs to be revoked in identity service)
	RefreshClaimed bool            `json:"refresh_claimed" db:"refresh_claimed"` // helper logic for service to know if refresh token has been used
}

// SessionAccessXref is a model for the database record that persists the xref
// between the authenticated uxsession and the access token(s).
type SessionAccessXref struct {
	Id            int    `json:"id,omitempty" db:"id"`
	UxsessionId   string `json:"uxsession_id,omitempty" db:"uxsession_uuid"`
	AccessTokenId string `json:"access_token,omitempty" db:"accesstoken_uuid"`
}
