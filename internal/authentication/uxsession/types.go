package uxsession

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

const (
	// 422
	ErrInvalidSession = "invalid or not well formed session token"
	ErrInvalidCsrf    = "invalid or not well formed csrf token"

	// 401
	ErrSessionRevoked          = "session is revoked"
	ErrSessionExpired          = "session is expired"
	ErrSessionNotFound         = "session not found"
	ErrSessionNotAuthenticated = "session is not authenticated"

	ErrAccessRefreshNotFound = "no valid access or refresh tokens found"
	ErrAccessTokenNotFound   = "access token not found"
	ErrAccessTokenExpired    = "access token is expired"
	ErrAccessTokenRevoked    = "access token is revoked"
	ErrRefreshNotFound       = "refresh token not found"
	ErrRefreshTokenExpired   = "refresh token is expired"
	ErrRefreshTokenClaimed   = "refresh token is claimed"
	ErrRefreshTokenRevoked   = "refresh token is revoked"

	ErrCsrfMismatch = "decryped csrf token does not match csrf provided"

	ErrVerifyAccessToken = "failed to verify/build access token"
	ErrVerifyIdToken     = "unable to verify/build id token"

	// 500
	ErrGenPrimaryKey   = "failed to generate primary key"
	ErrGenSessionUuid  = "failed to generate session uuid"
	ErrGenSessionToken = "failed to generate session token"
	ErrGenIndex        = "failed to generate session index"
	ErrGenCsrfToken    = "failed to generate csrf token"

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

	ErrDeleteUxsession                = "failed to delete uxsession"
	ErrDeleteAccessToken              = "failed to delete access token"
	ErrDeleteOauthExchange            = "failed to delete oauthfow record"
	ErrDeleteUxsessionAccesstokenXref = "failed to delete uxsession_accesstoken xref record"
	ErrDeleteUxsessionOauthflowXref   = "failed to delete uxsession_oauthflow xref record"
)

// container interface for multiple task specific interfaces
type Service interface {
	SessionService
	CsrfService
	TokenService
	SessionErrService
}

// NewService creates a new instance of the container Service interface and returns a pointer to its concrete implementation.
func NewService(
	cfg *config.OauthRedirect,
	db *sql.DB,
	i data.Indexer,
	c data.Cryptor,
	p provider.S2sTokenProvider,
	call *connect.S2sCaller,
) Service {

	return &uxService{
		SessionService:    NewSessionService(cfg, db, i, c, p, call),
		CsrfService:       NewCsrfService(db, i, c),
		TokenService:      NewTokenService(cfg, db, i, c, p, call),
		SessionErrService: NewSessionErrService(),
	}
}

// service is the concrete implementation of the Service interface.
type uxService struct {
	SessionService
	CsrfService
	TokenService
	SessionErrService
}

// frontend only every sees session and csrf tokens,
// the rest of theses fields are internal metadata for the gateway
type UxSession struct {
	Id            string          `json:"id,omitempty" db:"uuid"`
	Index         string          `json:"session_index,omitempty" db:"session_index"`
	SessionToken  string          `json:"session_token" db:"session_token"`
	CsrfToken     string          `json:"csrf_token,omitempty" db:"csrf_token"`
	CreatedAt     data.CustomTime `json:"created_at" db:"created_at"`
	Authenticated bool            `json:"authenticated" db:"authenticated"` // convenience field, not used for actual auth decisions
	Revoked       bool            `json:"revoked,omitempty" db:"revoked"`
}

type UxSessionType bool

const (
	Anonymous     UxSessionType = false
	Authenticated UxSessionType = true
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

// Uxsession is a model for the database record in the uxsession_oauthflow table
type UxsesionOauthFlow struct {
	Id              int    `json:"id,omitempty" db:"id"`
	UxsessionId     string `json:"uxsession_id,omitempty" db:"uxsession_uuid"`
	OauthExchangeId string `json:"oauth_exchange_id,omitempty" db:"oauthflow_uuid"`
}

// LiveAccessToken is a model for the database query/xref table output which includes the uxsession_accesstoken table fields
// and the accesstoken table fields.
type LiveAccessToken struct {
	Id            int    `json:"id,omitempty" db:"id"`
	UxsessionId   string `json:"uxsession_id,omitempty" db:"uxsession_uuid"`
	AccessTokenId string `json:"access_token,omitempty" db:"accesstoken_uuid"` // primary key for deletion from accesstoken table
	RefreshToken  string `json:"refresh_token" db:"refresh_token"`             // refresh token for destroy call to identity service
}

// SessionAccessToken is a model for the database query output which includes
// fields from the uxsession table and the accesstoken table
// Note: NOT all fields are included, only the ones needed for the service
type UxsessionAccesstoken struct {
	// uxsession fields
	// omitting sensitive/unused fields: session_token, csrf_token, session_index
	UxsessionId          string          `json:"uxsession_id,omitempty" db:"uxsession_uuid"`
	SessionCreatedAt     data.CustomTime `json:"created_at" db:"created_at"`
	SessionAuthenticated bool            `json:"authenticated" db:"authenticated"`
	SessionRevoked       bool            `json:"revoked,omitempty" db:"revoked"`

	// accesstoken fields
	AccessTokenId  string          `json:"access_token_id,omitempty" db:"accesstoken_uuid"`
	AccessToken    string          `json:"access_token" db:"access_token"`
	AccessExpires  data.CustomTime `json:"access_expires" db:"access_expires"`
	AccessRevoked  bool            `json:"access_revoked" db:"access_revoked"`
	RefreshToken   string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
	RefreshRevoked bool            `json:"refresh_revoked" db:"refresh_revoked"`
	RefreshClaimed bool            `json:"refresh_claimed" db:"refresh_claimed"`
}
