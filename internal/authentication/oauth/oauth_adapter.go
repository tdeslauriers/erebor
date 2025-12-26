package oauth

import (
	"database/sql"
	"erebor/internal/authentication/uxsession"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// Repository defines the interface for interacting with the oauth data store.
type OAuthRepository interface {

	// FindOauthBySession retrieves a specific oauth record associated with a given session token by its session_index
	FindOauthBySession(sessionIndex string) (*OauthSession, error)

	// FindActiveOauthflow retrieves an active oauthflow record by the session index tied to it in the sessiontoken table.
	FindActiveOauthflow(sessionIndex string) (*OauthExchange, error)

	// InsertOauthflow inserts a new oauthflow record into the database
	InsertOauthflow(oauthflow OauthExchange) error

	// InsertUxsessionOauthXref inserts a new uxsession_oauthflow xref record into the database
	InsertUxsessionOauthXref(xref uxsession.UxsesionOauthFlow) error
}

// NewOAuthRepository creates a new instance of the OAuthRepository interface, returning a concrete implementation.
func NewOAuthRepository(sql *sql.DB) OAuthRepository {
	return &oauthAdapter{
		sql: sql,
	}
}

var _ OAuthRepository = (*oauthAdapter)(nil)

// concrete implementation of the OAuthRepository interface.
type oauthAdapter struct {
	sql *sql.DB
}

// FindOauthBySession retrieves a specific oauth record associated with a given session token by its session_index
func (a *oauthAdapter) FindOauthBySession(sessionIndex string) (*OauthSession, error) {

	qry := `
		SELECT
			u.uuid AS uxsession_uuid,
			u.created_at AS uxsession_created_at,
			u.authenticated,
			u.revoked,
			COALESCE(o.uuid, '') AS oauth_uuid,
			COALESCE(o.response_type, '') AS response_type,
			COALESCE(o.nonce, '') AS nonce,
			COALESCE(o.state, '') AS state,
			COALESCE(o.client_id, '') AS client_id,
			COALESCE(o.redirect_url, '') AS redirect_url,
			COALESCE(o.created_at, '1970-01-01 00:00:00') AS oauth_created_at
		FROM uxsession u
			LEFT OUTER JOIN uxsession_oauthflow uo ON u.uuid = uo.uxsession_uuid
			LEFT OUTER JOIN oauthflow o ON uo.oauthflow_uuid = o.uuid
		WHERE u.session_index = ?`

	o, err := data.SelectOneRecord[OauthSession](a.sql, qry, sessionIndex)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("oauth not found by session token")
		}
		return nil, err
	}

	return &o, nil
}

// FindActiveOauthflow retrieves an active oauthflow record by the session index tied to it in the sessiontoken table.
func (a *oauthAdapter) FindActiveOauthflow(sessionIndex string) (*OauthExchange, error) {

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

	o, err := data.SelectOneRecord[OauthExchange](a.sql, qry, sessionIndex)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("active oauth not found by session token")
		}
		return nil, err
	}

	return &o, nil
}

// InsertOauthflow inserts a new oauthflow record into the database
func (a *oauthAdapter) InsertOauthflow(oauthflow OauthExchange) error {

	qry := `
		INSERT INTO oauthflow (
			uuid, 
			state_index, 
			response_type, 
			nonce, 
			state, 
			client_id, 
			redirect_url, 
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(a.sql, qry, oauthflow)
}

// InsertUxsessionOauthXref inserts a new uxsession_oauthflow xref record into the database
func (a *oauthAdapter) InsertUxsessionOauthXref(xref uxsession.UxsesionOauthFlow) error {

	qry := `
		INSERT INTO uxsession_oauthflow (
			id, 
			uxsession_uuid, 
			oauthflow_uuid
			) VALUES (?, ?, ?)`

	return data.InsertRecord(a.sql, qry, xref)
}
