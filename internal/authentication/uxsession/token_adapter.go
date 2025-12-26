package uxsession

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// TokenRepository is the interface for handling ux session token specific operations.
type TokenRepository interface {

	// FindAccessTokensBySession retrieves all access tokens associated with a given session token by its session_index
	FindAccessTokensBySession(sessionIndex string) ([]UxsessionAccesstoken, error)

	// InsertAccessToken inserts a new access token record into the database
	InsertAccessToken(token AccessToken) error

	// InsertUxsessionAccessTknXref inserts a new uxsession_accesstoken xref record into the database
	InsertUxsessionAccessTknXref(xref SessionAccessXref) error

	// DeleteAccessToken deletes an access token record by its uuid
	DeleteAccessToken(accesstokenUuid string) error

	// DeleteUxsessionAccessTknXref deletes a uxsession_accesstoken xref record by uxsession uuid and accesstoken uuid
	DeleteUxsessionAccessTknXref(accesstokenUuid string) error
}

// NewTokenRepository creates a new instance of the TokenRepository interface, returning a concrete implementation.
func NewTokenRepository(db *sql.DB) TokenRepository {
	return &tokenAdapter{
		db: db,
	}
}

var _ TokenRepository = (*tokenAdapter)(nil)

type tokenAdapter struct {
	db *sql.DB
}

// FindAccessTokensBySession retrieves all access tokens associated with a given session token by its session_index
func (a *tokenAdapter) FindAccessTokensBySession(sessionIndex string) ([]UxsessionAccesstoken, error) {

	// look up uxSession from db by index
	// Note: the coalesce function is used to return defaults for null values.  Revoked and expired checks are set to trigger their errors
	// in the checks below just to make double sure if the session is untenticated a token will n ever be tried.
	// checks are also done for empty strings which would indicate an unauthenticated session.
	qry := `
		SELECT 
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

	return data.SelectRecords[UxsessionAccesstoken](a.db, qry, sessionIndex)
}

// InsertAccessToken inserts a new access token record into the database
func (a *tokenAdapter) InsertAccessToken(token AccessToken) error {

	qry := `
		INSERT INTO accesstoken (
			uuid, 
			access_token, 
			access_expires, 
			access_revoked, 
			refresh_token, 
			refresh_expires, 
			refresh_revoked, 
			refresh_claimed
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(a.db, qry, token)
}

// InsertUxsessionAccessTknXref inserts a new uxsession_accesstoken xref record into the database
func (a *tokenAdapter) InsertUxsessionAccessTknXref(xref SessionAccessXref) error {

	qry := `
		INSERT INTO uxsession_accesstoken (
			id, 
			uxsession_uuid, 
			accesstoken_uuid
		) VALUES (?, ?, ?)`

	return data.InsertRecord(a.db, qry, xref)
}

// DeleteAccessToken deletes an access token record by its uuid
func (a *tokenAdapter) DeleteAccessToken(accesstokenUuid string) error {

	qry := `
		DELETE FROM accesstoken 
		WHERE uuid = ?`

	return data.DeleteRecord(a.db, qry, accesstokenUuid)
}

// DeleteUxsessionAccessTknXref deletes a uxsession_accesstoken xref record by uxsession uuid and accesstoken uuid
func (a *tokenAdapter) DeleteUxsessionAccessTknXref(accesstokenUuid string) error {

	qry := `
		DELETE FROM uxsession_accesstoken 
		WHERE accesstoken_uuid = ?`

	return data.DeleteRecord(a.db, qry, accesstokenUuid)
}
