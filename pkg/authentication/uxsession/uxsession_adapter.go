package uxsession

import (
	"database/sql"
	"errors"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// Repository defines the interface for interacting with the uxsession data store.
type SessionRepository interface {

	// FindSession retrieves a uxsession record by its session_index
	FindSession(sessionIndex string) (*UxSession, error)

	// FindLiveAccessTokens retrieves all unexpired access tokens (either access token unxpired or
	// refresh token unxpired), tied ot a session id.
	FindLiveAccessTokens(sessionId string) ([]LiveAccessToken, error)

	// Find SessionOauthXrefs finds all uxsession_oauth xref records by session uuid
	FindSessionOauthXrefs(sessionUuid string) ([]UxsesionOauthFlow, error)

	// UpdateRevoked updates the revoked status of a uxsession record by session index
	UpdateRevoked(sessionIndex string, revoked bool) error

	// InsertUxSession inserts a new uxsession record into the database.
	// Note: fields requiring encryption should be encrypted before calling this method.
	InsertUxSession(ux UxSession) error

	// DeleteSession deletes a uxsession record by its session_index
	DeleteSession(sessionIndex string) error

	// DeleteAccessToken deletes an accesstoken record by its uuid
	DeleteAccessToken(uuid string) error

	// DeleteOauthflow deletes an oauthflow record by its uuid
	DeleteOauthflow(uuid string) error

	// DeleteSessionAccessXref deletes an uxsession_accesstoken record by its id
	DeleteSessionAccessXref(id int) error

	// DeleteSessionOauthXref deletes an uxsession_oauthflow record by its id
	DeleteSessionOauthXref(id int) error
}

// NewRepository creates a new instance of the Repository interface, returning a concrete implementation.
func NewSessionRepository(db *sql.DB) SessionRepository {
	return &uxsessionAdapter{
		db: db,
	}
}

var _ SessionRepository = (*uxsessionAdapter)(nil)

type uxsessionAdapter struct {
	db *sql.DB
}

// FindSession retrieves a uxsession record by its session_index
func (a *uxsessionAdapter) FindSession(sessionIndex string) (*UxSession, error) {

	qry := `
		SELECT 
			uuid, 
			session_index, 
			session_token, 
			csrf_token, 
			created_at, 
			authenticated, 
			revoked 
		FROM uxsession 
		WHERE session_index = ?`

	s, err := data.SelectOneRecord[UxSession](a.db, qry, sessionIndex)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("session not found")
		}
		return nil, err
	}

	return &s, nil
}

// FindLiveAccessTokens retrieves all unexpired access tokens (either access token unxpired or
// refresh token unxpired), tied ot a session id.
func (a *uxsessionAdapter) FindLiveAccessTokens(sessionId string) ([]LiveAccessToken, error) {

	qry := `
		SELECT
			ua.id,
			ua.uxsession_uuid,
			ua.accesstoken_uuid,
			a.refresh_token
		FROM uxsession_accesstoken ua
			LEFT OUTER JOIN accesstoken a ON ua.accesstoken_uuid = a.uuid
		WHERE ua.uxsession_uuid = ?
			AND (
				a.access_expires > UTC_TIMESTAMP()
					OR (a.refresh_expires > UTC_TIMESTAMP()
						AND a.refresh_claimed = FALSE
					)
			)`

	return data.SelectRecords[LiveAccessToken](a.db, qry, sessionId)
}

// Find SessionOauthXrefs finds all uxsession_oauth xref records by session uuid
func (a *uxsessionAdapter) FindSessionOauthXrefs(sessionUuid string) ([]UxsesionOauthFlow, error) {

	qry := `
		SELECT 
			id, 
			uxsession_uuid, 
			oauthflow_uuid 
		FROM uxsession_oauthflow 
		WHERE uxsession_uuid = ?`

	return data.SelectRecords[UxsesionOauthFlow](a.db, qry, sessionUuid)
}

// InsertUxSession inserts a new uxsession record into the database.
// Note: fields requiring encryption should be encrypted before calling this method.
func (a *uxsessionAdapter) InsertUxSession(ux UxSession) error {

	qry := `
		INSERT INTO uxsession (
			uuid, 
			session_index, 
			session_token, 
			csrf_token, 
			created_at, 
			authenticated, 
			revoked
		) VALUES (?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(a.db, qry, ux)
}

// UpdateRevoked updates the revoked status of a uxsession record by session index
func (a *uxsessionAdapter) UpdateRevoked(sessionIndex string, revoked bool) error {

	qry := `
		UPDATE uxsession 
		SET revoked = ? 
		WHERE session_index = ?`

	return data.UpdateRecord(a.db, qry, revoked, sessionIndex)
}

// DeleteSession deletes a uxsession record by its session_index
func (a *uxsessionAdapter) DeleteSession(sessionIndex string) error {

	qry := `
		DELETE FROM uxsession 
		WHERE session_index = ?`

	return data.DeleteRecord(a.db, qry, sessionIndex)
}

// DeleteAccessToken deletes an accesstoken record by its uuid
func (a *uxsessionAdapter) DeleteAccessToken(uuid string) error {

	qry := `
		DELETE FROM accesstoken 
		WHERE uuid = ?`

	return data.DeleteRecord(a.db, qry, uuid)
}

// DeleteOauthflow deletes an oauthflow record by its uuid
func (a *uxsessionAdapter) DeleteOauthflow(uuid string) error {

	qry := `
		DELETE FROM oauthflow 
		WHERE uuid = ?`

	return data.DeleteRecord(a.db, qry, uuid)
}

// DeleteSessionAccessXref deletes an uxsession_accesstoken record by its id
func (a *uxsessionAdapter) DeleteSessionAccessXref(id int) error {

	qry := `
		DELETE FROM uxsession_accesstoken 
		WHERE id = ?`

	return data.DeleteRecord(a.db, qry, id)
}

// DeleteSessionOauthXref deletes an uxsession_oauthflow record by its id
func (a *uxsessionAdapter) DeleteSessionOauthXref(id int) error {

	qry := `
		DELETE FROM uxsession_oauthflow 
		WHERE id = ?`

	return data.DeleteRecord(a.db, qry, id)
}
