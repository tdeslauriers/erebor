package uxsession

import (
	"database/sql"
	"errors"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// CsrfRepository is the interface for handling ux session csrf token specific operations.
type CsrfRepository interface {

	// FindSession retrieves a uxsession record by its session_index
	FindSession(sessionIndex string) (*UxSession, error)
}

// NewCsrfRepository creates a new instance of the CsrfRepository interface, returning a concrete implementation.
func NewCsrfRepository(db *sql.DB) CsrfRepository {
	return &csrfAdapter{
		db: db,
	}
}

var _ CsrfRepository = (*csrfAdapter)(nil)

type csrfAdapter struct {
	db *sql.DB
}

// FindSession retrieves a uxsession record by its session_index
func (a *csrfAdapter) FindSession(sessionIndex string) (*UxSession, error) {

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
