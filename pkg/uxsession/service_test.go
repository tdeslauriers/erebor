package uxsession

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
)

const (
	TestValidSessionId = "valid-session-id"
	TestValidIndex     = "valid-session-index"
	TestValidSession   = "valid-session-token"
	TestInvalidSession = "invalid-session-token"
	TestRevokedSession = "revoked-session-token"
	TestExpiredSession = "expired-session-token"
	TestValidCsrf      = "valid-csrf-token"
)

type mockSqlRepository struct{}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	// need to refrect record interface's type to mock sql query hydrating the record
	uxsession := reflect.ValueOf(record).Elem()

	switch args[0] {
	case "index-" + TestValidSession:
		testResults := []string{TestValidSessionId, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
		for i := 0; i < uxsession.NumField(); i++ {
			if i == 4 {
				now := time.Now()
				unexpired := now.Add(-30 * time.Minute)
				uxsession.Field(i).Set(reflect.ValueOf(data.CustomTime{Time: unexpired}))
			} else if i == 5 || i == 6 {
				uxsession.Field(i).SetBool(false)
			} else {
				uxsession.Field(i).SetString(testResults[i])
			}
		}
	case "index-" + TestInvalidSession:
		return sql.ErrNoRows
	case "index-" + TestRevokedSession:
		testResults := []string{TestRevokedSession, TestValidIndex, "encrypted-" + TestRevokedSession, "encrypted-" + TestValidCsrf}
		for i := 0; i < uxsession.NumField(); i++ {
			if i == 4 {
				now := time.Now()
				expired := now.Add(-30 * time.Minute)
				uxsession.Field(i).Set(reflect.ValueOf(data.CustomTime{Time: expired}))
			} else if i == 5 || i == 6 {
				uxsession.Field(i).SetBool(true) // set revoked to true and authenticated to true, but authenticated is just a convenience field
			} else {
				uxsession.Field(i).SetString(testResults[i])
			}
		}
	case "index-" + TestExpiredSession:
		testResults := []string{TestRevokedSession, TestValidIndex, "encrypted-" + TestExpiredSession, "encrypted-" + TestValidCsrf}
		for i := 0; i < uxsession.NumField(); i++ {
			if i == 4 {
				now := time.Now()
				unexpired := now.Add(-90 * time.Minute) // sets created_at to 90 minutes ago
				uxsession.Field(i).Set(reflect.ValueOf(data.CustomTime{Time: unexpired}))
			} else if i == 5 || i == 6 {
				uxsession.Field(i).SetBool(false)
			} else {
				uxsession.Field(i).SetString(testResults[i])
			}
		}
	default:
	}

	return nil
}
func (dao *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockSqlRepository) InsertRecord(query string, record interface{}) error  { return nil }
func (dao *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockSqlRepository) Close() error                                         { return nil }

type mockCryptor struct{}

func (c *mockCryptor) EncryptServiceData(plaintext string) (string, error) {
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}
func (c *mockCryptor) DecryptServiceData(encrypted string) (string, error) {

	return encrypted[10:], nil
}

type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(record string) (string, error) {
	return fmt.Sprintf("index-%s", record), nil
}

func TestBuildSession(t *testing.T) {

	testCases := []struct {
		name string
		UxSessionType
		err error
	}{
		{
			name:          "success anonymous session",
			UxSessionType: Anonymous,
			err:           nil,
		},
		{
			name:          "success authenticated session",
			UxSessionType: Authenticated,
			err:           nil,
		},
		{
			name:          "session type false",
			UxSessionType: UxSessionType(false),
			err:           nil,
		},
		{
			name:          "session type true",
			UxSessionType: UxSessionType(true),
			err:           nil,
		},
	}

	sessionSvc := NewService(&mockSqlRepository{}, &mockIndexer{}, &mockCryptor{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := sessionSvc.Build(tc.UxSessionType)
			if err != tc.err {
				t.Errorf("expected %v, got %v", tc.err, err)
			}
			if session != nil {
				if session.SessionToken == "" {
					t.Errorf("expected non-empty session token, got %s", session.SessionToken)
				}
				if session.CsrfToken == "" {
					t.Errorf("expected non-empty csrf token, got %s", session.CsrfToken)

				}
				if bool(tc.UxSessionType) != session.Authenticated {
					t.Errorf("expected %v, got %v", tc.UxSessionType, session.Authenticated)
				}
			}
		})
	}
}

func TestGetCsrf(t *testing.T) {
	testCases := []struct {
		name      string
		session   string
		uxsession *UxSession
		err       error
	}{
		{
			name:    "valid session token - returns csrf token",
			session: TestValidSession,
			uxsession: &UxSession{
				SessionToken:  TestValidSession,
				CsrfToken:     TestValidCsrf,
				Authenticated: false,
				Revoked:       false,
			},
			err: nil,
		},
		{
			name:      "empty session token - returns validation error",
			session:   "",
			uxsession: nil,
			err:       errors.New(ErrInvalidSessionId),
		},
		{
			name:      "too short session token - returns validation error",
			session:   "short",
			uxsession: nil,
			err:       errors.New(ErrInvalidSessionId),
		},
		{
			name:      "too long session token - returns validation error",
			session:   "this-session-token-is-too-long-to-be-valid-and-should-return-an-error",
			uxsession: nil,
			err:       errors.New(ErrInvalidSessionId),
		},
		{
			name:      "invalid session token - returns error",
			session:   TestInvalidSession,
			uxsession: nil,
			err:       sql.ErrNoRows,
		},
		{
			name:    "revoked session token - returns error",
			session: TestRevokedSession,
			uxsession: &UxSession{
				SessionToken:  TestRevokedSession,
				CsrfToken:     TestValidCsrf,
				Authenticated: true,
				Revoked:       true,
			},
			err: errors.New(ErrSessionRevoked),
		},
		{
			name:    "expired session token - returns csrf token",
			session: TestExpiredSession,
			uxsession: &UxSession{
				SessionToken:  TestExpiredSession,
				CsrfToken:     TestValidCsrf,
				Authenticated: false,
				Revoked:       false,
			},
			err: errors.New(ErrSessionExpired),
		},
	}

	sessionSvc := NewService(&mockSqlRepository{}, &mockIndexer{}, &mockCryptor{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uxSession, err := sessionSvc.GetCsrf(tc.session)
			if err != nil {

				if err.Error() != tc.err.Error() {
					t.Errorf("expected %v, got %v", tc.err, err)
				}
			} else {

				if uxSession.SessionToken != tc.uxsession.SessionToken {
					t.Errorf("expected %s, got %s", tc.uxsession.Id, uxSession.SessionToken)
				}
				if uxSession.CsrfToken != tc.uxsession.CsrfToken {
					t.Errorf("expected %s, got %s", tc.uxsession.CsrfToken, uxSession.CsrfToken)
				}
				if uxSession.Authenticated != tc.uxsession.Authenticated {
					t.Errorf("expected %v, got %v", tc.uxsession.Authenticated, uxSession.Authenticated)
				}
				if uxSession.Revoked != tc.uxsession.Revoked {
					t.Errorf("expected %v, got %v", tc.uxsession, uxSession.Revoked)
				}
			}

		})
	}

}
