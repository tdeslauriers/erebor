package uxsession

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

const (
	TestValidSessionId = "valid-session-id"
	TestValidIndex     = "valid-session-index"
	TestValidSession   = "valid-session-token"
	TestInvalidSession = "invalid-session-token"
	TestRevokedSession = "revoked-session-token"
	TestExpiredSession = "expired-session-token"
	TestValidCsrf      = "valid-csrf-token"

	// test cases for DestroySession
	TestValidSessionNoAccessTokens          = "valid-session-uuid-no-access-tokens"
	TestValidSessionWithAccessTokens        = "valid-session-uuid-with-access-tokens"
	TestValidSessionNoOauthFlows            = "valid-session-uuid-no-oauthflows"
	TestValidSessionWithOauthFlows          = "valid-session-uuid-with-oauthflows"
	TestValidSessionFailDeleteAccessTokens  = "valid-session-uuid-fail-delete-access-tokens"
	TestValidSessionFailDeleteOauthExchange = "valid-session-uuid-fail-delete-oauth-exchange"
	TestValidSessionFailDecryptRefreshToken = "valid-session-uuid-fail-decrypt-refresh-token"

	TestValidSessionFailCallS2s                = "valid-session-uuid-fail-call-s2s"
	TestValidSessionFailDeleteAccessTokensXref = "valid-session-uuid-fail-delete-access-tokens-xref"
	TestValidSessionFailDeleteOauthflowXref    = "valid-session-uuid-fail-delete-oauthflow-xref"
	TestValidSessionFailDeleteUxsession        = "valid-session-uuid-fail-delete-uxsession"
)

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

	sessionSvc := NewService(nil, &mockSqlRepository{}, &mockIndexer{}, &mockCryptor{}, nil, nil)
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
			err:       errors.New(ErrInvalidSession),
		},
		{
			name:      "too short session token - returns validation error",
			session:   "short",
			uxsession: nil,
			err:       errors.New(ErrInvalidSession),
		},
		{
			name:      "too long session token - returns validation error",
			session:   "this-session-token-is-too-long-to-be-valid-and-should-return-an-error",
			uxsession: nil,
			err:       errors.New(ErrInvalidSession),
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

	sessionSvc := NewService(nil, &mockSqlRepository{}, &mockIndexer{}, &mockCryptor{}, nil, nil)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uxSession, err := sessionSvc.GetCsrf(tc.session)
			if err != nil {

				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("test failed: expected error '%v' to contain '%v'", err, tc.err.Error())
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

func TestIsValidCsrf(t *testing.T) {

	testCases := []struct {
		name    string
		session string
		csrf    string
		valid   bool
		err     error
	}{
		{
			name:    "valid session and csrf",
			session: TestValidSession,
			csrf:    TestValidCsrf,
			valid:   true,
			err:     nil,
		},
		{
			name:    "invalid session - empty session token",
			session: "",
			csrf:    TestValidCsrf,
			valid:   false,
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "invalid session - too long session token",
			session: "this-session-token-is-too-long-to-be-valid-and-should-return-an-error",
			csrf:    TestValidCsrf,
			valid:   false,
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "invalid session - empty csrf token",
			session: TestValidSession,
			csrf:    "",
			valid:   false,
			err:     errors.New(ErrInvalidCsrf),
		},
		{
			name:    "invalid session - too long csrf token",
			session: TestValidSession,
			csrf:    "this-csrf-token-is-too-long-to-be-valid-and-should-return-an-error",
			valid:   false,
			err:     errors.New(ErrInvalidCsrf),
		},
		{
			name:    "invalid session - sessoin not in db",
			session: TestInvalidSession,
			csrf:    TestValidCsrf,
			valid:   false,
			err:     sql.ErrNoRows,
		},
		{
			name:    "invalid session - session revoked",
			session: TestRevokedSession,
			csrf:    TestValidCsrf,
			valid:   false,
			err:     errors.New(ErrSessionRevoked),
		},
		{
			name:    "invalid session - session expired",
			session: TestExpiredSession,
			csrf:    TestValidCsrf,
			valid:   false,
			err:     errors.New(ErrSessionExpired),
		},
		{
			name:    "invalid csrf - csrf provided does not match session's csrf",
			session: TestValidSession,
			csrf:    "invalid-csrf-token",
			valid:   false,
			err:     errors.New(ErrCsrfMismatch),
		},
	}

	sessionSvc := NewService(nil, &mockSqlRepository{}, &mockIndexer{}, &mockCryptor{}, nil, nil)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := sessionSvc.IsValidCsrf(tc.session, tc.csrf)
			if !valid && err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("test failed: expected error '%v' to contain '%v'", err, tc.err.Error())
				}

			}
		})
	}
}

func TestIsValid(t *testing.T) {

	testCases := []struct {
		name    string
		session string
		valid   bool
		err     error
	}{
		{
			name:    "success - valid session",
			session: TestValidSession,
			valid:   true,
			err:     nil,
		},
		{
			name:    "failed - invalid session - empty session token",
			session: "",
			valid:   false,
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "failed - invalid session - too long session token",
			session: "this-session-token-is-too-long-to-be-valid-and-should-return-an-error",
			valid:   false,
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "failed - invalid session - session not in db",
			session: TestInvalidSession,
			valid:   false,
			err:     errors.New(ErrSessionNotFound),
		},
		{
			name:    "failed - invalid session - session revoked",
			session: TestRevokedSession,
			valid:   false,
			err:     errors.New(ErrSessionRevoked),
		},
		{
			name:    "failed - invalid session - session expired",
			session: TestExpiredSession,
			valid:   false,
			err:     errors.New(ErrSessionExpired),
		},
	}

	sessionSvc := NewService(nil, &mockSqlRepository{}, &mockIndexer{}, nil, nil, nil)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := sessionSvc.IsValid(tc.session)
			if !valid && err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("test failed: expected error '%v' to contain '%v'", err, tc.err.Error())
				}
			}
		})
	}
}

func TestRevokeSession(t *testing.T) {

	testCases := []struct {
		name    string
		session string
		err     error
	}{
		{
			name:    "success - session revoked",
			session: TestValidSession,
			err:     nil,
		},
		{
			name:    "invalid session - empty session token",
			session: "",
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "invalid session - too long session token",
			session: "this-session-token-is-too-long-to-be-valid-and-should-return-an-error",
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "invalid session - failed index",
			session: "failed-index-generation",
			err:     errors.New(ErrGenIndex),
		},
		// stmt.Exec(args...) returns successfully even when no rows are affected by returning the count as zero, not an error
		// carapace's current impl dumps the row count.
	}

	sessionSvc := NewService(nil, &mockSqlRepository{}, &mockIndexer{}, &mockCryptor{}, nil, nil)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := sessionSvc.RevokeSession(tc.session)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("test failed: expected error '%v' to contain '%v'", err, tc.err.Error())
				}
			}
		})
	}
}

func TestDestroySession(t *testing.T) {

	testCases := []struct {
		name    string
		session string
		err     error
	}{
		{
			name:    "success - no access tokens on record",
			session: TestValidSessionNoAccessTokens,
			err:     nil,
		},
		{
			name:    "success - access tokens on record",
			session: TestValidSessionWithAccessTokens,
			err:     nil,
		},
		{
			name:    "success - no oauthflow records",
			session: TestValidSessionNoOauthFlows,
			err:     nil,
		},
		{
			name:    "success - oauthflow records exist",
			session: TestValidSessionWithOauthFlows,
			err:     nil,
		},
		{
			name:    "invalid session - empty session token",
			session: "",
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "invalid session - too long session token",
			session: "this-session-token-is-too-long-to-be-valid-and-should-return-an-error",
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "invalid session - failed index",
			session: "failed-index-generation",
			err:     errors.New(ErrGenIndex),
		},
		{
			name:    "session not in db - returns error",
			session: TestInvalidSession,
			err:     sql.ErrNoRows,
		},
		{
			name:    "valid session id - failed to delete access tokens",
			session: TestValidSessionFailDeleteAccessTokens,
			err:     errors.New(ErrDeleteAccessToken),
		},
		{
			name:    "valid session id - failed to decrypt refresh token",
			session: TestValidSessionFailDecryptRefreshToken,
			err:     errors.New("failed to decrypt"),
		},
		// no good way to test/hook failure to get service token
		{
			name:    "valid session id - failed call to s2s service",
			session: TestValidSessionFailCallS2s,
			err:     errors.New("call to identity service /refresh/destory endpoint failed"),
		},
		{
			name:    "valid session id - failed to delete uxsession_accesstoken xref",
			session: TestValidSessionFailDeleteAccessTokensXref,
			err:     errors.New(ErrDeleteUxsessionAccesstokenXref),
		},
		{
			name:    "valid session id - failed to delete oauth exchange records",
			session: TestValidSessionFailDeleteOauthExchange,
			err:     errors.New(ErrDeleteOauthExchange),
		},
		{
			name:    "valid session id - failed to delete uxsession_oauthflow xref",
			session: TestValidSessionFailDeleteOauthflowXref,
			err:     errors.New("failed to delete oauth flow id"),
		},
		{
			name:    "valid session id - failed to delete uxsession record",
			session: TestValidSessionFailDeleteUxsession,
			err:     errors.New("failed to delete authenticated(true) session id"),
		},
	}

	sessionSvc := NewService(nil, &mockSqlRepository{}, &mockIndexer{}, &mockCryptor{}, &mockS2sProvider{}, &mockS2sCaller{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := sessionSvc.DestroySession(tc.session)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("test failed: expected error '%v' to contain '%v'", err, tc.err.Error())
				}
			}
		})
	}
}

// moved mocks down here to keep the test file clean
type mockSqlRepository struct{}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	switch r := records.(type) {
	case *[]LiveAccessToken:

		if args[0] == TestValidSessionWithAccessTokens {

			// slice is declared, will have one element
			*records.(*[]LiveAccessToken) = []LiveAccessToken{
				{
					Id:            123,
					UxsessionId:   "valid-uxsession-uuid",
					AccessTokenId: "valid-accesstoken-uuid",
					RefreshToken:  "encrypted-valid-refresh-token",
				},
			}
		} else if args[0] == TestValidSessionFailDeleteAccessTokens {
			// slice is declared, will have one element
			*records.(*[]LiveAccessToken) = []LiveAccessToken{
				{
					Id:            123,
					UxsessionId:   "valid-uxsession-uuid",
					AccessTokenId: "invalid-accesstoken-uuid",
					RefreshToken:  "encrypted-valid-refresh-token",
				},
			}
		} else if args[0] == TestValidSessionFailDecryptRefreshToken {
			// slice is declared, will have one element
			*records.(*[]LiveAccessToken) = []LiveAccessToken{
				{
					Id:            123,
					UxsessionId:   "valid-uxsession-uuid",
					AccessTokenId: "valid-accesstoken-uuid",
					RefreshToken:  "invalid-refresh-token",
				},
			}
		} else if args[0] == TestValidSessionFailCallS2s {
			// slice is declared, will have one element
			*records.(*[]LiveAccessToken) = []LiveAccessToken{
				{
					Id:            123,
					UxsessionId:   "valid-uxsession-uuid",
					AccessTokenId: "invalid-accesstoken-uuid",
					RefreshToken:  "encrypted-invalid-refresh-token",
				},
			}
		} else if args[0] == TestValidSessionFailDeleteAccessTokensXref {
			// slice is declared, will have one element
			*records.(*[]LiveAccessToken) = []LiveAccessToken{
				{
					Id:            456, // fail id number
					UxsessionId:   "valid-uxsession-uuid",
					AccessTokenId: "invalid-accesstoken-uuid",
					RefreshToken:  "encrypted-invalid-refresh-token",
				},
			}
		}
		return nil
	case *[]UxsesionOauthFlow:

		if args[0] == TestValidSessionWithOauthFlows {

			*records.(*[]UxsesionOauthFlow) = []UxsesionOauthFlow{
				{
					Id:              123,
					UxsessionId:     "valid-uxsession-uuid",
					OauthExchangeId: "valid-oauthexchange-uuid",
				},
			}
		} else if args[0] == TestValidSessionFailDeleteOauthExchange {
			*records.(*[]UxsesionOauthFlow) = []UxsesionOauthFlow{
				{
					Id:              123,
					UxsessionId:     "valid-uxsession-uuid",
					OauthExchangeId: TestValidSessionFailDeleteOauthExchange,
				},
			}
		} else if args[0] == TestValidSessionFailDeleteOauthflowXref {
			*records.(*[]UxsesionOauthFlow) = []UxsesionOauthFlow{
				{
					Id:              123,
					UxsessionId:     "valid-uxsession-uuid",
					OauthExchangeId: TestValidSessionFailDeleteOauthflowXref,
				},
			}
		}
		return nil
	default:
		return fmt.Errorf("unexpected record type: %T", r)
	}

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
		return nil
	case "index-" + TestValidSessionNoAccessTokens:
		testResults := []string{TestValidSessionNoAccessTokens, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionWithAccessTokens:
		testResults := []string{TestValidSessionWithAccessTokens, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionNoOauthFlows:
		testResults := []string{TestValidSessionNoOauthFlows, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionWithOauthFlows:
		testResults := []string{TestValidSessionWithOauthFlows, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailDeleteAccessTokens:
		testResults := []string{TestValidSessionFailDeleteAccessTokens, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailDeleteOauthExchange:
		testResults := []string{TestValidSessionFailDeleteOauthExchange, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailDecryptRefreshToken:
		testResults := []string{TestValidSessionFailDecryptRefreshToken, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailCallS2s:
		testResults := []string{TestValidSessionFailCallS2s, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailDeleteAccessTokensXref:
		testResults := []string{TestValidSessionFailDeleteAccessTokensXref, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailDeleteOauthflowXref:
		testResults := []string{TestValidSessionFailDeleteOauthflowXref, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
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
		return nil
	case "index-" + TestValidSessionFailDeleteUxsession:
		testResults := []string{TestValidSessionFailDeleteUxsession, TestValidIndex, "encrypted-" + TestValidSession, "encrypted-" + TestValidCsrf}
		for i := 0; i < uxsession.NumField(); i++ {
			if i == 4 {
				now := time.Now()
				unexpired := now.Add(-30 * time.Minute)
				uxsession.Field(i).Set(reflect.ValueOf(data.CustomTime{Time: unexpired}))
			} else if i == 5 || i == 6 {
				uxsession.Field(i).SetBool(true)
			} else {
				uxsession.Field(i).SetString(testResults[i])
			}
		}
		return nil

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
		return nil
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
		return nil
	default:
	}

	return nil
}
func (dao *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockSqlRepository) InsertRecord(query string, record interface{}) error { return nil }
func (dao *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error {
	return nil
}
func (dao *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error {

	if args[0] == TestValidSessionFailDeleteAccessTokens {
		return errors.New(ErrDeleteAccessToken)
	}

	if args[0] == TestValidSessionFailDeleteOauthExchange {
		return errors.New(ErrDeleteOauthExchange)

	}

	if args[0] == 456 {
		return errors.New(ErrDeleteUxsessionAccesstokenXref)
	}

	if args[0] == TestValidSessionFailDeleteOauthExchange {
		return errors.New(ErrDeleteOauthExchange)
	}

	if args[0] == TestValidSessionFailDeleteUxsession {
		return errors.New("failed to delete authenticated(true) session")
	}

	return nil
}

func (dao *mockSqlRepository) Close() error { return nil }

type mockCryptor struct{}

func (c *mockCryptor) EncryptServiceData(plaintext string) (string, error) {
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}
func (c *mockCryptor) DecryptServiceData(encrypted string) (string, error) {

	return encrypted[10:], nil
}

type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(record string) (string, error) {
	if record == "failed-index-generation" {
		return "", errors.New(ErrGenIndex)
	}
	return fmt.Sprintf("index-%s", record), nil
}

type mockS2sProvider struct{}

func (p *mockS2sProvider) GetServiceToken(svc string) (string, error) {
	return "valid-access-token", nil
}

type mockS2sCaller struct{}

func (m *mockS2sCaller) GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error {
	return nil
}

func (m *mockS2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {

	if cmd.(types.DestroyRefreshCmd).DestroyRefreshToken == "invalid-refresh-token" {
		return errors.New("call to identity service /refresh/destory endpoint failed")
	}
	return nil
}

func (m *mockS2sCaller) RespondUpstreamError(err error, w http.ResponseWriter) {}
