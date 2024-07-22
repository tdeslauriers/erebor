package oauth

import (
	"database/sql"
	"erebor/pkg/authentication/uxsession"
	"errors"

	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	TestValidSessionXref     string = "valid-session-token-with-xref-to-oauth"
	TestValidSessionNewOauth string = "valid-session-token-with-new-oauth"
	TestSessionDoesNotExist  string = "session-does-not-exist"
	TestSessionRevoked       string = "session-is-revoked"
	TestSessionExpired       string = "session-is-expired"

	TestBuildNewOauthExchangeFailure string = "build-new-oauth-exchange-failure" // use index faileure to cause new oauth exchange to fail

	TestValidSessionId = "valid-session-id"
	TestValidIndex     = "valid-session-index"
	TestValidSession   = "valid-session-token"
	TestValidCsrf      = "valid-csrf-token"

	TestXrefOauthExchangeId   string = "xref-oauth-exchange-id"
	TestXrefOauthResponseType string = string(types.AuthCode)
	TestXrefOauthNonce        string = "f3b6acb9-28b2-4130-a421-ed5b4d7cf222"
	TestXrefOauthState        string = "6b638422-3f25-4156-a6e3-56e4b0531f7a"

	TestNewOauthExchangeId   string = "new-oauth-exchange-id"
	TestNewOauthResponseType string = string(types.AuthCode)

	TestValidResponseCode types.ResponseType = types.AuthCode
	TestValidState        string             = "6b638422-3f25-4156-a6e3-56e4b0531f7a"
	TestValidNonce        string             = "f3b6acb9-28b2-4130-a421-ed5b4d7cf222"
)

// mock default callback/redirect url and client
var mockOauthRedirect = config.OauthRedirect{
	CallbackUrl:      "http://localhost:8080/oauth/callback",
	CallbackClientId: "valid-callback-client-id",
}

type mockAuthSqlRepository struct{}

func (dao *mockAuthSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// first query is needed to check for it's value for when it is successful, but the second query fails
const (
	TestFirstQuery string = `
		SELECT 
			o.uuid, 
			o.state_index, 
			o.response_type, 
			o.nonce, 
			o.state, 
			o.client_id, 
			o.redirect_url, 
			o.created_at,
		FROM oauthflow o 
			LEFT OUTER JOIN uxsession_oauthflow uo ON o.uuid = uo.oauthflow_uuid
			LEFT OUTER JOIN uxsession u ON uo.uxsession_uuid = u.uuid
		WHERE u.session_index = ?
			AND u.revoked = false
			AND u.created_at > NOW() - INTERVAL 1 HOUR
			AND o.created_at > NOW() - INTERVAL 1 HOUR`
)

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockAuthSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	switch {
	case args[0] == "index-"+TestValidSessionXref:
		// need to reflect record interface's type to mock sql query hydrating the record
		exchange := reflect.ValueOf(record).Elem()
		testResults := []string{
			TestXrefOauthExchangeId,
			"index-" + TestXrefOauthState,
			"encrypted-" + TestXrefOauthResponseType,
			"encrypted-" + TestXrefOauthNonce,
			"encrypted-" + TestXrefOauthState,
			"encrypted-" + mockOauthRedirect.CallbackClientId,
			"encrypted-" + mockOauthRedirect.CallbackUrl} // created at not retuned by this service

		for i := 0; i < len(testResults); i++ {
			exchange.Field(i).SetString(testResults[i])
		}
		return nil

	case args[0] == "index-"+TestValidSessionNewOauth:
		if query == TestFirstQuery {
			return sql.ErrNoRows
		} else {
			// need to reflect record interface's type to mock sql query hydrating the record
			uxsession := reflect.ValueOf(record).Elem()
			testResults := []string{
				TestValidSessionId,
				TestValidIndex,
				"encrypted-" + TestValidSession,
				"encrypted-" + TestValidCsrf}

			for i := 0; i < uxsession.NumField(); i++ {
				if i == 4 {
					now := time.Now()
					uxsession.Field(i).Set(reflect.ValueOf(data.CustomTime{Time: now}))
				} else if i == 5 || i == 6 {
					uxsession.Field(i).SetBool(false)
				} else {
					uxsession.Field(i).SetString(testResults[i])
				}
			}
			return nil
		}
	case args[0] == "index-"+TestSessionDoesNotExist:
		return sql.ErrNoRows
	case args[0] == "index-"+TestSessionRevoked:
		if query == TestFirstQuery {
			return sql.ErrNoRows
		} else {

			// need to refrect record interface's type to mock sql query hydrating the record
			uxsession := reflect.ValueOf(record).Elem()

			testResults := []string{TestSessionRevoked, TestValidIndex, "encrypted-" + TestSessionRevoked, "encrypted-" + TestValidCsrf}
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
		}
	case args[0] == "index-"+TestSessionExpired:
		if query == TestFirstQuery {
			return sql.ErrNoRows
		} else {
			// need to refrect record interface's type to mock sql query hydrating the record
			uxsession := reflect.ValueOf(record).Elem()
			testResults := []string{TestSessionRevoked, TestValidIndex, "encrypted-" + TestSessionExpired, "encrypted-" + TestValidCsrf}
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
		}
	case args[0] == "index-"+TestValidSession:
		// need to reflect record interface's type to mock sql query hydrating the record
		exchange := reflect.ValueOf(record).Elem()
		testResults := []string{
			TestXrefOauthExchangeId,
			"index-" + TestXrefOauthState,
			"encrypted-" + "code",
			"encrypted-" + TestValidNonce,
			"encrypted-" + TestValidState,
			"encrypted-" + mockOauthRedirect.CallbackClientId,
			"encrypted-" + mockOauthRedirect.CallbackUrl} // created at not retuned by this service

		for i := 0; i < len(testResults); i++ {
			exchange.Field(i).SetString(testResults[i])
		}
		return nil
	}
	return nil
}
func (dao *mockAuthSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockAuthSqlRepository) InsertRecord(query string, record interface{}) error  { return nil }
func (dao *mockAuthSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockAuthSqlRepository) Close() error                                         { return nil }

type mockRegisterCryptor struct{}

func (c *mockRegisterCryptor) EncryptServiceData(plaintext string) (string, error) {
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}
func (c *mockRegisterCryptor) DecryptServiceData(encrypted string) (string, error) {

	return strings.ReplaceAll(encrypted, "encrypted-", ""), nil
}

type mockIndexer struct{}

func (i *mockIndexer) ObtainBlindIndex(record string) (string, error) {

	if record == TestBuildNewOauthExchangeFailure || record == "failed-to-generate-session-lookup-index" {
		return "", errors.New(uxsession.ErrGenIndex)
	}
	return fmt.Sprintf("index-%s", record), nil
}

func TestObtain(t *testing.T) {

	testCases := []struct {
		name         string
		sessionToken string
		*OauthExchange
		err error
	}{
		{
			name:         "valid session has associated oauth exchange",
			sessionToken: TestValidSessionXref,
			OauthExchange: &OauthExchange{
				Id:           TestXrefOauthExchangeId,
				ResponseType: TestXrefOauthResponseType,
				Nonce:        TestXrefOauthNonce,
				State:        TestXrefOauthState,
				ClientId:     mockOauthRedirect.CallbackClientId,
				RedirectUrl:  mockOauthRedirect.CallbackUrl,
			},
			err: nil,
		},
		{
			name:         "valid session creates new oauth exchange",
			sessionToken: TestValidSessionNewOauth,
			OauthExchange: &OauthExchange{
				// gernerated values/uuid's in function, only has to be non-nil
				Id:           TestNewOauthExchangeId,
				ResponseType: TestNewOauthResponseType,
				ClientId:     mockOauthRedirect.CallbackClientId,
				RedirectUrl:  mockOauthRedirect.CallbackUrl,
			},
			err: nil,
		},
		{
			name:          "invalid session - empty session token",
			sessionToken:  "",
			OauthExchange: nil,
			err:           errors.New(uxsession.ErrInvalidSession),
		},
		{
			name:          "invalid session - session token too long",
			sessionToken:  "invalid-session-token-too-long -- this should generate an error because it is too long",
			OauthExchange: nil,
			err:           errors.New(uxsession.ErrInvalidSession),
		},
		{
			name:          "invalid session - session does not exist",
			sessionToken:  TestSessionDoesNotExist,
			OauthExchange: nil,
			err:           errors.New(uxsession.ErrSessionNotFound),
		},
		{
			name:          "invalid session - session is revoked",
			sessionToken:  TestSessionRevoked,
			OauthExchange: nil,
			err:           errors.New(uxsession.ErrSessionRevoked),
		},
		{
			name:          "invalid session - session is expired",
			sessionToken:  TestSessionExpired,
			OauthExchange: nil,
			err:           errors.New(uxsession.ErrSessionExpired),
		},
		{
			name:          "valid session - failure to build new oauth exchange",
			sessionToken:  TestBuildNewOauthExchangeFailure,
			OauthExchange: nil,
			err:           errors.New(uxsession.ErrGenIndex),
		},
	}

	oauthService := NewService(mockOauthRedirect, &mockAuthSqlRepository{}, &mockRegisterCryptor{}, &mockIndexer{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exchange, err := oauthService.Obtain(tc.sessionToken)
			if err != nil {
				t.Logf("error: %s", err.Error())
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("expected error '%s' to contain '%s'", err.Error(), tc.err.Error())
				}
			}
			if exchange != nil {
				// only the following fields are returned by Obtain func
				if exchange.ResponseType != tc.OauthExchange.ResponseType {
					t.Errorf("expected %s, got %s", tc.OauthExchange.ResponseType, exchange.ResponseType)
				}

				if !validate.IsValidUuid(exchange.Nonce) {
					t.Errorf("expected valid uuid, got %s", exchange.Nonce)
				}

				if !validate.IsValidUuid(exchange.State) {
					t.Errorf("expected valid uuid, got %s", exchange.State)
				}

				if exchange.ClientId != tc.OauthExchange.ClientId {
					t.Errorf("expected %s, got %s", tc.OauthExchange.ClientId, exchange.ClientId)
				}

				if exchange.RedirectUrl != tc.OauthExchange.RedirectUrl {
					t.Errorf("expected %s, got %s", tc.OauthExchange.RedirectUrl, exchange.RedirectUrl)
				}
			}
		})
	}

}

func TestValidate(t *testing.T) {

	testCases := []struct {
		name    string
		authCmd *types.AuthCodeCmd
		err     error
	}{
		{
			name: "valid auth code cmd",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: nil,
		},
		{
			name: "empty session token",
			authCmd: &types.AuthCodeCmd{
				Session:      "",
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "empty auth code",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "empty response type",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: "",
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "empty state",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        "",
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "empty nonce",
			authCmd: &types.AuthCodeCmd{
				Session: TestValidSession,

				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        "",
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "empty client id",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     "",
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "empty redirect url",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     "",
			},
			err: errors.New(ErrInvalidAuthCodeCmd),
		},
		{
			name: "failed to generate session lookup index",
			authCmd: &types.AuthCodeCmd{
				Session:      "failed-to-generate-session-lookup-index",
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrGenSessionIndex),
		},
		{
			name: "invalid session - not found, revoked, or expired",
			authCmd: &types.AuthCodeCmd{
				Session:      TestSessionDoesNotExist,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(uxsession.ErrSessionNotFound),
		},
		{
			name: "invalid response type",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: "fail",
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrResponseTypeMismatch),
		},
		{
			name: "invalide state",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        "invalid-state-code",
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrStateCodeMismatch),
		},
		{
			name: "invalid nonce",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        "invalid-nonce-code",
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrNonceMismatch),
		},
		{
			name: "invalid client id",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     "invalid-client-id",
				Redirect:     mockOauthRedirect.CallbackUrl,
			},
			err: errors.New(ErrClientIdMismatch),
		},
		{
			name: "invalid redirect url",
			authCmd: &types.AuthCodeCmd{
				Session:      TestValidSession,
				AuthCode:     "authcode not tested/validated by this service",
				ResponseType: TestValidResponseCode,
				State:        TestValidState,
				Nonce:        TestValidNonce,
				ClientId:     mockOauthRedirect.CallbackClientId,
				Redirect:     "invalid-redirect-url",
			},
			err: errors.New(ErrRedirectUrlMismatch),
		},
	}

	oauthService := NewService(mockOauthRedirect, &mockAuthSqlRepository{}, &mockRegisterCryptor{}, &mockIndexer{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := oauthService.Validate(*tc.authCmd)
			if err != nil {
				t.Logf("error: %s", err.Error())
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("expected error '%s' to contain '%s'", err.Error(), tc.err.Error())
				}
			}
		})
	}
}
