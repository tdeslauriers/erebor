package uxsession

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

const (
	ValidAccessTokenId      = "valid-access-token-id"
	ValidAccessToken        = "valid-access-token"
	ValidAccessTokenRevoked = false
	ValidRefresh            = "valid-refresh-token"
	ValidRefreshRevoked     = false
	ValidRefreshClaimed     = false
)

var (
	validAccessTokenExpires data.CustomTime = data.CustomTime{Time: time.Now().Add(1 * time.Hour)}
	validRefreshExpires                     = data.CustomTime{Time: time.Now().Add(24 * time.Hour)}
)

func TestGetToken(t *testing.T) {

	testCases := []struct {
		name    string
		session string
		access  string
		err     error
	}{
		{
			name:    "success - returns valid access token",
			session: "valid-session-token",
			access:  "valid-access-token",
			err:     nil,
		},
		{
			name:    "failed - invalid session token",
			session: "too-short",
			access:  "",
			err:     errors.New(ErrInvalidSession),
		},
		{
			name:    "failed - failed index generation",
			session: "failed-index-generation",
			access:  "",
			err:     errors.New(ErrGenIndex),
		},
		{
			name:    "failed - session not found",
			session: "session-not-found",
			access:  "",
			err:     errors.New(ErrSessionNotFound),
		},
		{
			name:    "failed - session revoked",
			session: "session-token-revoked",
			access:  "",
			err:     errors.New(ErrSessionRevoked),
		},
		{
			name:    "failed - session not authenticated",
			session: "session-not-authenticated",
			access:  "",
			err:     errors.New(ErrSessionNotAuthenticated),
		},
		{
			name:    "failed - emtpy access token",
			session: "empty-access-token",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - access token revoked",
			session: "access-token-revoked",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - access token expired",
			session: "access-token-expired",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - decrypt access token",
			session: "failed-to-decrypt-access-token",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - empty refresh token",
			session: "empty-refresh-token",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - refresh token revoked",
			session: "refresh-token-revoked",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - refresh token claimed",
			session: "refresh-token-claimed",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "failed - refresh token expired",
			session: "refresh-token-expired",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		// no hook to force s2s token call to fail: tested in carapace anyway.
		{
			name:    "failed - call to identity",
			session: "failed-to-call-identity",
			access:  "",
			err:     errors.New(ErrAccessRefreshNotFound),
		},
		{
			name:    "success - call to identity success",
			session: "call-identity-success",
			access:  "valid-access-token",
			err:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			cfg := config.OauthRedirect{
				CallbackClientId: "valid-callback-client-id",
			}

			svc := NewService(&cfg, &mockTokenSqlRepository{}, &mockTokenIndexer{}, &mockTokenCryptor{}, &mockS2sTokenProvider{}, &mockIdentityServiceCaller{})

			_, err := svc.GetAccessToken(tc.session)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("expected error: %v, got: %v", tc.err, err)
				}
			}
		})
	}
}

func TestPersistToken(t *testing.T) {

	testCases := []struct {
		name     string
		access   *provider.UserAuthorization
		expected *AccessToken
		err      error
	}{
		{
			name: "success - valid access token",
			access: &provider.UserAuthorization{
				Jti:                "valid-jti",
				AccessToken:        ValidAccessToken,
				AccessTokenExpires: validAccessTokenExpires,
				Refresh:            ValidRefresh,
				RefreshExpires:     validRefreshExpires,
			},
			expected: &AccessToken{
				Id:             ValidAccessTokenId,
				AccessToken:    "encrypted-" + ValidAccessToken,
				AccessExpries:  validAccessTokenExpires,
				AccessRevoked:  ValidAccessTokenRevoked,
				RefreshToken:   "encrypted-" + ValidRefresh,
				RefreshExpires: validRefreshExpires,
				RefreshRevoked: ValidRefreshRevoked,
				RefreshClaimed: ValidRefreshClaimed,
			},
			err: nil,
		},
		{
			name: "error - failed to encrypt access token",
			access: &provider.UserAuthorization{
				Jti:                "valid-jti",
				AccessToken:        "fail-to-encrypt-access-token",
				AccessTokenExpires: validAccessTokenExpires,
				Refresh:            ValidRefresh,
				RefreshExpires:     validRefreshExpires,
			},
			expected: nil,
			err:      errors.New(ErrEncryptAccessToken),
		},
		{
			name: "error - failed to insert access token",
			access: &provider.UserAuthorization{
				Jti:                "valid-jti",
				AccessToken:        "fail-to-insert-access-token",
				AccessTokenExpires: validAccessTokenExpires,
				Refresh:            ValidRefresh,
				RefreshExpires:     validRefreshExpires,
			},
			expected: nil,
			err:      errors.New("failed to persist access token"),
		},
	}

	svc := NewService(nil, &mockTokenSqlRepository{}, &mockTokenIndexer{}, &mockTokenCryptor{}, nil, nil)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			access, err := svc.PersistToken(tc.access)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("expected error: %v, got: %v", tc.err, err)
				}
			}

			if access != nil {
				t.Log(access)
				if access.AccessToken != tc.expected.AccessToken {
					t.Errorf("expected access token: %s, got: %s", tc.expected.AccessToken, access.AccessToken)
				}
				if access.RefreshToken != tc.expected.RefreshToken {
					t.Errorf("expected refresh token: %s, got: %s", tc.expected.RefreshToken, access.RefreshToken)
				}
			}
		})
	}
}

func TestPersistXref(t *testing.T) {
	testCases := []struct {
		name string
		xref *SessionAccessXref
		err  error
	}{
		{
			name: "success - valid xref",
			xref: &SessionAccessXref{
				UxsessionId:   "valid-uxsession-id",
				AccessTokenId: "valid-access-token-id",
			},
			err: nil,
		},
		{
			name: "error - invalid session id",
			xref: &SessionAccessXref{
				UxsessionId:   "invalid",
				AccessTokenId: "valid-access-token-id",
			},
			err: errors.New(ErrInvalidSessionId),
		},
		{
			name: "error - failed to insert xref",
			xref: &SessionAccessXref{
				UxsessionId:   "fail-to-insert-xref",
				AccessTokenId: "valid-access-token-id",
			},
			err: errors.New("persist uxsession_access_token xref"),
		},
	}

	svc := NewService(nil, &mockTokenSqlRepository{}, &mockTokenIndexer{}, &mockTokenCryptor{}, nil, nil)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.PersistXref(*tc.xref)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("expected error: %v, got: %v", tc.err, err)
				}
			}
		})
	}
}

// Bumping mocks to the bottom to remove clutter

// mock sql repository for testing
type mockTokenSqlRepository struct{}

func (dao *mockTokenSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	now := time.Now().UTC()
	switch args[0] {
	case "index-valid-session-token":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessTokenId:        "valid-access-token-id",
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "encrypted-valid-refresh-token",
				RefreshExpires:       data.CustomTime{Time: now.Add(24 * time.Hour)},
				RefreshRevoked:       false,
				RefreshClaimed:       false,
			},
		}
		return nil

	case "index-session-token-revoked":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:    "valid-uxsession-id",
				SessionRevoked: true,
			},
		}
		return nil

	case "index-session-not-authenticated":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionAuthenticated: false,
				SessionRevoked:       false,
			},
		}
		return nil

	case "index-session-token-expired":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now.Add(-2 * time.Hour)},
				SessionAuthenticated: true,
				SessionRevoked:       false,
			},
		}
		return nil

	case "index-empty-access-token":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "",
			},
		}
		return nil

	case "index-access-token-revoked":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessRevoked:        true,
			},
		}
		return nil

	case "index-access-token-expired":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessRevoked:        false,
				AccessExpires:        data.CustomTime{Time: now.Add(-2 * time.Hour)},
			},
		}
		return nil

	case "index-failed-to-decrypt-access-token":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "failed-to-decrypt-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(15 * time.Minute)},
				AccessRevoked:        false,
			},
		}
		return nil

	case "index-empty-refresh-token":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(-15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "",
			},
		}
		return nil

	case "index-refresh-token-revoked":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(-15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "encrypted-valid-refresh-token",
				RefreshRevoked:       true,
			},
		}
		return nil

	case "index-refresh-token-claimed":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(-15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "encrypted-valid-refresh-token",
				RefreshRevoked:       false,
				RefreshClaimed:       true,
			},
		}
		return nil

	case "index-refresh-token-expired":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(-15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "encrypted-valid-refresh-token",
				RefreshExpires:       data.CustomTime{Time: now.Add(-2 * time.Hour)},
				RefreshRevoked:       false,
				RefreshClaimed:       false,
			},
		}
		return nil

	case "index-failed-to-call-identity":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(-15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "encrypted-invalid-refresh-token",
				RefreshExpires:       data.CustomTime{Time: now.Add(2 * time.Hour)},
				RefreshRevoked:       false,
				RefreshClaimed:       false,
			},
		}
		return nil

	case "index-call-identity-success":
		*records.(*[]UxsessionAccesstoken) = []UxsessionAccesstoken{
			{
				UxsessionId:          "valid-uxsession-id",
				SessionCreatedAt:     data.CustomTime{Time: now},
				SessionAuthenticated: true,
				SessionRevoked:       false,
				AccessToken:          "encrypted-valid-access-token",
				AccessExpires:        data.CustomTime{Time: now.Add(-15 * time.Minute)},
				AccessRevoked:        false,
				RefreshToken:         "encrypted-valid-refresh-token",
				RefreshExpires:       data.CustomTime{Time: now.Add(2 * time.Hour)},
				RefreshRevoked:       false,
				RefreshClaimed:       false,
			},
		}
		return nil

	default:
		return errors.New(ErrSessionNotFound)
	}
}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockTokenSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	return nil
}
func (dao *mockTokenSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (dao *mockTokenSqlRepository) InsertRecord(query string, record interface{}) error {

	switch r := record.(type) {
	case AccessToken:
		if r.AccessToken == "encrypted-fail-to-insert-access-token" {
			return errors.New("failed to persist access token")
		} else {
			return nil
		}

	case SessionAccessXref:
		if r.UxsessionId == "encrypted-fail-to-insert-xref" {
			return errors.New("persist uxsession_access_token xref")
		} else {
			return nil
		}
	default:
		return errors.New("unknown record type")
	}
}
func (dao *mockTokenSqlRepository) UpdateRecord(query string, args ...interface{}) error {
	return nil
}
func (dao *mockTokenSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (dao *mockTokenSqlRepository) Close() error                                         { return nil }

// mock cryptor for testing
type mockTokenCryptor struct{}

func (c *mockTokenCryptor) EncryptServiceData(data []byte) (string, error) {
	if string(data) == "fail-to-encrypt-access-token" {
		return "", errors.New(ErrGenPrimaryKey)
	}
	return fmt.Sprintf("encrypted-%s", data), nil
}
func (c *mockTokenCryptor) DecryptServiceData(encrypted string) ([]byte, error) {
	if encrypted == "failed-to-decrypt-access-token" {
		return nil, errors.New(ErrDecryptAccessToken)
	}
	return []byte(encrypted[10:]), nil
}

// mock token indexer for testing
type mockTokenIndexer struct{}

func (i *mockTokenIndexer) ObtainBlindIndex(record string) (string, error) {
	if record == "failed-index-generation" {
		return "", errors.New(ErrGenIndex)
	}
	return fmt.Sprintf("index-%s", record), nil
}

type mockS2sTokenProvider struct{}

func (p *mockS2sTokenProvider) GetServiceToken(svcName string) (string, error) {
	return "valid-s2s-token", nil
}

type mockIdentityServiceCaller struct{}

func (m *mockIdentityServiceCaller) GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error {
	return nil
}

func (m *mockIdentityServiceCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {

	if cmd.(types.UserRefreshCmd).RefreshToken == "invalid-refresh-token" {
		return errors.New("mock call to identity service failed")
	}

	return nil
}

func (m *mockIdentityServiceCaller) RespondUpstreamError(err error, w http.ResponseWriter) {}
