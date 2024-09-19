package uxsession

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
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

// mock sql repository for testing
type mockTokenSqlRepository struct{}

func (dao *mockTokenSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
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

func (c *mockTokenCryptor) EncryptServiceData(plaintext string) (string, error) {
	if plaintext == "fail-to-encrypt-access-token" {
		return "", errors.New(ErrGenPrimaryKey)
	}
	return fmt.Sprintf("encrypted-%s", plaintext), nil
}
func (c *mockTokenCryptor) DecryptServiceData(encrypted string) (string, error) {

	return encrypted[10:], nil
}

// mock token indexer for testing
type mockTokenIndexer struct{}

func (i *mockTokenIndexer) ObtainBlindIndex(record string) (string, error) {
	if record == "failed-index-generation" {
		return "", errors.New(ErrGenIndex)
	}
	return fmt.Sprintf("index-%s", record), nil
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
