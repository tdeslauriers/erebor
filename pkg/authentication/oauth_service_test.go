package authentication

import (
	"fmt"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// mock default callback/redirect url and client
var mockOauthRedirect = config.OauthRedirect{
	CallbackUrl:      "http://localhost:8080/oauth/callback",
	CallbackClientId: "valid-client-id",
}

type mockAuthSqlRepository struct{}

func (dao *mockAuthSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockAuthSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {
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
func (c *mockRegisterCryptor) DecryptServiceData(string) (string, error) { return "", nil }
func TestBuild(t *testing.T) {

	testCases := []struct {
		name string
		err  error
	}{
		{
			name: "success",
			err:  nil,
		},
	}

	oauthService := NewOauthService(mockOauthRedirect, &mockAuthSqlRepository{}, &mockRegisterCryptor{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exchange, err := oauthService.Build()
			if err != tc.err {
				t.Errorf("expected %v, got %v", tc.err, err)
			}
			if exchange != nil {
				if exchange.ResponseType != "code" {
					t.Errorf("expected code, got %s", exchange.ResponseType)
				}

				if !validate.IsValidUuid(exchange.Nonce) {
					t.Errorf("expected valid uuid, got %s", exchange.Nonce)
				}

				if !validate.IsValidUuid(exchange.State) {
					t.Errorf("expected valid uuid, got %s", exchange.State)
				}

				if exchange.ClientId != mockOauthRedirect.CallbackClientId {
					t.Errorf("expected %s, got %s", mockOauthRedirect.CallbackClientId, exchange.ClientId)
				}

				if exchange.RedirectUrl != mockOauthRedirect.CallbackUrl {
					t.Errorf("expected %s, got %s", mockOauthRedirect.CallbackUrl, exchange.RedirectUrl)
				}
			}
		})
	}

}
