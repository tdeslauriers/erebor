package uxsession

import (
	"fmt"
	"testing"
)

type mockSqlRepository struct{}

func (dao *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}

// mocks the SelectRecord method of the SqlRepository interface used by Validate Credentials func
func (dao *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {
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
func (c *mockCryptor) DecryptServiceData(string) (string, error) { return "", nil }

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

	sessionSvc := NewUxSessionService(&mockSqlRepository{}, &mockIndexer{}, &mockCryptor{})
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
