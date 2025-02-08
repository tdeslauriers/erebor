package clients

import (
	"erebor/pkg/authentication/uxsession"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

type Handler interface {
	ClientHandler
	ResetHandler
}

// NewHandler returns a new Handler.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) Handler {
	return &handler{
		ClientHandler: NewClientHandler(ux, p, c),
		ResetHandler:  NewResetHandler(ux, p, c),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	ClientHandler
	ResetHandler
}

type ServiceClientCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Id             string          `json:"id,omitempty" db:"uuid"`
	Name           string          `json:"name" db:"name"`
	Owner          string          `json:"owner" db:"owner"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
}

// ValidateCmd performs input validation check on client fields.
func (c *ServiceClientCmd) ValidateCmd() error {

	if !validate.IsValidUuid(c.Csrf) {
		return fmt.Errorf("invalid csrf token")
	}

	if c.Id != "" && !validate.IsValidUuid(c.Id) {
		return fmt.Errorf("invalid or not well formatted client id")
	}

	if valid, err := validate.IsValidServiceName(c.Name); !valid {
		return fmt.Errorf("invalid client name: %v", err)
	}

	if err := validate.IsValidName(c.Owner); err != nil {
		return fmt.Errorf("invalid client owner: %v", err)
	}

	// CreatedAt is a timestamp created programmatically,
	// no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	if c.Slug != "" && !validate.IsValidUuid(c.Slug) {
		return fmt.Errorf("invalid or not well formatted slug")
	}

	return nil
}
