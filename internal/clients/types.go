package clients

import (
	"erebor/internal/authentication/uxsession"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Handler is an aggregate interface for handling client services.
type Handler interface {
	ClientHandler
	ResetHandler
	ScopesHandler
}

// NewHandler returns a new Handler.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, c *connect.S2sCaller) Handler {
	return &handler{
		ClientHandler: NewClientHandler(ux, p, c),
		ResetHandler:  NewResetHandler(ux, p, c),
		ScopesHandler: NewScopesHandler(ux, p, c),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface.
type handler struct {
	ClientHandler
	ResetHandler
	ScopesHandler
}

// RegisterClientCmd is a model for registering a new client.
type RegisterClientCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Id              string `json:"id,omitempty"`
	Name            string `json:"name"`
	Owner           string `json:"owner"`
	Password        string `json:"password,omitempty"`
	ConfirmPassword string `json:"confirm_password,omitempty"`
	Slug            string `json:"slug,omitempty"`
	Enabled         bool   `json:"enabled"`
	// AccountLocked is not in registration submission, or returned in registration response
	// AccountExpired is not in registration submission, or returned in registration response
	// CreatedAt is not in registration submission, or returned in registration response
	// Scopes is not in registration submission, or returned in registration response
}

// ValidateCmd performs input validation check on client registration fields.
func (c *RegisterClientCmd) ValidateCmd() error {

	if err := validate.ValidateUuid(c.Csrf); err != nil {
		return fmt.Errorf("invalid csrf token")
	}

	// Id is generated at time of registration upstream, no validation needed

	if err := validate.ValidateServiceName(c.Name); err != nil {
		return fmt.Errorf("invalid client name: %v", err)
	}

	if err := validate.ValidateName(c.Owner); err != nil {
		return fmt.Errorf("invalid client owner: %v", err)
	}

	if err := validate.ValidatePassword(c.Password); err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	if c.Password != c.ConfirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	// slug is generated at time of registration upstream, no validation needed
	return nil
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

	if err := validate.ValidateUuid(c.Csrf); err != nil {
		return fmt.Errorf("invalid csrf token")
	}

	if c.Id != "" {
		if err := validate.ValidateUuid(c.Id); err != nil {
			return fmt.Errorf("invalid or not well formatted client id")
		}
	}

	if err := validate.ValidateServiceName(c.Name); err != nil {
		return fmt.Errorf("invalid client name: %v", err)
	}

	if err := validate.ValidateName(c.Owner); err != nil {
		return fmt.Errorf("invalid client owner: %v", err)
	}

	// CreatedAt is a timestamp created programmatically,
	// no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	if c.Slug != "" {
		if err := validate.ValidateUuid(c.Slug); err != nil {
			return fmt.Errorf("invalid or not well formatted slug")
		}
	}

	return nil
}

// ClientScopesCmd is a model for updating the scopes of a client.
type ClientScopesCmd struct {
	Csrf       string   `json:"csrf,omitempty"`
	ClientSlug string   `json:"client_slug"`
	ScopeSlugs []string `json:"scope_slugs"`
}

// ValidateCmd performs input validation check on client scopes fields.
func (cmd *ClientScopesCmd) ValidateCmd() error {

	if err := validate.ValidateUuid(cmd.Csrf); err != nil {
		return fmt.Errorf("invalid csrf token")
	}

	if err := validate.ValidateUuid(cmd.ClientSlug); err != nil {
		return fmt.Errorf("invalid client slug")
	}

	if len(cmd.ScopeSlugs) > 0 {
		for _, slug := range cmd.ScopeSlugs {
			if err := validate.ValidateUuid(slug); err != nil {
				return fmt.Errorf("invalid scope slug submitted: all slugs must be valid uuids")
			}
		}
	}

	return nil
}
