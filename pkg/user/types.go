package user

import (
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Handler is the interface for handling user requests from the client.  Aggregates all user handler interfaces.
type Handler interface {
	PermissionsHandler
	ProfileHandler
	ResetHandler
	ScopesHandler
	UserHandler
}

func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam, task, g connect.S2sCaller) Handler {
	return &handler{
		PermissionsHandler: NewPermissionsHandler(ux, p, iam, task, g),
		ProfileHandler:     NewProfileHandler(ux, p, iam),
		ResetHandler:       NewResetHandler(ux, p, iam),
		ScopesHandler:      NewScopesHandler(ux, p, iam),
		UserHandler:        NewUserHandler(ux, p, iam),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the interface function that handles user requests from the client.
type handler struct {
	PermissionsHandler
	ProfileHandler
	ResetHandler
	ScopesHandler
	UserHandler
}

// Profile is a model for a user's profile as it is expected to be returned to the frontend ui.
// It is also the model that will be submitted back to the gateway to update service data.
type ProfileCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Id             string                   `json:"id,omitempty"`
	Username       string                   `json:"username"`
	Firstname      string                   `json:"firstname"`
	Lastname       string                   `json:"lastname"`
	BirthMonth     int                      `json:"birth_month,omitempty"`
	BirthDay       int                      `json:"birth_day,omitempty"`
	BirthYear      int                      `json:"birth_year,omitempty"`
	Slug           string                   `json:"slug,omitempty"`
	CreatedAt      data.CustomTime          `json:"created_at"`
	Enabled        bool                     `json:"enabled"`
	AccountExpired bool                     `json:"account_expired"`
	AccountLocked  bool                     `json:"account_locked"`
	Scopes         []types.Scope            `json:"scopes,omitempty"`      // will not always be returned: call specific
	Permissions    []permissions.Permission `json:"permissions,omitempty"` // will not always be returned: call specific
}

func (cmd *ProfileCmd) ValidateCmd() error {

	// light weight validation of csrf
	if len(cmd.Csrf) <= 16 || len((cmd.Csrf)) > 64 {
		return fmt.Errorf("invalid csrf token: must be between 16 and 64 characters")
	}

	// Username is immutable at this time, and will be dropped for update operations
	// only lightweight validation to make sure it isnt too long
	// may not be present on user initiated updates since using name not taken from update cmd
	if cmd.Username != "" {
		if len(cmd.Username) < validate.EmailMin || len(cmd.Username) > validate.EmailMax {
			return fmt.Errorf("invalid username: must be greater than %d and less than %d characters long", validate.EmailMin, validate.EmailMax)
		}
	}

	// validate firstname
	if err := validate.IsValidName(cmd.Firstname); err != nil {
		return fmt.Errorf("invalid firstname: %v", err)
	}

	// validate lastname
	if err := validate.IsValidName(cmd.Lastname); err != nil {
		return fmt.Errorf("invalid lastname: %v", err)
	}

	// validate either all or none of the date of birth fields are present
	if (cmd.BirthMonth != 0 && (cmd.BirthDay == 0 || cmd.BirthYear == 0)) ||
		(cmd.BirthDay != 0 && (cmd.BirthMonth == 0 || cmd.BirthYear == 0)) ||
		(cmd.BirthYear != 0 && (cmd.BirthMonth == 0 || cmd.BirthDay == 0)) {
		return fmt.Errorf("invalid birthdate: must include month, day, and year, omit date of birth info entirely")
	}

	// validate birth month if present
	if cmd.BirthMonth != 0 && (cmd.BirthMonth < 1 || cmd.BirthMonth > 12) {
		return fmt.Errorf("invalid birth month: must be between 1 and 12")
	}

	// validate birth day if present
	if cmd.BirthDay != 0 && (cmd.BirthDay < 1 || cmd.BirthDay > 31) {
		return fmt.Errorf("invalid birth day: must be between 1 and 31")
	}

	// validate birth year if present
	if cmd.BirthYear != 0 {

		// get current year
		year := time.Now().UTC().Year()
		if cmd.BirthYear < (year-120) || cmd.BirthYear > year {
			return fmt.Errorf("invalid birth year: must be between %d and %d", (year - 120), year)
		}

	}

	// validate slug is well formed if present
	// Note: only checks if it is a uuid, not if it is the correct uuid
	// Slug may or may not be present depending on the operation,
	// if it is supposed to be present, and is not, that will need to be checked elsewhere
	if cmd.Slug != "" {
		if len(cmd.Slug) < 16 || len(cmd.Slug) > 64 {
			return fmt.Errorf("invalid slug: must be between 16 and 64 characters")
		}
	}

	// CreatedAt is a timestamp, no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	return nil
}

// UserScopesCmd is a model for a user's assigned scopes as it is expected to be returned to the frontend ui.
type UserScopesCmd struct {
	Csrf       string   `json:"csrf,omitempty"`
	UserSlug   string   `json:"user_slug"`
	ScopeSlugs []string `json:"scope_slugs"`
}

// ValidateCmd performs input validation check on user scopes fields.
func (cmd *UserScopesCmd) ValidateCmd() error {

	if !validate.IsValidUuid(cmd.Csrf) {
		return fmt.Errorf("invalid csrf token")
	}

	if !validate.IsValidUuid(cmd.UserSlug) {
		return fmt.Errorf("invalid user slug")
	}

	if len(cmd.ScopeSlugs) > 0 {
		for _, slug := range cmd.ScopeSlugs {
			if !validate.IsValidUuid(slug) {
				return fmt.Errorf("invalid scope slug submitted: all slugs must be valid uuids")
			}
		}
	}

	return nil
}
