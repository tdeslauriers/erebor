package user

import (
	"erebor/gen"
	"erebor/internal/authentication/uxsession"
	"fmt"
	"strings"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// Handler is the interface for handling user requests from the client.  Aggregates all user handler interfaces.
type Handler interface {
	PermissionsHandler
	ProfileHandler
	ResetHandler
	ScopesHandler
	UserHandler
}

func NewHandler(
	ux uxsession.Service,
	pvdr provider.S2sTokenProvider,
	iam *connect.S2sCaller,
	task *connect.S2sCaller,
	g *connect.S2sCaller,
	p gen.ProfilesClient,
) Handler {
	return &handler{
		PermissionsHandler: NewPermissionsHandler(ux, pvdr, iam, task, g),
		ProfileHandler:     NewProfileHandler(ux, pvdr, iam, p),
		ResetHandler:       NewResetHandler(ux, pvdr, iam),
		ScopesHandler:      NewScopesHandler(ux, pvdr, iam),
		UserHandler:        NewUserHandler(ux, pvdr, iam, task, g, p),
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

	Id             string                         `json:"id,omitempty"`
	Username       string                         `json:"username"`
	Firstname      string                         `json:"firstname"`
	Lastname       string                         `json:"lastname"`
	NickName       string                         `json:"nickname,omitempty"`
	DarkMode       bool                           `json:"dark_mode,omitempty"`
	BirthMonth     int                            `json:"birth_month,omitempty"`
	BirthDay       int                            `json:"birth_day,omitempty"`
	BirthYear      int                            `json:"birth_year,omitempty"`
	Slug           string                         `json:"slug,omitempty"`
	CreatedAt      data.CustomTime                `json:"created_at"`
	Enabled        bool                           `json:"enabled"`
	AccountExpired bool                           `json:"account_expired"`
	AccountLocked  bool                           `json:"account_locked"`
	Scopes         []scopes.Scope                 `json:"scopes,omitempty"`      // will not always be returned: call specific
	Permissions    []permissions.PermissionRecord `json:"permissions,omitempty"` // will not always be returned: call specific
}

func (cmd *ProfileCmd) ValidateCmd() error {

	// light weight validation of csrf
	if len(cmd.Csrf) <= 16 || len((strings.TrimSpace(cmd.Csrf))) > 64 {
		return fmt.Errorf("invalid csrf token: must be between 16 and 64 characters")
	}

	// Username is immutable at this time, and will be dropped for update operations
	// in the identity service, however, it is used as a lookup field for the profile service,
	// so it is required for all operations.
	if err := validate.IsValidEmail(strings.TrimSpace(cmd.Username)); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	// validate firstname
	if err := validate.IsValidName(strings.TrimSpace(cmd.Firstname)); err != nil {
		return fmt.Errorf("invalid firstname: %v", err)
	}

	// validate lastname
	if err := validate.IsValidName(strings.TrimSpace(cmd.Lastname)); err != nil {
		return fmt.Errorf("invalid lastname: %v", err)
	}

	// validate nickname - optional but if present must be validate nickname
	if strings.TrimSpace(cmd.NickName) != "" {
		if err := validate.IsValidName(strings.TrimSpace(cmd.NickName)); err != nil {
			return fmt.Errorf("invalid nickname: %v", err)
		}
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

	// DarkMode is a boolean, no validation needed

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

// ProfileResponse is a model for a user's profile as it is expected to be returned to the frontend ui.
// It is a composite of the data returned by several different services, like identity and profile.
type ProfileResponse struct {
	Id             string                         `json:"id,omitempty"`
	Username       string                         `json:"username"`
	Firstname      string                         `json:"firstname"`
	Lastname       string                         `json:"lastname"`
	NickName       string                         `json:"nickname,omitempty"`
	BirthMonth     int                            `json:"birth_month,omitempty"`
	BirthDay       int                            `json:"birth_day,omitempty"`
	BirthYear      int                            `json:"birth_year,omitempty"`
	DarkMode       bool                           `json:"dark_mode,omitempty"`
	Slug           string                         `json:"slug,omitempty"`
	CreatedAt      data.CustomTime                `json:"created_at"`
	Enabled        bool                           `json:"enabled"`
	AccountExpired bool                           `json:"account_expired"`
	AccountLocked  bool                           `json:"account_locked"`
	Addresses      []*gen.Address                 `json:"addresses,omitempty"`   // will not always be returned: call specific
	Phones         []*gen.Phone                   `json:"phones,omitempty"`      // will not always be returned: call specific
	Scopes         []scopes.Scope                 `json:"scopes,omitempty"`      // will not always be returned: call specific
	Permissions    []permissions.PermissionRecord `json:"permissions,omitempty"` // will not always be returned: call specific
}

// AddressCmd is a model for a user's address as it is expected to be submitted from
// the frontend ui when creating or updating an address.
type AddressCmd struct {
	Csrf     string      `json:"csrf,omitempty"`
	Slug     string      `json:"slug,omitempty"` // slug will be empty for creates, but required for updates
	Username string      `json:"username"`
	Address  gen.Address `json:"address"`
}

// ValidateCmd performs input validation check on address fields.
func (cmd *AddressCmd) ValidateCmd() error {

	//  csrf token
	if len(cmd.Csrf) <= 16 || len((strings.TrimSpace(cmd.Csrf))) > 64 {
		return fmt.Errorf("invalid csrf token: must be between 16 and 64 characters")
	}

	// slug may not be present for creates, but if it is present it must be valid
	if cmd.Slug != "" {
		if len(cmd.Slug) < 16 || len(cmd.Slug) > 64 {
			return fmt.Errorf("invalid slug: must be between 16 and 64 characters")
		}
	}

	// username is required and must be a valid email
	if err := validate.IsValidEmail(strings.TrimSpace(cmd.Username)); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	// validate street address line 1
	if err := validate.ValidateStreetAddress(strings.TrimSpace(cmd.Address.StreetAddress)); err != nil {
		return fmt.Errorf("invalid street address line 1: %v", err)
	}

	// validate street address line 2 - optional but if present must be valid
	if strings.TrimSpace(*cmd.Address.StreetAddress_2) != "" {
		if err := validate.ValidateStreetAddress2(strings.TrimSpace(*cmd.Address.StreetAddress_2)); err != nil {
			return fmt.Errorf("invalid street address line 2: %v", err)
		}
	}

	// validate city
	if err := validate.ValidateCity(strings.TrimSpace(cmd.Address.City)); err != nil {
		return fmt.Errorf("invalid city: %v", err)
	}

	// validate state
	if err := validate.ValidateState(strings.TrimSpace(cmd.Address.StateProvince)); err != nil {
		return fmt.Errorf("invalid state: %v", err)
	}

	// validate postal code
	if err := validate.ValidateZipCode(strings.TrimSpace(cmd.Address.PostalCode)); err != nil {
		return fmt.Errorf("invalid postal code: %v", err)
	}

	// validate country
	if err := validate.ValidateCountry(strings.TrimSpace(cmd.Address.Country)); err != nil {
		return fmt.Errorf("invalid country: %v", err)
	}

	return nil
}

