package scopes

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

type ScopeCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Uuid        string `db:"uuid" json:"scope_id"`
	ServiceName string `db:"service_name" json:"service_name"`
	Scope       string `db:"scope" json:"scope"`
	Name        string `db:"name"  json:"name"`
	Description string `db:"description" json:"description"`
	CreatedAt   string `db:"created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
	Slug        string `db:"slug" json:"slug"`
}

func (s *ScopeCmd) Validate() error {

	if err := validate.ValidateUuid(s.Csrf); err != nil {
		return fmt.Errorf("invalid csrf token")
	}

	if s.Uuid != "" {
		if err := validate.ValidateUuid(s.Uuid); err != nil {
			return fmt.Errorf("invalid scope id in scope payload")
		}
	}

	if err := validate.ValidateServiceName(s.ServiceName); err != nil {
		return fmt.Errorf("invalid service name in scope payload: %v", err)
	}

	if err := validate.ValidateScope(s.Scope); err != nil {
		return fmt.Errorf("invalid scope in scope payload: %v", err)
	}

	if err := validate.ValidateScopeName(s.Name); err != nil {
		return fmt.Errorf("invalid scope name in scope payload: %v", err)
	}

	if validate.TooShort(s.Description, 2) || validate.TooLong(s.Description, 256) {
		return fmt.Errorf("invalid description in scope payload")
	}

	if s.Slug != "" {
		if err := validate.ValidateUuid(s.Slug); err != nil {
			return fmt.Errorf("invalid slug in scope payload")
		}
	}

	return nil
}
