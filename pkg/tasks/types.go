package tasks

import (
	"erebor/pkg/authentication/uxsession"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

type Handler interface {
	AllowanceHandler
	TemplateHandler
	TaskHandler
}

func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam, task connect.S2sCaller) Handler {
	return &handler{
		AllowanceHandler: NewAllowanceHandler(ux, p, iam, task),
		TemplateHandler:  NewTemplateHandler(ux, p, task),
		TaskHandler:      NewTaskHandler(ux, p, task),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	AllowanceHandler
	TemplateHandler
	TaskHandler
}

// CreateAllowanceCmd is a model for creating a new allowance account
// recieved by the gateway service.
type CreateAllowanceCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Username  string `json:"username"`
	Slug      string `json:"slug"`
	BirthDate string `json:"birth_date"`
}

// ValidateCmd performs input validation check on allowance account creation fields.
func (c *CreateAllowanceCmd) ValidateCmd() error {

	if !validate.IsValidUuid(c.Csrf) {
		return fmt.Errorf("invalid csrf token")
	}

	if err := validate.IsValidEmail(c.Username); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	if !validate.IsValidUuid(c.Slug) {
		return fmt.Errorf("invalid slug")
	}

	if err := validate.IsValidBirthday(c.BirthDate); err != nil {
		return fmt.Errorf("invalid birth date: %v", err)
	}

	return nil
}




