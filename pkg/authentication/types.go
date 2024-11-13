package authentication

import (
	"erebor/internal/util"
	"fmt"
	"strings"
)

// CallbackResponse is a struct that is used to return the callback authentication response to the client
// The session should be an authenticated session token that is linked to the access/refresh tokens
// the gateway will use to fetch data from the apis on the client's behalf.
type CallbackResponse struct {
	Session string `json:"session"`

	Authenticated bool   `json:"authenticated"` // convenience only, not proof of authentication
	Username      string `json:"username"`
	Fullname      string `json:"fullname"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Birthdate     string `json:"birthdate,omitempty"`

	Ux Render `json:"access,omitempty"`
}

// Render is a struct that reflects the visual elements that are available to the user
// on the client side.  This struct is used to determine what the user can see and interact with.
// NOTE: these flags are ux/ui convenience for feature display ONLY:
// they in no way give the user access to the data that is being called by the respective apis.
type Render struct {
	ProfileRead  *bool `json:"profile_read,omitempty"`
	ProfileWrite *bool `json:"profile_write,omitempty"`

	UserList   *bool `json:"user_list,omitempty"`
	UserRead   *bool `json:"user_read,omitempty"`
	UserWrite  *bool `json:"user_write,omitempty"`
	UserDelete *bool `json:"user_delete,omitempty"`

	BlogRead  *bool `json:"blog_read,omitempty"`
	BlogWrite *bool `json:"blog_write,omitempty"`

	// Allowance
	TaskList      *bool `json:"task_list,omitempty"`
	TaskRead      *bool `json:"task_read,omitempty"`
	TaskWrite     *bool `json:"task_write,omitempty"`
	TaskDelete    *bool `json:"task_delete,omitempty"`
	PayRollList   *bool `json:"payroll_list,omitempty"`
	PayrollRead   *bool `json:"payroll_read,omitempty"`
	PayrollWrite  *bool `json:"payroll_write,omitempty"`
	PayrollDelete *bool `json:"payroll_delete,omitempty"`

	GalleryRead  *bool `json:"gallery_read,omitempty"`
	GalleryWrite *bool `json:"gallery_write,omitempty"`

	JudoRead  *bool `json:"judo_read,omitempty"`
	JudoWrite *bool `json:"judo_write,omitempty"`

	FaimlyTreeRead  *bool `json:"familytree_read,omitempty"`
	FaimlyTreeWrite *bool `json:"familytree_write,omitempty"`
}

type UxAccess string
type ApiEndpoint string

const (
	List   UxAccess = "l"
	Read   UxAccess = "r"
	Write  UxAccess = "w"
	Delete UxAccess = "d"

	Profile ApiEndpoint = "profile"
	User    ApiEndpoint = "user"

	Task    ApiEndpoint = "task"
	Payroll ApiEndpoint = "payroll"
)

// SetRenderFlag is a function that is used to set the Render flag to the value that is passed in.
func setRenderFlag(b bool) *bool {
	return &b
}

// BuildRender is a function that is used to build the Render struct based on the scopes string that is passed in.
// Note: not all scopes map one to one with the Render object, or at all.
// scopes should be in the following format: "r:shaw:profile:* r:junk:* r:gallery:*"
func BuildRender(scopes string) Render {

	var render Render

	// check forf empty scopes
	if len(scopes) < 1 {
		return render
	}

	for _, scope := range strings.Split(strings.TrimSpace(scopes), " ") {

		if len(scope) < 1 {
			continue
		}

		s := strings.Split(strings.TrimSpace(scope), ":")
		if len(s) < 2 {
			continue
		}

		switch s[1] {
		case util.ServiceUserIdentity:
			if len(s) < 3 {
				continue
			}

			switch s[2] {
			case string(Profile):
				if s[0] == string(Read) {
					render.ProfileRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					render.ProfileWrite = setRenderFlag(true)
					continue
				}

			case string(User):
				if s[0] == string(List) {
					render.UserList = setRenderFlag(true)
					continue
				}
				if s[0] == string(Read) {
					render.UserRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					render.UserWrite = setRenderFlag(true)
					continue
				}
				if s[0] == string(Delete) {
					render.UserDelete = setRenderFlag(true)
					continue
				}
			default:
				break
			}

		case util.ServiceBlog:
			if s[0] == string(Read) {
				render.BlogRead = setRenderFlag(true)
				continue
			}
			if s[0] == string(Write) {
				render.BlogWrite = setRenderFlag(true)
				continue
			}

		case util.ServiceAllowance:
			if len(s) < 3 {
				continue
			}

			switch s[2] {
			case string(Task):
				if s[0] == string(List) {
					render.TaskList = setRenderFlag(true)
					continue
				}
				if s[0] == string(Read) {
					render.TaskRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					render.TaskWrite = setRenderFlag(true)
					continue
				}
				if s[0] == string(Delete) {
					render.TaskDelete = setRenderFlag(true)
					continue
				}

			case string(Payroll):
				if s[0] == string(List) {
					render.PayRollList = setRenderFlag(true)
					continue
				}
				if s[0] == string(Read) {
					render.PayrollRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					render.PayrollWrite = setRenderFlag(true)
					continue
				}
				if s[0] == string(Delete) {
					render.PayrollDelete = setRenderFlag(true)
					continue
				}
			default:
				break
			}

		case util.ServiceGallery:
			if s[0] == string(Read) {
				render.GalleryRead = setRenderFlag(true)
				continue
			}
			if s[0] == string(Write) {
				render.GalleryWrite = setRenderFlag(true)
				continue
			}

		case util.ServiceJudo:
			if s[0] == string(Read) {
				render.JudoRead = setRenderFlag(true)
				continue
			}
			if s[0] == string(Write) {
				render.JudoWrite = setRenderFlag(true)
				continue
			}

		case util.ServiceFamilyTree:
			if s[0] == string(Read) {
				render.FaimlyTreeRead = setRenderFlag(true)
				continue
			}
			if s[0] == string(Write) {
				render.FaimlyTreeWrite = setRenderFlag(true)
				continue
			}

		default:
		}
	}

	return render
}

// LogoutCmd is a struct that is used to logout the user from their active session.
type LogoutCmd struct {
	Session string `json:"session"`
}

// ValidateCmd is a method that is used to validate the logout command.
func (c *LogoutCmd) ValidateCmd() error {
	if len(c.Session) < 16 || len(c.Session) > 64 {
		return fmt.Errorf("session token is required")
	}
	return nil
}
