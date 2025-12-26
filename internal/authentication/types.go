package authentication

import (
	"erebor/internal/util"
	"fmt"
	"reflect"
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
	Ux            Render `json:"ux_render,omitempty"`
}

// Render is a struct that reflects the visual elements that are available to the user
// on the client side.  This struct is used to determine what the user can see and interact with.
// NOTE: these flags are ux/ui convenience for feature display ONLY:
// they in no way give the user access to the data that is being called by the respective apis.
type Render struct {
	// users
	ProfileRead *bool               `json:"profile_read,omitempty"`
	Users       *UserAccessFlags    `json:"users,omitempty"`
	Gallery     *GalleryAccessFlags `json:"gallery,omitempty"`
	Blog        *BlogAccessFlags    `json:"blog,omitempty"`
	Tasks       *TaskAccessFlags    `json:"tasks,omitempty"`
}

// UserAccessFlags is a struct that is used to return the user access flags for ui rendering
// NOTE: these flags are ux/ui convenience for feature display ONLY:
// they in no way give the user access to the data that is being called by the respective apis.
type UserAccessFlags struct {
	UserRead    *bool `json:"user_read,omitempty"`
	UserWrite   *bool `json:"user_write,omitempty"`
	ScopeRead   *bool `json:"scope_read,omitempty"`
	ScopeWrite  *bool `json:"scope_write,omitempty"`
	ClientRead  *bool `json:"client_read,omitempty"`
	ClientWrite *bool `json:"client_write,omitempty"`
}

// GalleryAccessFlags is a struct that is used to return the gallery access flags for ui rendering
// NOTE: these flags are ux/ui convenience for feature display ONLY:
// they in no way give the user access to the data that is being called by the respective apis.
type GalleryAccessFlags struct {
	AlbumRead  *bool `json:"album_read,omitempty"`
	AlbumWrite *bool `json:"album_write,omitempty"`
	ImageRead  *bool `json:"image_read,omitempty"`
	ImageWrite *bool `json:"image_write,omitempty"`
}

// BlogAccessFlags is a struct that is used to return the blog access flags for ui rendering
// NOTE: these flags are ux/ui convenience for feature display ONLY:
// they in no way give the user access to the data that is being called by the respective apis.
type BlogAccessFlags struct {
	BlogRead  *bool `json:"blog_read,omitempty"`
	BlogWrite *bool `json:"blog_write,omitempty"`
}

// TaskAccessFlags is a struct that is used to return the task access flags for ui rendering
// NOTE: these flags are ux/ui convenience for feature display ONLY:
// they in no way give the user access to the data that is being called by the respective apis.
type TaskAccessFlags struct {
	AccountRead     *bool `json:"account_read,omitempty"`
	AccountWrite    *bool `json:"account_write,omitempty"`
	AllowancesRead  *bool `json:"allowances_read,omitempty"`
	AllowancesWrite *bool `json:"allowances_write,omitempty"`
	TemplatesRead   *bool `json:"templates_read,omitempty"`
	TemplatesWrite  *bool `json:"templates_write,omitempty"`
	TasksRead       *bool `json:"tasks_read,omitempty"`
	TasksWrite      *bool `json:"tasks_write,omitempty"`
}

type UxAccess string
type ApiEndpoint string

const (
	List   UxAccess = "l"
	Read   UxAccess = "r"
	Write  UxAccess = "w"
	Delete UxAccess = "d"

	Profile ApiEndpoint = "profile"
	User    ApiEndpoint = "users"
	Scope   ApiEndpoint = "scopes"
	Client  ApiEndpoint = "clients"

	Account    ApiEndpoint = "account"
	Allowances ApiEndpoint = "allowances"
	Templates  ApiEndpoint = "templates"
	Tasks      ApiEndpoint = "tasks"

	Albums ApiEndpoint = "albums"
	Images ApiEndpoint = "images"
)

// SetRenderFlag is a function that is used to set the Render flag to the value that is passed in.
func setRenderFlag(b bool) *bool {
	return &b
}

// checks for any fields in the struct that are set to a non-nil value.
func HasAnyFieldsSet(i interface{}) bool {
	v := reflect.ValueOf(i)

	// If it's a pointer to a struct, dereference it
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}

	// Must be a struct
	if v.Kind() != reflect.Struct {
		return false
	}

	// Iterate through fields
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			return true
		}
	}

	return false
}

// BuildRender is a function that is used to build the Render struct based on the scopes string that is passed in.
// Note: not all scopes map one to one with the Render object, or at all.
// scopes should be in the following format: "r:shaw:profile:* r:junk:* r:gallery:*"
func BuildRender(scopes string) Render {

	// build render object
	var render Render
	users := &UserAccessFlags{}
	gallery := &GalleryAccessFlags{}
	blog := &BlogAccessFlags{}
	tasks := &TaskAccessFlags{}

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

		// Identity
		switch s[1] {
		case util.ServiceIdentity:
			if len(s) < 3 {
				continue
			}

			switch s[2] {
			case string(Profile):
				if s[0] == string(Read) {
					render.ProfileRead = setRenderFlag(true)
					continue
				}
				// All users have profile-write so no need for specific render

			case string(User):
				if s[0] == string(Read) {
					users.UserRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					users.UserWrite = setRenderFlag(true)
					continue
				}
			case string(Scope):

			default:
				break
			}

		// Clients
		case util.ServiceS2s:
			switch s[2] {
			case string(Scope):
				if s[0] == string(Read) {
					users.ScopeRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					users.ScopeWrite = setRenderFlag(true)
					continue
				}
			case string(Client):
				if s[0] == string(Read) {
					users.ClientRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					users.ClientWrite = setRenderFlag(true)
					continue
				}
			default:
				break
			}

		// Gallery
		case util.ServiceGallery:
			switch s[2] {
			case string(Albums):
				if s[0] == string(Read) {
					gallery.AlbumRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					gallery.AlbumWrite = setRenderFlag(true)
					continue
				}
			case string(Images):
				if s[0] == string(Read) {
					gallery.ImageRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					gallery.ImageWrite = setRenderFlag(true)
					continue
				}
			default:
				break
			}

		// Blog
		case util.ServiceBlog:
			if s[0] == string(Read) {
				blog.BlogRead = setRenderFlag(true)
				continue
			}
			if s[0] == string(Write) {
				blog.BlogWrite = setRenderFlag(true)
				continue
			}

		// Tasks
		case util.ServiceTasks:
			if len(s) < 3 {
				continue
			}

			switch s[2] {
			case string(Account):
				if s[0] == string(Read) {
					tasks.AccountRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					tasks.AccountWrite = setRenderFlag(true)
					continue
				}

			case string(Allowances):
				if s[0] == string(Read) {
					tasks.AllowancesRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					tasks.AllowancesWrite = setRenderFlag(true)
					continue
				}

			case string(Templates):
				if s[0] == string(Read) {
					tasks.TemplatesRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					tasks.TemplatesWrite = setRenderFlag(true)
					continue
				}

			case string(Tasks):
				if s[0] == string(Read) {
					tasks.TasksRead = setRenderFlag(true)
					continue
				}
				if s[0] == string(Write) {
					tasks.TasksWrite = setRenderFlag(true)
					continue
				}

			default:
				break
			}

		default:
		}
	}

	// check for any fields in the access flags structs that are set to a non-nil value.
	if HasAnyFieldsSet(users) {
		render.Users = users
	}

	if HasAnyFieldsSet(gallery) {
		render.Gallery = gallery
	}

	if HasAnyFieldsSet(blog) {
		render.Blog = blog
	}

	if HasAnyFieldsSet(tasks) {
		render.Tasks = tasks
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
