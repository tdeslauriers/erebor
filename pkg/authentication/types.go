package authentication

import "fmt"


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
// NOTE: false is not meant to be returned to the client: this would be a data leak, though a minor one.
// It in no way gives the user access to the data that is being called by the respective apis.
// Access tokens audience list will be used to populate this section.
type Render struct {
	Profile    bool `json:"profile_access,omitempty"`
	Blog       bool `json:"blog_access,omitempty"`
	Allownace  bool `json:"allowance_access,omitempty"`
	Gallery    bool `json:"gallery_access,omitempty"`
	Judo       bool `json:"judo_access,omitempty"`
	FaimlyTree bool `json:"familytree_access,omitempty"`
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
