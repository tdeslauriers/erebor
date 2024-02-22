package auth

import (
	"encoding/json"
	"net/http"

	"github.com/tdeslauriers/carapace/session"
	"github.com/tdeslauriers/carapace/validate"
)

type LoginHandler struct {
	S2s *session.S2sTokenProvider
}

func NewLoginHandler(s2s *session.S2sTokenProvider) *LoginHandler {
	return &LoginHandler{
		S2s: s2s,
	}
}

func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd session.UserLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// validate field input restrictions
	if err := validate.IsValidEmail(cmd.Username); err != nil {
		http.Error(w, "invalid user credentials", http.StatusUnauthorized)
	}

	if err := validate.IsValidPassword(cmd.Password); err != nil {
		http.Error(w, "invalid user credentials", http.StatusUnauthorized)
	}

	// get service token
	// s2sToken, err := h.S2s.GetServiceToken()
	// if err != nil {

	// 	log.Printf("unable to retreive s2s token: %v", err)
	// 	http.Error(w, "unable to retrieve service token", http.StatusBadRequest)
	// 	return
	// }

}
