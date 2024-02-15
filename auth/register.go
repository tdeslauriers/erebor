package auth

import (
	"fmt"
	"log"
	"net/http"

	"github.com/tdeslauriers/carapace/session"
	"github.com/tdeslauriers/carapace/validate"
)

type RegistrationHandler struct {
	S2s session.S2STokenProvider
}

func NewRegistrationHandler(session session.S2STokenProvider) *RegistrationHandler {
	return &RegistrationHandler{
		S2s: session,
	}
}

func (h *RegistrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd session.RegisterCmd
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// input validation
	if err := validate.IsValidEmail(cmd.Username); err != nil {
		http.Error(w, fmt.Sprintf("invalid username: %v", err), http.StatusBadRequest)
		return
	}

	if err := validate.IsValidName(cmd.Firstname); err != nil {
		http.Error(w, fmt.Sprintf("invalid firstname: %v", err), http.StatusBadRequest)
		return
	}

	if err := validate.IsValidName(cmd.Lastname); err != nil {
		http.Error(w, fmt.Sprintf("invalid lastname: %v", err), http.StatusBadRequest)
		return
	}

	if err := validate.IsValidBirthday(cmd.Birthdate); err != nil {
		http.Error(w, fmt.Sprintf("invalid date of birth: %v", err), http.StatusBadRequest)
		return
	}

	if cmd.Password != cmd.Confirm {
		http.Error(w, "password does not match confirm password", http.StatusBadRequest)
		return
	}

	if err := validate.IsValidPassword(cmd.Password); err != nil {
		http.Error(w, fmt.Sprintf("invalid password: %v", err), http.StatusBadRequest)
		return
	}

	// get service token
	s2sToken, err := h.S2s.GetServiceToken()
	if err != nil {
		log.Printf("unable to retreive s2s token: %v", err)
		http.Error(w, "unable to retrieve service token", http.StatusBadRequest)
		return
	}
}
