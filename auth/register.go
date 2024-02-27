package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/session"
)

type RegistrationHandler struct {
	S2sProvider session.S2STokenProvider
	Caller      connect.S2SCaller
}

func NewRegistrationHandler(provider session.S2STokenProvider, caller connect.S2SCaller) *RegistrationHandler {
	return &RegistrationHandler{
		S2sProvider: provider,
		Caller:      caller,
	}
}

func (h *RegistrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd session.UserRegisterCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// get service token
	s2sToken, err := h.S2sProvider.GetServiceToken()
	if err != nil {
		log.Printf("unable to retreive s2s token: %v", err)
		http.Error(w, "registration unsuccessful", http.StatusInternalServerError)
		return
	}

	var registered session.UserRegisterCmd
	if err := h.Caller.PostToService("/register", s2sToken, "", cmd, &registered); err != nil {
		log.Printf("registration call to user auth service failed for username %s: %v", cmd.Username, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(registered)
}
