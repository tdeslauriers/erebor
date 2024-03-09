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
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd session.UserRegisterCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		log.Printf("unable to decode json in user registration request body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get shaw service token
	s2sToken, err := h.S2sProvider.GetServiceToken("shaw")
	if err != nil {
		log.Printf("unable to retreive shaw s2s token: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user registration failed due to internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var registered session.UserRegisterCmd
	if err := h.Caller.PostToService("/register", s2sToken, "", cmd, &registered); err != nil {
		log.Printf("registration failed for username %s: %v", cmd.Username, err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user registration failed due to internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(registered); err != nil {
		log.Printf("unable to marshal/send user registration response body: %v", err)
		// returning successfully registered user data is a convenience only, omit on error
		return
	}
}
