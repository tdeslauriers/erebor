package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/session"
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
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd session.UserLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		log.Printf("unable to decode json in user login request body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate field input restrictions
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
	// s2sToken, err := h.S2s.GetServiceToken()
	// if err != nil {

	// 	log.Printf("unable to retreive s2s token: %v", err)
	// 	http.Error(w, "unable to retrieve service token", http.StatusBadRequest)
	// 	return
	// }

}
