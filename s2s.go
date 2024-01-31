package main

import (
	"log"
	"net/http"

	"github.com/tdeslauriers/carapace/session"
)

type LoginHandler struct {
	S2s session.S2sTokenProvider
}

func NewLoginHandler(s2s session.S2sTokenProvider) *LoginHandler {
	return &LoginHandler{
		S2s: s2s,
	}
}

func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

	s2sToken, err := h.S2s.GetServiceToken()
	if err != nil {

		log.Printf("unable to retreive s2s token: %v", err)
		http.Error(w, "unable to retrieve service token", http.StatusBadRequest)
		return
	}

}
