package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"erebor/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type LoginHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewLoginHandler(provider session.S2sTokenProvider, caller connect.S2sCaller) LoginHandler {
	return &loginHandler{
		s2sProvider: provider,
		caller:      caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuth)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	s2sProvider session.S2sTokenProvider
	caller      connect.S2sCaller

	logger *slog.Logger
}

func (h *loginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /login endpoint")
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
		h.logger.Error("unable to decode json in user login request body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate field input restrictions
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("unable to validate fields in login request body", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
	// s2sToken, err := h.S2sProvider.GetServiceToken()
	// if err != nil {
	// 	log.Printf("unable to retreive s2s token: %v", err)
	// 	e := connect.ErrorHttp{
	// 		StatusCode: http.StatusInternalServerError,
	// 		Message:    "login unsuccessful: internal server error",
	// 	}
	// 	e.SendJsonErr(w)
	// 	return
	// }

	// post creds to user auth login

}
