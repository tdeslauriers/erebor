package authentication

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

func NewLoginHandler(siteUrl string, provider session.S2sTokenProvider, caller connect.S2sCaller) LoginHandler {
	return &loginHandler{
		siteUrl:     siteUrl,
		s2sProvider: provider,
		caller:      caller,
		// loginService: loginService,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuth)).With(slog.String(util.ServiceKey, util.ServiceLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	siteUrl     string
	s2sProvider session.S2sTokenProvider
	caller      connect.S2sCaller
	// loginService loginService

	logger *slog.Logger
}

// HandleLogin handles the login request from the client by submitting it against the user auth service.
// The user auth service will return an auth code (as well as state/redirect/etc) that will be sent to the client.
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
		h.logger.Error("unable to decode json in user login request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// login level field validation
	// very lightweight validation, just to ensure the fields are not empty ot too long
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("unable to validate fields in login request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
	s2sToken, err := h.s2sProvider.GetServiceToken("shaw")
	if err != nil {
		h.logger.Error("failed to retreive s2s token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "login unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// post creds to user auth login service
	var authcode session.AuthCodeResponse
	if err := h.caller.PostToService("/login", s2sToken, "", cmd, &authcode); err != nil {
		// TODO: more detailed error handling.  This is a placeholder
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "login unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// TODO: send auth code to client
}
