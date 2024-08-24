package authentication

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// LoginHandler is the interface for handling login requests from the client.
type LoginHandler interface {
	// HandleLogin handles the login request from the client by submitting it against the user auth service.
	// The user auth service will return an auth code (as well as state/redirect/etc) that returned to the client if login successful.
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

// NewLoginHandler creates a new LoginHandler instance.
func NewLoginHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) LoginHandler {
	return &loginHandler{
		uxSession: ux,
		s2sToken:  p,
		caller:    c,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

// loginHandler is the concrete implementation of the LoginHandler interface.
type loginHandler struct {
	uxSession uxsession.Service
	s2sToken  provider.S2sTokenProvider
	caller    connect.S2sCaller

	logger *slog.Logger
}

// HandleLogin handles the login request from the client by submitting it against the user auth service.

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

	var cmd types.UserLoginCmd
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

	// check for valid session with valid csrf token
	if valid, err := h.uxSession.IsValidCsrf(cmd.Session, cmd.Csrf); !valid {
		h.logger.Error("invalid session or csrf token", "err", err.Error())
		h.uxSession.HandleSessionErr(err, w)
		return
	}

	// get service token
	s2sToken, err := h.s2sToken.GetServiceToken(util.ServiceUserIdentity)
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
	var authcode types.AuthCodeExchange
	if err := h.caller.PostToService("/login", s2sToken, "", cmd, &authcode); err != nil {
		h.logger.Error("call to identity service login endpoint failed", "err", err.Error())
		h.caller.RespondUpstreamError(err, w)
		return
	}

	// send auth code to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authcode); err != nil {
		h.logger.Error("failed to encode auth code response to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode login response to json",
		}
		e.SendJsonErr(w)
		return
	}
}
