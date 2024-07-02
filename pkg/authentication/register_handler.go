package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"erebor/internal/util"
	"erebor/pkg/uxsession"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type RegistrationHandler interface {
	// HandleRegistration handles the registration request from the client by submitting it against the user auth service.
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewRegistrationHandler(o config.OauthRedirect, s uxsession.Service, p session.S2sTokenProvider, c connect.S2sCaller) RegistrationHandler {
	return &registrationHandler{
		oauth:          o,
		sessionService: s,
		s2sProvider:    p,
		caller:         c,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	oauth          config.OauthRedirect
	sessionService uxsession.Service
	s2sProvider    session.S2sTokenProvider
	caller         connect.S2sCaller

	logger *slog.Logger
}

func (h *registrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /register endpoint")
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
		h.logger.Error("unable to decode json in user registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// TODO: add logic to choose which client to add to user's registration request
	// for now this is the primary website's client id
	// Adding the client id here as a "hack" to pass input validation
	// which is unnecessary in this case (because client id comes from config)
	cmd.ClientId = h.oauth.CallbackClientId // association required by identity service for user login after registation

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("unable to validate fields in registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check is valid session with valid csrf token
	if valid, err := h.sessionService.IsValidCsrf(cmd.Session, cmd.Csrf); !valid {
		h.logger.Error("invalid session or csrf token", "err", err.Error())
		h.handleSessionErr(err, w)
		return
	}

	// remove session and csrf tokens from registration request
	// before sending to identity service to avoid unnecessary exposure
	// cmd.Session = ""
	// cmd.Csrf = ""

	// get shaw service token
	s2sToken, err := h.s2sProvider.GetServiceToken(util.ServiceUserIdentity)
	if err != nil {
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "User registration failed due to internal server error.",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service with registration request
	var registered session.UserRegisterCmd
	if err := h.caller.PostToService("/register", s2sToken, "", cmd, &registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to register user (%s)", cmd.Username), "err", err.Error())
		h.caller.RespondUpstreamError(err, w)
		return
	}

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered user data is a convenience only, omit on error
		h.logger.Error("unable to marshal/send user registration response body", "err", err.Error())
		return
	}
}

func (h *registrationHandler) handleSessionErr(err error, w http.ResponseWriter) {

	switch {
	case strings.Contains(err.Error(), uxsession.ErrInvalidSession):
	case strings.Contains(err.Error(), uxsession.ErrInvalidCsrf):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), uxsession.ErrSessionRevoked):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrSessionRevoked,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), uxsession.ErrSessionExpired):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrSessionExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), uxsession.ErrSessionNotFound):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrSessionNotFound,
		}
		e.SendJsonErr(w)
	case strings.Contains(err.Error(), uxsession.ErrCsrfMismatch):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    uxsession.ErrCsrfMismatch,
		}
		e.SendJsonErr(w)
		return
	default:
		h.logger.Error("failed to get csrf token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get csrf token",
		}
		e.SendJsonErr(w)
		return
	}

}
