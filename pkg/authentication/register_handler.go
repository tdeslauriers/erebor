package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

type RegistrationHandler interface {
	// HandleRegistration handles the registration request from the client by submitting it against the user auth service.
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewRegistrationHandler(o config.OauthRedirect, s uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) RegistrationHandler {
	return &registrationHandler{
		oAuth:     o,
		uxSession: s,
		s2sToken:  p,
		caller:    c,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	oAuth     config.OauthRedirect
	uxSession uxsession.Service
	s2sToken  provider.S2sTokenProvider
	caller    connect.S2sCaller

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

	var cmd types.UserRegisterCmd
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
	cmd.ClientId = h.oAuth.CallbackClientId // association required by identity service for user login after registation

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

	// check for valid session with valid csrf token
	if valid, err := h.uxSession.IsValidCsrf(cmd.Session, cmd.Csrf); !valid {
		h.logger.Error("invalid session or csrf token", "err", err.Error())
		h.uxSession.HandleSessionErr(err, w)
		return
	}

	// remove session and csrf tokens from registration request
	// before sending to identity service to avoid unnecessary exposure
	cmd.Session = ""
	cmd.Csrf = ""

	// get shaw service token
	s2sToken, err := h.s2sToken.GetServiceToken(util.ServiceUserIdentity)
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
	var registered types.UserAccount
	if err := h.caller.PostToService("/register", s2sToken, "", cmd, &registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to register user %s", cmd.Username), "err", err.Error())
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
