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
	"github.com/tdeslauriers/pixie/pkg/patron"
)

type RegistrationHandler interface {
	// HandleRegistration handles the registration request from the client by submitting it against the user auth service.
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewRegistrationHandler(o config.OauthRedirect, s uxsession.Service, p provider.S2sTokenProvider, iam, g connect.S2sCaller) RegistrationHandler {
	return &registrationHandler{
		oAuth:     o,
		uxSession: s,
		s2sToken:  p,
		identity:  iam,
		gallery:   g,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageAuth)).
			With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	oAuth     config.OauthRedirect
	uxSession uxsession.Service
	s2sToken  provider.S2sTokenProvider
	identity  connect.S2sCaller
	gallery   connect.S2sCaller

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
		h.logger.Error("failed to decode json in user registration request body", "err", err.Error())
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
		h.logger.Error("failed to validate fields in registration request body", "err", err.Error())
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
	s2sIamToken, err := h.s2sToken.GetServiceToken(util.ServiceIdentity)
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
	if err := h.identity.PostToService("/register", s2sIamToken, "", cmd, &registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to register user %s", cmd.Username), "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("user %s successfully registered", registered.Username))

	// ghost account creation in downstream services
	// concurrent so can return immediately --> ghost account creation abstracted from user
	// gallery account creation
	go func(username string) {

		s2sGalleryToken, err := h.s2sToken.GetServiceToken(util.ServiceGallery)
		if err != nil {
			// logging only, not returning error --> hidden/abstracted from user
			h.logger.Error(fmt.Sprintf("failed to get s2s token for gallery service: %s", err.Error()))
			return
		}

		if err := h.gallery.PostToService("/s2s/patrons/register", s2sGalleryToken, "", patron.PatronRegisterCmd{Username: username}, nil); err != nil {
			// logging only, not returning error --> hidden/abstracted from user
			h.logger.Error(fmt.Sprintf("failed to create gallery patron for user %s: %s", registered.Username, err.Error()))
			return
		}

		h.logger.Info(fmt.Sprintf("gallery patron account successfully created for user %s", username))

	}(cmd.Username)

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered user data is a convenience only, omit on error
		h.logger.Error("unable to marshal/send user registration response body", "err", err.Error())
		return
	}
}
