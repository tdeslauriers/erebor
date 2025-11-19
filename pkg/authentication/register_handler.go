package authentication

import (
	"context"
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

func NewRegistrationHandler(
	o config.OauthRedirect,
	s uxsession.Service,
	p provider.S2sTokenProvider,
	iam *connect.S2sCaller,
	g *connect.S2sCaller,
) RegistrationHandler {
	return &registrationHandler{
		oAuth:     o,
		uxSession: s,
		s2sToken:  p,
		identity:  iam,
		gallery:   g,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAuth)).
			With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	oAuth     config.OauthRedirect
	uxSession uxsession.Service
	s2sToken  provider.S2sTokenProvider
	identity  *connect.S2sCaller
	gallery   *connect.S2sCaller

	logger *slog.Logger
}

func (h *registrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	telemetry := connect.NewTelemetry(r, h.logger)
	telemetryLogger := h.logger.With(telemetry.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, telemetry)

	if r.Method != "POST" {
		telemetryLogger.Error("only POST requests are allowed")
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
		telemetryLogger.Error("failed to decode json in user registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json in user registration request body",
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
		telemetryLogger.Error("failed to validate user registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check for valid session with valid csrf token
	if valid, err := h.uxSession.IsValidCsrf(cmd.Session, cmd.Csrf); !valid {
		telemetryLogger.Error("invalid session or csrf token", "err", err.Error())
		h.uxSession.HandleSessionErr(err, w)
		return
	}

	// remove session and csrf tokens from registration request
	// before sending to identity service to avoid unnecessary exposure
	cmd.Session = ""
	cmd.Csrf = ""

	// get identity service token
	s2sIamToken, err := h.s2sToken.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		telemetryLogger.Error("failed to get s2s token for identity service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user registration failed due to internal server error.",
		}
		e.SendJsonErr(w)
		return
	}

	// post registration request to identity service
	registered, err := connect.PostToService[types.UserRegisterCmd, types.UserAccount](
		ctx,
		h.identity,
		"/register",
		s2sIamToken,
		"",
		cmd,
	)
	if err != nil {
		telemetryLogger.Error(fmt.Sprintf("failed to register user %s", cmd.Username), "err", err.Error())

	}

	// ghost account creation in downstream services
	// concurrent so can return immediately --> ghost account creation abstracted from user
	// gallery account creation
	go func(username string) {

		s2sGalleryToken, err := h.s2sToken.GetServiceToken(ctx, util.ServiceGallery)
		if err != nil {
			// logging only, not returning error --> hidden/abstracted from user
			telemetryLogger.Error(fmt.Sprintf("failed to get s2s token for gallery service: %s", err.Error()))
			return
		}

		_, err = connect.PostToService[patron.PatronRegisterCmd, struct{}](
			ctx,
			h.gallery,
			"/s2s/patrons/register",
			s2sGalleryToken,
			"",
			patron.PatronRegisterCmd{Username: username},
		)
		if err != nil {
			// logging only, not returning error --> hidden/abstracted from user
			telemetryLogger.Error(fmt.Sprintf("failed to create gallery patron for user %s", username), "err", err.Error())
			return
		}

		telemetryLogger.Info(fmt.Sprintf("successfully created patron account for user %s", username))

	}(cmd.Username)

	telemetryLogger.Info(fmt.Sprintf("user %s successfully registered", registered.Username))

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered user data is a convenience only, omit on error
		telemetryLogger.Error("unable to marshal/send user registration response body", "err", err.Error())
		return
	}
}
