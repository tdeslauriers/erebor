package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"erebor/internal/authentication/uxsession"
	"erebor/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/shaw/pkg/api/login"
)

// LoginHandler is the interface for handling login requests from the client.
type LoginHandler interface {
	// HandleLogin handles the login request from the client by submitting it against the user auth service.
	// The user auth service will return an auth code (as well as state/redirect/etc) that returned to the client if login successful.
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

// NewLoginHandler creates a new LoginHandler instance.
func NewLoginHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam *connect.S2sCaller) LoginHandler {

	return &loginHandler{
		uxSession: ux,
		s2sToken:  p,
		iam:       iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAuth)).
			With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

// loginHandler is the concrete implementation of the LoginHandler interface.
type loginHandler struct {
	uxSession uxsession.Service
	s2sToken  provider.S2sTokenProvider
	iam       *connect.S2sCaller

	logger *slog.Logger
}

// HandleLogin handles the login request from the client by submitting it against the user auth service.

func (h *loginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

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

	var cmd login.UserLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		telemetryLogger.Error("failed to decode json in user login request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json in login request body",
		}
		e.SendJsonErr(w)
		return
	}

	// login level field validation
	// very lightweight validation, just to ensure the fields are not empty ot too long
	if err := cmd.ValidateCmd(); err != nil {
		telemetryLogger.Error("failed to validate fields in login request body", "err", err.Error())
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

	// get service token
	s2sToken, err := h.s2sToken.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		telemetryLogger.Error("failed to retreive s2s token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "login unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// post creds to user auth identity service
	authCode, err := connect.PostToService[login.UserLoginCmd, types.AuthCodeExchange](
		ctx,
		h.iam,
		"/login",
		s2sToken,
		"",
		cmd,
	)
	if err != nil {
		telemetryLogger.Error("failed to post login cmd to identity service", "err", err.Error())
		h.iam.RespondUpstreamError(err, w)
		return
	}

	telemetryLogger.Info(fmt.Sprintf("successfully logged in user %s", cmd.Username))

	// send auth code to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authCode); err != nil {
		telemetryLogger.Error("failed to encode auth code response to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode login response to json",
		}
		e.SendJsonErr(w)
		return
	}
}
