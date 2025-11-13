package clients

import (
	"context"
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// ResetHandler is an interface for handling service password resets
type ResetHandler interface {

	// HandleReset handles the password reset request for client services.
	HandleReset(w http.ResponseWriter, r *http.Request)
}

func NewResetHandler(ux uxsession.Service, p provider.S2sTokenProvider, c *connect.S2sCaller) ResetHandler {
	return &resetHandler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentResetClient)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}

}

var _ ResetHandler = (*resetHandler)(nil)

type resetHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      *connect.S2sCaller

	logger *slog.Logger
}

// HandleReset is the concrete implementation of the interface function that handles the password reset request for client services.
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	telemetry := connect.NewTelemetry(r)
	logger := h.logger.With(telemetry.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, telemetry)

	if r.Method != "POST" {
		logger.Error("only POST requests are allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		logger.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		logger.Error("failed to get access token from session token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd profile.ResetCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		logger.Error("failed to decode json in request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json in request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {

		logger.Error("failed to validate reset command fields in request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		logger.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		logger.Error("failed to get s2s token for s2s service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "service client password reset unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// make the request to the s2s service
	// there will be no response body, only a status code -> s2s will not return password data
	_, err = connect.PostToService[profile.ResetCmd, struct{}](
		ctx,
		h.s2s,
		"/clients/reset",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		logger.Error("failed to post reset cmd to s2s service", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	logger.Info(fmt.Sprintf("service client %s password reset successful", cmd.ResourceId))
	w.WriteHeader(http.StatusNoContent)
}
