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
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// ScopesHandler is an interface for handling client scope requests.
type ScopesHandler interface {
	// HandleScopes handles the request to udpate a client's assigned scopes.
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewScopesHandler returns a pointer to the concrete implementation of the ScopesHandler interface.
func NewScopesHandler(ux uxsession.Service, p provider.S2sTokenProvider, c *connect.S2sCaller) ScopesHandler {
	return &scopesHandler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClientsScopes)),
	}
}

var _ ScopesHandler = (*scopesHandler)(nil)

// scopesHandler is the concrete implementation of the ScopesHandler interface.
type scopesHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      *connect.S2sCaller

	logger *slog.Logger
}

// HandleScopes is the concrete implementation of the interface function that handles the request to udpate a client's assigned scopes.
func (h *scopesHandler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	telemetry := connect.NewTelemetry(r, h.logger)
	logger := h.logger.With(telemetry.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, telemetry)

	if r.Method != "PUT" {
		logger.Error("only PUT requests are allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only PUT requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		logger.Error("failed to get session from request", "err", err.Error())
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
	var cmd ClientScopesCmd
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
		logger.Error("failed to validate client scopes command fields in request body", "err", err.Error())
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
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// make request to the s2s service
	// no resopnse is expected from the s2s service --> 204 No Content
	_, err = connect.PostToService[ClientScopesCmd, struct{}](
		ctx,
		h.s2s,
		"/clients/scopes",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		logger.Error("failed to post to /client/scopes endpoint", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	logger.Info(fmt.Sprintf("client (slug) %s scopes updated successfully", cmd.ClientSlug))
	w.WriteHeader(http.StatusNoContent)
}
