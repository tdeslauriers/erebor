package user

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

// ScopesHandler is an interface for handling user scope requests.
type ScopesHandler interface {
	// HandleScopes handles the request to update a user's assigned scopes.
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewScopesHandler returns a pointer to the concrete implementation of the ScopesHandler interface.
func NewScopesHandler(ux uxsession.Service, p provider.S2sTokenProvider, c *connect.S2sCaller) ScopesHandler {
	return &scopesHandler{
		session:  ux,
		provider: p,
		identity: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUserScopes)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}
}

var _ ScopesHandler = (*scopesHandler)(nil)

// scopesHandler is the concrete implementation of the ScopesHandler interface.
type scopesHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity *connect.S2sCaller

	logger *slog.Logger
}

// HandleScopes is the concrete implementation of the interface function that handles the request to update a user's assigned scopes.
func (h *scopesHandler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	if r.Method != "PUT" {
		log.Error("failed to update scopes", "err", "only PUT requests are allowed")
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
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to get access token from session", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd UserScopesCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in user scopes update command request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid user scopes update command request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token in user scopes update command request body", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	// get service token
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get service token for identity service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// make request to the identity service
	// no response is expected from the identity service --> 204 No Content
	_, err = connect.PutToService[UserScopesCmd, struct{}](
		ctx,
		h.identity,
		"/users/scopes",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to update user scopes in identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated scopes for user slug: %s", cmd.UserSlug))

	w.WriteHeader(http.StatusNoContent)
}
