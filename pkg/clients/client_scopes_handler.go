package clients

import (
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
func NewScopesHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) ScopesHandler {
	return &scopesHandler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClientsScopes)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}
}

var _ ScopesHandler = (*scopesHandler)(nil)

// scopesHandler is the concrete implementation of the ScopesHandler interface.
type scopesHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      connect.S2sCaller

	logger *slog.Logger
}

// HandleScopes is the concrete implementation of the interface function that handles the request to udpate a client's assigned scopes.
func (h *scopesHandler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "PUT" {
		h.logger.Error("only PUT requests are allowed to /clients/scopes endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only PUT requests are allowed to /clients/scopes endpoint",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd ClientScopesCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json in client scopes request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("invalid client scopes request: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid csrf token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for s2s service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "service client scopes update failed: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// make request to the s2s service
	// no resopnse is expected from the s2s service --> 204 No Content
	if err := h.s2s.PostToService("/clients/scopes", s2sToken, accessToken, cmd, nil); err != nil {
		h.logger.Error(fmt.Sprintf("failed to post to /client/scopes endpoint: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("client (slug) %s scopes updated successfully", cmd.ClientSlug))
	w.WriteHeader(http.StatusNoContent)
}
