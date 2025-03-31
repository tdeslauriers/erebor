package user

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

// ScopesHandler is an interface for handling user scope requests.
type ScopesHandler interface {
	// HandleScopes handles the request to update a user's assigned scopes.
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewScopesHandler returns a pointer to the concrete implementation of the ScopesHandler interface.
func NewScopesHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) ScopesHandler {
	return &scopesHandler{
		session:  ux,
		provider: p,
		identity: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUserScopes)).
			With(slog.String(util.SerivceKey, util.ServiceGateway)),
	}
}

var _ ScopesHandler = (*scopesHandler)(nil)

// scopesHandler is the concrete implementation of the ScopesHandler interface.
type scopesHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity connect.S2sCaller

	logger *slog.Logger
}

// HandleScopes is the concrete implementation of the interface function that handles the request to update a user's assigned scopes.
func (h *scopesHandler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "PUT" {
		h.logger.Error("only PUT requests are allowed to /user/scopes endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only PUT requests are allowed to /user/scopes endpoint",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token: %s", err.Error()))
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
	var cmd UserScopesCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json in user scopes request body: %s", err.Error())
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
		errMsg := fmt.Sprintf("invalid user scopes request: %s", err.Error())
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

	// get service token
	s2sToken, err := h.provider.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for identity service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user scopes request failed: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// make request to the identity service
	// no response is expected from the identity service --> 204 No Content
	if err := h.identity.PostToService("/users/scopes", s2sToken, accessToken, cmd, nil); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update user scopes: %s", err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("user scopes updated for user slug: %s", cmd.UserSlug))
	w.WriteHeader(http.StatusNoContent)
}
