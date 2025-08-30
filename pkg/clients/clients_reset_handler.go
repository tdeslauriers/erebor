package clients

import (
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

func NewResetHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) ResetHandler {
	return &resetHandler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}

}

var _ ResetHandler = (*resetHandler)(nil)

type resetHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      connect.S2sCaller

	logger *slog.Logger
}

// HandleReset is the concrete implementation of the interface function that handles the password reset request for client services.
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /reset endpoint")
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
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
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
	var cmd profile.ResetCmd
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
		errMsg := fmt.Sprintf("error validating request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
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
			Message:    "service client password reset unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// make the request to the s2s service
	// there will be no response body, only a status code -> s2s will not return password data
	if err := h.s2s.PostToService("/clients/reset", s2sToken, accessToken, cmd, nil); err != nil {
		h.logger.Error(fmt.Sprintf("error calling service client reset endpoint on s2s service: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("service client %s password reset successful", cmd.ResourceId))
	w.WriteHeader(http.StatusNoContent)
}
