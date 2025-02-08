package clients

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
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
			With(slog.String(util.SerivceKey, util.ServiceGateway)),
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
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token found in authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session_id cookie found in request",
		}
		e.SendJsonErr(w)
		return
	}

	if valid, err := h.session.IsValid(session); !valid {
		h.logger.Error("invalid session token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd profile.ResetCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error("error decoding request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "error decoding request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("error validating request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "error validating request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	// get access token tied to the session
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error("error getting access token from session", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error("failed to retrieve s2s token", "err", err.Error())
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
		h.logger.Error("error calling service client reset endpoint on s2s service", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info("service client password reset successful")
	w.WriteHeader(http.StatusNoContent)
}
