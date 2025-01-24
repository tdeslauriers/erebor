package scopes

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// Hanlder handles all requests for scopes.
type Handler interface {

	// HandleScopes handles the request to get all scopes.
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) Handler {
	return &handler{
		session:     ux,
		tknProvider: p,
		s2s:         c,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageScopes)).
			With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	session     uxsession.Service
	tknProvider provider.S2sTokenProvider
	s2s         connect.S2sCaller

	logger *slog.Logger
}

func (h *handler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /scopes endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user session token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token provided")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token provided",
		}
		e.SendJsonErr(w)
		return
	}

	// get user access token
	accessTkn, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token")
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sTkn, err := h.tknProvider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get all scopes
	var scopes []types.Scope
	if err := h.s2s.GetServiceData("/scopes", s2sTkn, accessTkn, &scopes); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get scopes from s2s service: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// respond with scopes to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(scopes); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode scopes: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scopes",
		}
		e.SendJsonErr(w)
		return
	}
}
