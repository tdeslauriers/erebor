package user

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

type UserHandler interface {
	// HandleUsers returns a list of users by forwarding the request to the identity service.
	HandleUsers(w http.ResponseWriter, r *http.Request)

	// HandleUser handles a request from the client by submitting it against the user identity service and user profile service.
	HandleUser(w http.ResponseWriter, r *http.Request)
}

func NewUserHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) UserHandler {
	return &userHandler{
		session:  ux,
		provider: p,
		identity: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ UserHandler = (*userHandler)(nil)

type userHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity connect.S2sCaller

	logger *slog.Logger
}

func (h *userHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /users endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token provided in request Authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token provided in request Authorization header",
		}
		e.SendJsonErr(w)
		return
	}

	// get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceUserIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for identity service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token for identity service",
		}
		e.SendJsonErr(w)
		return
	}

	// get users from identity service
	var users []profile.User
	if err := h.identity.GetServiceData("/users", s2sToken, accessToken, &users); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get users from identity service: %s", err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// respond with users to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode users to json: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode users to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *userHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
}
