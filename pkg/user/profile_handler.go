package user

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

// ProfileHandler is the interface for handling profile requests from the client.
// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
type ProfileHandler interface {
	// HandleProfile handles the profile request from the client by submitting it against the user auth service and user profile service.
	// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
	HandleProfile(w http.ResponseWriter, r *http.Request)
}

// NewProfileHandler returns a pointer to a concrete implementation of the ProfileHandler interface.
func NewProfileHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) ProfileHandler {
	return &profileHandler{
		session:  ux,
		provider: p,
		identity: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentProfile)),
	}
}

var _ ProfileHandler = (*profileHandler)(nil)

// profileHandler is the concrete implementation of the ProfileHandler interface.
type profileHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity connect.S2sCaller
	// profile connect.S2sCaller: silhoutte service, ie, non-identity data that is part of user profile, address, phone, preferences, etc

	logger *slog.Logger
}

// HandleProfile handles the profile requests from the client by submitting it against the user auth service and user profile service.
// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
func (h *profileHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		// get user profile
		h.handleGetProfile(w, r)
		return
	case "PUT":
	// update user profile
	default:
		h.logger.Error("only GET and PUT requests are allowed to /profile endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET and PUT requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetProfile handles the GET request for a user's profile.
func (h *profileHandler) handleGetProfile(w http.ResponseWriter, r *http.Request) {

	// validate the user has an active, authenticated session
	session, err := r.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			h.logger.Error("no session_id cookie found in request")
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    "no session_id cookie found in request",
			}
			e.SendJsonErr(w)
			return
		} else {
			h.logger.Error("failed to get session_id cookie from request", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to get session_id cookie from request",
			}
			e.SendJsonErr(w)
			return
		}
	}

	// get user access token from session
	accessToken, err := h.session.GetAccessToken(session.Value)
	if err != nil {
		h.logger.Error("failed to get access token from session", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2sIdentity)
	if err != nil {
		h.logger.Error("failed to get s2s token for call to profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get user data from identity service
	var user profile.User
	if err := h.identity.GetServiceData("/profile", accessToken, s2sToken, user); err != nil {
		h.logger.Error("failed to get user profile", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// respond user profile to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.logger.Error("failed to encode user profile to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode user profile to json",
		}
		e.SendJsonErr(w)
		return
	}
}
