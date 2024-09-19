package user

import (
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
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
func NewProfileHandler(ux uxsession.Service, p provider.S2sTokenProvider) ProfileHandler {
	return &profileHandler{
		session:  ux,
		s2sToken: p,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentProfile)),
	}
}

var _ ProfileHandler = (*profileHandler)(nil)

// profileHandler is the concrete implementation of the ProfileHandler interface.
type profileHandler struct {
	session  uxsession.Service
	s2sToken provider.S2sTokenProvider

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

	// get access token if session is valid, authenticated, and unexpired
	accessToken, err := h.session.GetAccessToken(session.Value)
	if err != nil {
		h.session.HandleSessionErr(err, w)
		return
	}
}
