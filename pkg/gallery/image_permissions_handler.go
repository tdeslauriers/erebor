package gallery

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// PermissionsHandler defines the interface for handling and forwarding image permissions-related
// operations against the permissions service.
type PermissionsHandler interface {
	// HandlePermissions is a method that handles requests to the /images/permissions endpoint and
	// forwards to the permissions service if necessary.
	HandlePermissions(w http.ResponseWriter, r *http.Request)
}

// NewPermissionsHandler creates a new instance of PermissionsHandler, returning a pointer to the concrete implementation.
func NewPermissionsHandler(ux uxsession.Service, p provider.S2sTokenProvider, g connect.S2sCaller) PermissionsHandler {
	return &permissionsHandler{
		ux:      ux,
		tkn:     p,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageGallery)).
			With(slog.String(util.ComponentKey, util.ComponentImagePermissions)),
	}
}

var _ PermissionsHandler = (*permissionsHandler)(nil)

// permissionsHandler implements the PermissionsHandler interface.
type permissionsHandler struct {
	ux      uxsession.Service
	tkn     provider.S2sTokenProvider
	gallery connect.S2sCaller

	logger *slog.Logger
}

// HandlePermissions in the concrete implementation of the interface method which handles requests to
// the permissions/slug endpoint and forwards them to the permissions service if necessary.
func (h *permissionsHandler) HandlePermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getPermissionsData(w, r)
		return
	default:
		h.logger.Error("unsupported method for /images/permissions endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *permissionsHandler) getPermissionsData(w http.ResponseWriter, r *http.Request) {

	// get the session token
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token: %v", err))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token: %v", err))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get s2s token
	s2sToken, err := h.tkn.GetServiceToken(util.ServiceGallery)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get service token",
		}
		e.SendJsonErr(w)
		return
	}

	var permissions []permissions.Permission
	if err := h.gallery.GetServiceData("/permissions", s2sToken, accessToken, &permissions); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get permissions data: %v", err))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	// respond with the permissions data to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(permissions); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permissions data: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode permissions data",
		}
		e.SendJsonErr(w)
		return
	}
}
