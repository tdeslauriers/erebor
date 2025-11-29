package gallery

import (
	"context"
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
func NewPermissionsHandler(ux uxsession.Service, p provider.S2sTokenProvider, g *connect.S2sCaller) PermissionsHandler {
	return &permissionsHandler{
		ux:      ux,
		tkn:     p,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageGallery)).
			With(slog.String(util.ComponentKey, util.ComponentImagePermissions)),
	}
}

var _ PermissionsHandler = (*permissionsHandler)(nil)

// permissionsHandler implements the PermissionsHandler interface.
type permissionsHandler struct {
	ux      uxsession.Service
	tkn     provider.S2sTokenProvider
	gallery *connect.S2sCaller

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
		// generate telemetry
		tel := connect.NewTelemetry(r, h.logger)
		log := h.logger.With(tel.TelemetryFields()...)

		log.Error("unsupported method for /images/permissions endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *permissionsHandler) getPermissionsData(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)
	// get the session token
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get s2s token
	s2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceGallery)
	if err != nil {
		log.Error("failed to get service token for gallery service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service for permissions data
	permissions, err := connect.GetServiceData[[]permissions.Permission](
		ctx,
		h.gallery,
		"/permissions",
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get permissions data from gallery service", "err", err.Error())
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d permissions from gallery", len(permissions)))

	// respond with the permissions data to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(permissions); err != nil {
		log.Error("failed to encode permissions data to JSON", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode permissions data to json",
		}
		e.SendJsonErr(w)
		return
	}
}
