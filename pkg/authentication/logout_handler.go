package authentication

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

// LogoutHandler is the interface for handling logout requests from the client.
type LogoutHandler interface {
	// HandleLogout handles the logout request from the client by submitting it against the user auth service.
	HandleLogout(w http.ResponseWriter, r *http.Request)
}

// NewLogoutHandler creates a new LogoutHandler instance.
func NewLogoutHandler(ux uxsession.Service) LogoutHandler {
	return &logoutHandler{
		uxSession: ux,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAuth)).
			With(slog.String(util.ComponentKey, util.ComponentLogout)),
	}
}

var _ LogoutHandler = (*logoutHandler)(nil)

// logoutHandler is the concrete implementation of the LogoutHandler interface.
type logoutHandler struct {
	uxSession uxsession.Service

	logger *slog.Logger
}

func (h *logoutHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /logout endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd LogoutCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("failed to decode json in the logout cmd request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("failed to validate session input value", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to validate session",
		}
		e.SendJsonErr(w)
		return
	}

	// logout user
	if err := h.uxSession.DestroySession(cmd.Session); err != nil {
		h.logger.Error("failed to logout", "err", err.Error())
		h.uxSession.HandleSessionErr(err, w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
