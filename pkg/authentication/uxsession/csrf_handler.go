package uxsession

import (
	"encoding/json"
	"erebor/internal/util"

	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type CsrfHandler interface {

	// HandleGetCsrf handles the request to get a csrf token for the given session id.
	HandleGetCsrf(w http.ResponseWriter, r *http.Request)
}

func NewCsrfHandler(c CsrfService) CsrfHandler {
	return &csrfHandler{
		csrf: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentCsrf)),
	}
}

var _ CsrfHandler = (*csrfHandler)(nil)

type csrfHandler struct {
	csrf CsrfService

	logger *slog.Logger
}

// HandleGetCsrf implements HandleGetCsrf of CsrfHandler interface
func (h *csrfHandler) HandleGetCsrf(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	telemetry := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(telemetry.TelemetryFields()...)

	// validate http method
	if r.Method != http.MethodGet {
		log.Error("only GET requests are allowed to /csrf endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// split url path by "/" to get the last element => the session id
	segments := strings.Split(r.URL.Path, "/")

	var sessionId string
	if len(segments) > 1 {
		sessionId = segments[len(segments)-1]
	}

	// light weight input validation (not checking if session id is valid or well-formed)
	if len(sessionId) < 16 || len(sessionId) > 64 {
		log.Error("invalid session id")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session id",
		}
		e.SendJsonErr(w)
		return
	}

	// get csrf token
	uxSession, err := h.csrf.GetCsrf(sessionId)
	if err != nil {
		log.Error("failed to get csrf token", "err", err.Error())
		h.handleServiceErrors(err, w)
		return
	}

	// respond with csrf token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(uxSession); err != nil {
		log.Error("failed to encode csrf token to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode csrf token to json",
		}
		e.SendJsonErr(w)
		return
	}

}

func (h *csrfHandler) handleServiceErrors(err error, w http.ResponseWriter) {
	switch {
	case strings.Contains(err.Error(), ErrInvalidSession):
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionRevoked):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionRevoked,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionExpired):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionNotFound,
		}
		e.SendJsonErr(w)
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get csrf token",
		}
		e.SendJsonErr(w)
		return
	}
}
