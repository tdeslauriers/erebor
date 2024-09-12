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

func NewCsrfHandler(s Service) CsrfHandler {
	return &csrfHandler{
		service: s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentCsrf)),
	}
}

var _ CsrfHandler = (*csrfHandler)(nil)

type csrfHandler struct {
	service Service

	logger *slog.Logger
}

func (h *csrfHandler) HandleGetCsrf(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /csrf endpoint")
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
		h.logger.Error("invalid session id")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session id",
		}
		e.SendJsonErr(w)
		return
	}

	// get csrf token
	uxSession, err := h.service.GetCsrf(sessionId)
	if err != nil {
		h.handleServiceErrors(err, w)
		return
	}

	// respond with csrf token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(uxSession); err != nil {
		h.logger.Error("failed to encode csrf token to json", "err", err.Error())
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
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionRevoked):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionRevoked,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionExpired):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionExpired,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrSessionNotFound):
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    ErrSessionNotFound,
		}
		e.SendJsonErr(w)
	default:
		h.logger.Error("failed to get csrf token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get csrf token",
		}
		e.SendJsonErr(w)
		return
	}
}
