package csrf

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/uxsession"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type Handler interface {
	// HandleGetCsrf handles the request to get a csrf token for the given session id.
	HandleGetCsrf(w http.ResponseWriter, r *http.Request)
}

func NewHandler(s uxsession.Service) Handler {
	return &csrfHandler{
		service: s,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentCsrf)),
	}
}

var _ Handler = (*csrfHandler)(nil)

type csrfHandler struct {
	service uxsession.Service

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

	// split ut rule path by "/" to get the last element => the session id
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
		switch {
		case err.Error() == uxsession.ErrInvalidSessionId:
			h.logger.Error(err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusBadRequest,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		case err.Error() == uxsession.ErrSessionRevoked:
		case err.Error() == uxsession.ErrSessionExpired:
		case err.Error() == uxsession.ErrTokenMismatch:
			h.logger.Error(err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
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
