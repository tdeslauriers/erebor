package uxsession

import (
	"encoding/json"
	"erebor/internal/util"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type Handler interface {

	// HandleGetSession handles the request to create a new ANONYMOUS session
	// TODO: this should be rate limited
	HandleGetSession(w http.ResponseWriter, r *http.Request)
}

func NewHandler(s Service) Handler {
	return &handler{
		service: s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentUxSession)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	service Service

	logger *slog.Logger
}

// implement GetSession of SessionHandler interface
func (h *handler) HandleGetSession(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /session endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// create/persist session (anonymous session)
	session, err := h.service.Build(Anonymous)
	if err != nil {
		h.logger.Error("failed to create session", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to create session",
		}
		e.SendJsonErr(w)
		return
	}

	// respond with anonymous session
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(session); err != nil {
		h.logger.Error("failed to encode session to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode session to json",
		}
		e.SendJsonErr(w)
		return
	}
}
