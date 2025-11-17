package uxsession

import (
	"encoding/json"
	"erebor/internal/util"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

// Handler is the interface for handling session requests from the client.
type Handler interface {

	// HandleGetSession handles the request to create a new ANONYMOUS session
	// TODO: this should be rate limited
	HandleGetSession(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new session Handler instance.
func NewHandler(s Service) Handler {
	return &handler{
		session: s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.ComponentKey, util.ComponentSession)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface.
type handler struct {
	session Service

	logger *slog.Logger
}

// HandleGetSession implements HandleGetSession of session Handler interface
func (h *handler) HandleGetSession(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	telemetry := connect.NewTelemetry(r)
	logger := h.logger.With(telemetry.TelemetryFields()...)

	if r.Method != http.MethodGet {
		logger.Error("only GET requests are allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// create/persist session (anonymous session)
	session, err := h.session.Build(Anonymous)
	if err != nil {
		logger.Error("failed to create anonymous session", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to create anonymous session",
		}
		e.SendJsonErr(w)
		return
	}

	logger.Info("successfully created anonymous session")

	// respond with anonymous session
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(&UxSession{SessionToken: session.SessionToken, CreatedAt: session.CreatedAt, Authenticated: false}); err != nil {
		logger.Error("failed to encode session to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode session to json",
		}
		e.SendJsonErr(w)
		return
	}
}
