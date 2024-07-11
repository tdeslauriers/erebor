package oauth

import (
	"encoding/json"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type Handler interface {
	// HandleGetState handles the request from the client to get the oauth state, nonce, client id, and callback url variables
	// to be used in the login url for the oauth flow
	HandleGetState(w http.ResponseWriter, r *http.Request)
}

func NewHandler(o Service) Handler {
	return &handler{
		oauthService: o,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentOauth)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	oauthService Service

	logger *slog.Logger
}

type SessionCmd struct {
	SessionToken string `json:"session_token"`
}

func (h *handler) HandleGetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /oauth/state endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd SessionCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("unable to decode session_token json in the request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json for session token",
		}
		e.SendJsonErr(w)
		return
	}

	if len(cmd.SessionToken) < 16 || len(cmd.SessionToken) > 64 {
		h.logger.Error(fmt.Sprintf("session token length is invalid: %d", len(cmd.SessionToken)))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "not well-formed session token",
		}
		e.SendJsonErr(w)
		return
	}

	// look up/create oauth state, nonce, client id, and callback url for the session
	exchange, err := h.oauthService.Obtain(cmd.SessionToken)
	if err != nil {
		h.oauthService.HandleServiceErr(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(exchange); err != nil {
		h.logger.Error("failed to encode oauth exchange to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

}
