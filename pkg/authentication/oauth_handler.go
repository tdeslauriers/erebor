package authentication

import (
	"encoding/json"
	"erebor/internal/util"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type OauthHandler interface {
	HandleGetState(w http.ResponseWriter, r *http.Request)
}

func NewOauthHandler(siteUrl string, oauthService OauthService) OauthHandler {
	return &oauthHandler{
		siteUrl:      siteUrl,
		oauthService: oauthService,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuth)).With(slog.String(util.ServiceKey, util.ServiceOauth)),
	}
}

var _ OauthHandler = (*oauthHandler)(nil)

type oauthHandler struct {
	siteUrl      string
	oauthService OauthService

	logger *slog.Logger
}

func (h *oauthHandler) HandleGetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /oauth/state endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// create/persist oauth vars
	exchange, err := h.oauthService.Create(h.siteUrl)
	if err != nil {
		h.logger.Error("failed to create oauth exchange", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to create oauth state and nonce variables",
		}
		e.SendJsonErr(w)
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

	// http.Redirect(w, r, state.RedirectUrl, http.StatusTemporaryRedirect)
}
