package authentication

import (
	"encoding/json"
	"erebor/internal/util"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type CallbackHandler interface {
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

func NewCallbackHandler(s2sProvider session.S2sTokenProvider, caller connect.S2sCaller, cryptor data.Cryptor, db data.SqlRepository) CallbackHandler {
	return &callbackHandler{
		s2sProvider: s2sProvider,
		caller:      caller,
		cryptor:     cryptor,
		db:          db,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentCallback)),
	}
}

var _ CallbackHandler = (*callbackHandler)(nil)

type callbackHandler struct {
	s2sProvider session.S2sTokenProvider
	caller      connect.S2sCaller
	cryptor     data.Cryptor
	db          data.SqlRepository

	logger *slog.Logger
}

func (h *callbackHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /callback endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd session.AuthCodeExchange
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("failed to decode json in user callback request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the callback request
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("invalid callback request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
	s2sToken, err := h.s2sProvider.GetServiceToken(util.ServiceUserIdentity)
	if err != nil {
		h.logger.Error("failed to retreive s2s token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "login unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var access session.AccessTokenResponse
	if err := h.caller.PostToService("/callback", s2sToken, "", cmd, &access); err != nil {
		h.logger.Error("call to identity service login failed", "err", err.Error())
		h.caller.RespondUpstreamError(err, w)
		return
	}

	// update the user session
}
