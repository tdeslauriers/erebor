package authentication

import (
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
}
