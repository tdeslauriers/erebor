package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"erebor/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type LoginHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

func NewLoginHandler(siteUrl string, provider session.S2sTokenProvider, caller connect.S2sCaller, loginSvc OauthService) LoginHandler {
	return &loginHandler{
		siteUrl:      siteUrl,
		s2sProvider:  provider,
		caller:       caller,
		loginService: loginSvc,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuth)),
	}
}

var _ LoginHandler = (*loginHandler)(nil)

type loginHandler struct {
	siteUrl      string
	s2sProvider  session.S2sTokenProvider
	caller       connect.S2sCaller
	loginService OauthService

	logger *slog.Logger
}

func (h *loginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /login endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd session.UserLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("unable to decode json in user login request body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// login level field validation
	// check for empty strings
	if cmd.Username == "" || cmd.Password == "" {
		h.logger.Error("login contained empty string for username or password")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "Username and password are required fields; cannot be empty.",
		}
		e.SendJsonErr(w)
		return
	}

	// check length of username and password isnt too long
	if len(strings.TrimSpace(cmd.Username)) > 254 || len(strings.TrimSpace(cmd.Password)) > 64 {
		h.logger.Error("login contained username or password that was too long")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "Username or passward exceeded allowed length.",
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
	s2sToken, err := h.s2sProvider.GetServiceToken("shaw")
	if err != nil {
		h.logger.Error("failed to retreive s2s token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "login unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// set up and persist oauth2 url params
	// if no redirect url is provided, use the site url
	oauth, err := h.loginService.Create(h.siteUrl)



	// post creds to user auth login

}
