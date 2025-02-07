package clients

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// Handler is an interface for handling calls to s2s service clients endpoints.
type Handler interface {

	// HandleClients handles a request from the client by submitting it against the s2s service clients endpoint.
	HandleClients(w http.ResponseWriter, r *http.Request)

	// HandleClient handles a request from the client by submitting it against the s2s service clients/{slug} endpoint.
	HandleClient(w http.ResponseWriter, r *http.Request)
}

// NewHandler returns a new Handler.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) Handler {
	return &handler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)).
			With(slog.String(util.SerivceKey, util.ServiceGateway)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      connect.S2sCaller

	logger *slog.Logger
}

// HandleClients handles a request from the client by submitting it against the s2s service clients endpoint.
// concrete implementation of the Handler interface.
func (h *handler) HandleClients(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /clients endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token found in /clients request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token found in /clients request",
		}
		e.SendJsonErr(w)
		return
	}

	// get user access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token provided in /clients request")
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sTkn, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get all clients from s2s service
	var clients []profile.Client
	if err := h.s2s.GetServiceData("/clients", s2sTkn, accessToken, &clients); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get clients: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get clients",
		}
		e.SendJsonErr(w)
		return
	}

	// respond with clients to ui
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(clients); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode clients: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode clients",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleClient handles a request from the client by submitting it against the s2s service clients/{slug} endpoint.
// concrete implementation of the Handler interface.
func (h *handler) HandleClient(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetClient(w, r)
		return
	case http.MethodPut:
		h.handlePutClient(w, r)
	default:
		h.logger.Error("only GET, POST, PUT, and DELETE requests are allowed to /clients/{slug} endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET, POST, PUT, and DELETE requests are allowed to /clients/{slug} endpoint",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetClient handles a GET request from the client by submitting it against the s2s service clients/{slug} endpoint.
func (h *handler) handleGetClient(w http.ResponseWriter, r *http.Request) {

	// get the url slug from the request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		h.logger.Error("no service client slug provided in get /clients/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "no service client slug provided in get /clients/{slug} request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight input validation (not checking if slug is valid or well-formed)
	if len(slug) < 16 || len(slug) > 64 {
		h.logger.Error("invalid scope slug")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid scope slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user's session token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token found in get /clients/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token found in get /clients/{slug} request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight input validation (not checking if session id is valid or well-formed)
	if len(session) < 16 || len(session) > 64 {
		h.logger.Error("invalid session token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session token",
		}
		e.SendJsonErr(w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for get /client/%s call to s2s service: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for get /client/%s call to s2s service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	var client profile.Client
	if err := h.s2s.GetServiceData(fmt.Sprintf("/clients/%s", slug), s2sToken, accessToken, &client); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service client %s: %s", slug, err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// respond with service client to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(client); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode service client %s: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode service client",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePutClient handles a PUT request from the client by submitting it against the s2s service clients/{slug} endpoint.\
func (h *handler) handlePutClient(w http.ResponseWriter, r *http.Request) {

	// get the url slug from the request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		h.logger.Error("no service client slug provided in /clients/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "no service client slug provided in /clients/{slug} request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight input validation (not checking if slug is valid or well-formed)
	if len(slug) < 16 || len(slug) > 64 {
		h.logger.Error("invalid scope slug")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid scope slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user's session token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token found in put /clients/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token found in put /clients/{slug} request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight input validation (not checking if session id is valid or well-formed)
	if len(session) < 16 || len(session) > 64 {
		h.logger.Error("invalid session token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session token",
		}
		e.SendJsonErr(w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for put /client/%s call to s2s service: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for put /client/%s call to s2s service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get request body
	var cmd ServiceClientCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode json in put /client/%s request body: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate client request
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid client request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare data
	updated := profile.Client{
		// Id is dropped
		Name:  cmd.Name,
		Owner: cmd.Owner,
		// CreatedAt is dropped
		Enabled:        cmd.Enabled,
		AccountExpired: cmd.AccountExpired,
		AccountLocked:  cmd.AccountLocked,
		// Slug is dropped
		//Scopes is dropped
	}

	// send request to s2s service to update client
	var response profile.Client
	if err := h.s2s.PostToService(fmt.Sprintf("/clients/%s", slug), s2sToken, accessToken, updated, &response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update client %s: %s", slug, err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// respond with updated client to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode updated client %s: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated client",
		}
		e.SendJsonErr(w)
		return
	}
}
