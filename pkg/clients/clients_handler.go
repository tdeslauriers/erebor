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
	"github.com/tdeslauriers/ran/pkg/pat"
)

// NewClientHandler returns a new Handler.
func NewClientHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) ClientHandler {
	return &clientHandler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}
}

// ClientHandler is an interface for handling calls to s2s service clients endpoints.
type ClientHandler interface {

	// HandleClients handles a request from the client by submitting it against the s2s service clients endpoint.
	HandleClients(w http.ResponseWriter, r *http.Request)

	// HandleClient handles a request from the client by submitting it against the s2s service clients/{slug} endpoint.
	HandleClient(w http.ResponseWriter, r *http.Request)

	// HandleGeneratePat handles a request from the client to generate a personal access token (PAT) for service clients.
	HandleGeneratePat(w http.ResponseWriter, r *http.Request)
}

var _ ClientHandler = (*clientHandler)(nil)

type clientHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      connect.S2sCaller

	logger *slog.Logger
}

// HandleClients handles a request from the client by submitting it against the s2s service clients endpoint.
// concrete implementation of the Handler interface.
func (h *clientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {

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
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
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
func (h *clientHandler) HandleClient(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetClient(w, r)
		return
	case http.MethodPut:
		h.handlePutClient(w, r)
		return
	case http.MethodPost:
		// this is used for the register service client use case/business logic, it will reject all other post requests
		h.handlePostClient(w, r)
		return
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
func (h *clientHandler) handleGetClient(w http.ResponseWriter, r *http.Request) {

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for get /client/slug call to s2s service: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for get /client/%s call to s2s service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
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
func (h *clientHandler) handlePutClient(w http.ResponseWriter, r *http.Request) {

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for put /client/slug call to s2s service: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
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

// handlePostClient handles a POST request from the client by submitting it against the s2s service clients/{slug} endpoint.
func (h *clientHandler) handlePostClient(w http.ResponseWriter, r *http.Request) {

	// get the url slug from the request
	segments := strings.Split(r.URL.Path, "/")

	// validate the url path is /clients/register
	var param string
	if len(segments) > 1 {
		param = segments[len(segments)-1]
		if param != "register" {
			h.logger.Error("invalid url path for post /clients/register request")
			e := connect.ErrorHttp{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid url path for post /clients/register request",
			}
			e.SendJsonErr(w)
			return
		}
	} else {
		h.logger.Error("no service client slug provided in /clients/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "no service client slug provided in /clients/{slug} request",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for post to /clients/register on s2s service: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for post to /clients/register on s2s service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var cmd RegisterClientCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json in post /clients/register request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("error validating request body of service client registration request: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
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

	// prepare data: drop any fields that are not needed
	cmd.Csrf = ""
	cmd.Id = ""
	cmd.Slug = ""

	var registered RegisterClientCmd
	if err := h.s2s.PostToService("/clients/register", s2sToken, accessToken, cmd, &registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to register service client: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// password will be empty, set to empty string anyway, just in case
	registered.Password = ""
	registered.ConfirmPassword = ""

	// respond 201 + registered client to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered service client data is a convenience only, omit on error
		h.logger.Error(fmt.Sprintf("failed to encode registered client: %s", err.Error()))
		return
	}
}

// HandleGeneratePat handles a request from the client to generate a personal access token (PAT) for service clients.
func (h *clientHandler) HandleGeneratePat(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		h.logger.Error("only POST requests are allowed to /clients/generate/pat endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed to /clients/generate/pat endpoint",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for post to /clients/generate/pat on s2s service: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd pat.GeneratePatCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode json in post /clients/generate/pat request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json for pat generation request",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("error validating request body of pat generation request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
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

	// set csrf to empty string to avoid sending it upstream
	cmd.Csrf = ""

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for post to /clients/generate/pat on s2s service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// send request to s2s service to generate pat

	// respond with pat to ui
}
