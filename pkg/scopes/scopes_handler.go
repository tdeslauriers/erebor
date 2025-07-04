package scopes

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// Hanlder handles all requests for scopes.
type Handler interface {

	// HandleScopes handles the request to get all scopes.
	HandleScopes(w http.ResponseWriter, r *http.Request)

	// HandleAdd handles the request to add a new scope.
	HandleAdd(w http.ResponseWriter, r *http.Request)

	// HandleScope handles get, put, post, and delete requests for a single scope.
	HandleScope(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) Handler {
	return &handler{
		session:     ux,
		tknProvider: p,
		s2s:         c,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageScopes)).
			With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	session     uxsession.Service
	tknProvider provider.S2sTokenProvider
	s2s         connect.S2sCaller

	logger *slog.Logger
}

func (h *handler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /scopes endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get user access token
	accessTkn, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token provided")
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sTkn, err := h.tknProvider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get all scopes
	var scopes []types.Scope
	if err := h.s2s.GetServiceData("/scopes", s2sTkn, accessTkn, &scopes); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get scopes from s2s service: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// respond with scopes to client ui
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scopes); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode scopes: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scopes",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleAdd handles the request to add a new scope.
// concrete implementation of the Handler interface.
func (h *handler) HandleAdd(w http.ResponseWriter, r *http.Request) {

	// only POST requests are allowed
	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /scopes/add endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from scope add request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for /scope/add call to s2s service: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get request body
	var cmd ScopeCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode scope request cmd for new scope : %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of scope request body scope cmd
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid scope request cmd for new scope: %s", err.Error()))
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

	// remove csrf token from request cmd -> not needed upstream
	cmd.Csrf = ""

	// get s2s token for s2s service
	s2sToken, err := h.tknProvider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for /scope/add call to s2s service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// prepare data
	add := types.Scope{
		ServiceName: cmd.ServiceName,
		Scope:       cmd.Scope,
		Name:        cmd.Name,
		Description: cmd.Description,
		Active:      cmd.Active,
	}

	// update scope in s2s service
	var response types.Scope
	if err := h.s2s.PostToService("/scopes/add", s2sToken, accessToken, add, &response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update scope in s2s service for scopes/add: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode response scope to json for scopes/add: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleScope handles get, put, post, and delete requests for a single scope.
// concrete implementation of the Handler interface's HandleScope method.
func (h *handler) HandleScope(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		h.handleGet(w, r)
		return
	case "PUT":
		h.handlePut(w, r)
		return
	// case "POST":
	// 	return
	// case "DELETE":
	// 	return
	default:
		h.logger.Error("only GET, PUT, POST, and DELETE requests are allowed to /scopes/{scope} endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET, PUT, POST, and DELETE requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) handleGet(w http.ResponseWriter, r *http.Request) {

	// get user's session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid scope slug",
		}
		e.SendJsonErr(w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for /scope/%s call to s2s service: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.tknProvider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for /scope/%s call to s2s service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get scope from s2s service
	var scope types.Scope
	if err := h.s2s.GetServiceData(fmt.Sprintf("/scopes/%s", slug), s2sToken, accessToken, &scope); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get scope from s2s service: %s", err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// respond with scope to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(scope); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode scope to json: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) handlePut(w http.ResponseWriter, r *http.Request) {

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for /scope/slug call to s2s service: %s", err.Error()))
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
	s2sToken, err := h.tknProvider.GetServiceToken(util.ServiceS2s)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for /scope/%s call to s2s service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// get request body
	var cmd ScopeCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode scope request cmd for slug %s: %s", slug, err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of scope request body scope cmd
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid scope request cmd for slug %s: %s", slug, err.Error()))
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
	updated := types.Scope{
		ServiceName: cmd.ServiceName,
		Scope:       cmd.Scope,
		Name:        cmd.Name,
		Description: cmd.Description,
		Active:      cmd.Active,
		Slug:        cmd.Slug,
	}

	// update scope in s2s service
	var response types.Scope
	if err := h.s2s.PostToService(fmt.Sprintf("/scopes/%s", slug), s2sToken, accessToken, updated, &response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update scope in s2s service for scope/slug %s: %s", slug, err.Error()))
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode response scope to json for scope/slug: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}
