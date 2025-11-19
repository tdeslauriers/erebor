package scopes

import (
	"context"
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

// Handler is an interface for calls to the gateway /scopes/{slug...} endpoint.
type Handler interface {

	// HandleScopes handles all requests to the gateway /scopes/{slug...} endpoint.
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, c *connect.S2sCaller) Handler {
	return &handler{
		session:     ux,
		tknProvider: p,
		s2s:         c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageScopes)).
			With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	session     uxsession.Service
	tknProvider provider.S2sTokenProvider
	s2s         *connect.S2sCaller

	logger *slog.Logger
}

// HandleScope handles get, put, post, and delete requests for a single scope.
// concrete implementation of the Handler interface's HandleScope method.
func (h *handler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// get slug if exists
	slug := r.PathValue("slug")

	switch r.Method {
	case http.MethodGet:

		if slug == "" {
			h.handleGetAll(w, r, tel, log)
			return
		} else {
			h.handleGet(w, r, tel, log)
			return
		}

	case "PUT":
		h.handlePut(w, r, tel, log)
		return
	case "POST":

		if slug == "add" {
			h.HandleAdd(w, r, tel, log)
			return
		} else {
			log.Error(fmt.Sprintf("invalid slug submitted to /scopes/%s", slug[:10]+"..."))
			e := connect.ErrorHttp{
				StatusCode: http.StatusMethodNotAllowed,
				Message:    "invalid slug submitted to /scopes/",
			}
			e.SendJsonErr(w)
			return
		}
	// case "DELETE":
	// 	return
	default:
		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path[:100]),
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) handleGetAll(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get user access token
	accessTkn, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sTkn, err := h.tknProvider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error("failed to get s2s token for s2s service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get all scopes from s2s service
	scopes, err := connect.GetServiceData[[]types.Scope](
		ctx,
		h.s2s,
		"/scopes",
		s2sTkn,
		accessTkn,
	)
	if err != nil {
		log.Error("failed to get scopes from s2s service", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d scopes from s2s service", len(scopes)))

	// respond with scopes to client ui
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scopes); err != nil {
		log.Error("failed to encode scopes", "err", err.Error())
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
func (h *handler) HandleAdd(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get request body
	var cmd ScopeCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to json decode scope request cmd for new scope", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to json decode scope request cmd for new scope",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of scope request body scope cmd
	if err := cmd.Validate(); err != nil {
		log.Error("invalid scope request cmd for new scope", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// remove csrf token from request cmd -> not needed upstream
	cmd.Csrf = ""

	// get s2s token for s2s service
	s2sToken, err := h.tknProvider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error("failed to get s2s token for s2s service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
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

	// add scope in s2s service
	response, err := connect.PostToService[types.Scope, types.Scope](
		ctx,
		h.s2s,
		"/scopes/add",
		s2sToken,
		accessToken,
		add,
	)
	if err != nil {
		log.Error("failed to add scope in s2s service", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully added new scope %s to s2s service", response.Name))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("failed to encode created scope to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode created scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) handleGet(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get user's session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get access token from session token for /scope/%s call to s2s service: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.tknProvider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get s2s token for /scope/%s call to s2s service", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get scope from s2s service
	scope, err := connect.GetServiceData[types.Scope](
		ctx,
		h.s2s,
		fmt.Sprintf("/scopes/%s", slug),
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get scope from s2s service for /scope/%s call", slug), "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved scope %s from s2s service", scope.Name))

	// respond with scope to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(scope); err != nil {
		log.Error("failed to encode scope to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePut handles the request to update an existing scope.
func (h *handler) handlePut(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get request body
	var cmd ScopeCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to json decode scope request cmd for scope update", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of scope request body scope cmd
	if err := cmd.Validate(); err != nil {
		log.Error(fmt.Sprintf("invalid scope request cmd for slug %s", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token", "err", err.Error())
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

	// get s2s token for s2s service
	s2sToken, err := h.tknProvider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get s2s token for /scope/%s call to s2s service", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	// update scope in s2s service
	response, err := connect.PutToService[types.Scope, types.Scope](
		ctx,
		h.s2s,
		fmt.Sprintf("/scopes/%s", slug),
		s2sToken,
		accessToken,
		updated,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update scope in s2s service for /scope/%s call", slug), "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Error(fmt.Sprintf("successfully updated scope %s in s2s service", response.Name))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("failed to encode updated scope to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}
