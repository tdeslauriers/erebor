package clients

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
	"github.com/tdeslauriers/ran/pkg/clients"
	"github.com/tdeslauriers/ran/pkg/pat"
)

// NewClientHandler returns a new Handler.
func NewClientHandler(ux uxsession.Service, p provider.S2sTokenProvider, c *connect.S2sCaller) ClientHandler {

	return &clientHandler{
		session:  ux,
		provider: p,
		s2s:      c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

// ClientHandler is an interface for handling calls to s2s service clients endpoints.
type ClientHandler interface {

	// HandleClients handles /clients requests, submitting them against the s2s service clients endpoint.
	HandleClients(w http.ResponseWriter, r *http.Request)

	// HandleGeneratePat handles a request from the client to generate a personal access token (PAT) for service clients.
	HandleGeneratePat(w http.ResponseWriter, r *http.Request)
}

var _ ClientHandler = (*clientHandler)(nil)

type clientHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	s2s      *connect.S2sCaller

	logger *slog.Logger
}

// HandleClients handles a request from the client by submitting it against the s2s service clients/{slug...} endpoint.
// It is the concrete implementation of the ClientHandler interface.
func (h *clientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// check for a slug to determine if this is a get call for all clients or the slug of a specific client
		// get the url slug from the request if it exists
		slug := r.PathValue("slug")
		if slug == "" {

			h.handleGetAllClients(w, r)
			return
		} else {

			h.handleGetClient(w, r)
			return
		}
	case http.MethodPut:
		h.handlePutClient(w, r)
		return
	case http.MethodPost:
		// this is used for the register service client use case/business logic, it will reject all other post requests
		h.handlePostClient(w, r)
		return
	default:
		// generate telemetry
		telemetry := connect.NewTelemetry(r, h.logger)
		logger := h.logger.With(telemetry.TelemetryFields()...)

		logger.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAllClients is a helper function which handles a request /clients by submitting it against
// the s2s service clients endpoint.
func (h *clientHandler) handleGetAllClients(w http.ResponseWriter, r *http.Request) {


	// generate telemetry
	tel:= connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)


	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get user access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for s2s service
	s2sTkn, err := h.provider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get s2s token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get all clients from s2s service
	clients, err := connect.GetServiceData[[]clients.Client](
		ctx,
		h.s2s,
		"/clients",
		s2sTkn,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get service clients from s2s service", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d clients from s2s service", len(clients)))

	// respond with clients to ui
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(clients); err != nil {
		log.Error("failed to encode clients to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode clients to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetClient handles a GET request from the client by submitting it against the s2s service clients/{slug} endpoint.
func (h *clientHandler) handleGetClient(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel:= connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session from request", "err", err.Error())
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
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get s2s token for get /client/%s call to s2s service", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get client from s2s service
	client, err := connect.GetServiceData[clients.Client](
		ctx,
		h.s2s,
		fmt.Sprintf("/clients/%s", slug),
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get service client %s from s2s service", slug), "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved client %s from s2s service", slug))

	// respond with service client to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(client); err != nil {
		log.Error(fmt.Sprintf("failed to encode client %s to json", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode service client to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePutClient handles a PUT request from the client by submitting it against the s2s service clients/{slug} endpoint.\
func (h *clientHandler) handlePutClient(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel:= connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session from request", "err", err.Error())
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
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error("failed to get s2s token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get request body
	var cmd ServiceClientCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error(fmt.Sprintf("failed to decode json in put /client/%s request body", slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate client request
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalide client update request", "err", err.Error())
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

	// prepare data
	updated := clients.Client{
		// Id is dropped
		// CreatedAt is dropped
		// Slug is dropped
		//Scopes is dropped
		Name:           cmd.Name,
		Owner:          cmd.Owner,
		Enabled:        cmd.Enabled,
		AccountExpired: cmd.AccountExpired,
		AccountLocked:  cmd.AccountLocked,
	}

	// send request to s2s service to update client
	response, err := connect.PutToService[clients.Client, clients.Client](
		ctx,
		h.s2s,
		fmt.Sprintf("/clients/%s", slug),
		s2sToken,
		accessToken,
		updated,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update client %s", slug), "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated client %s", slug))

	// respond with updated client to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode updated client %s: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated client to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePostClient handles a POST request from the client by submitting it against the s2s service clients/{slug} endpoint.
func (h *clientHandler) handlePostClient(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel:= connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the url slug from the request
	slug := r.PathValue("slug")
	if slug != "register" {
		log.Error("only POST requests to /clients/register are allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "only POST requests to /clients/register are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user's session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session from request", "err", err.Error())
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

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		log.Error("failed to get s2s token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var cmd RegisterClientCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in post /clients/register request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json for client registration request",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid client registration request body", "err", err.Error())
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

	// prepare data: drop any fields that are not needed
	cmd.Csrf = ""
	cmd.Id = ""
	cmd.Slug = ""

	// post registration request to s2s service to register client
	registered, err := connect.PostToService[RegisterClientCmd, RegisterClientCmd](
		ctx,
		h.s2s,
		"/clients/register",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to register client with s2s service", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	// password will be empty, set to empty string anyway, just in case
	registered.Password = ""
	registered.ConfirmPassword = ""

	log.Info(fmt.Sprintf("successfully registered client %s", registered.Name))

	// respond 201 + registered client to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered service client data is a convenience only, omit on error
		log.Error("failed to encode registered client to json", "err", err.Error())
		return
	}
}

// HandleGeneratePat handles a request from the client to generate a personal access token (PAT) for service clients.
func (h *clientHandler) HandleGeneratePat(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	telemetry := connect.NewTelemetry(r, h.logger)
	logger := h.logger.With(telemetry.TelemetryFields()...)

	// add telemetry to context for downstream calls
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, telemetry)

	if r.Method != http.MethodPost {
		logger.Error("only POST requests are allowed to /clients/generate/pat endpoint")
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
		logger.Error("failed to extract session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		logger.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd pat.GeneratePatCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		logger.Error("failed to decode json in post /clients/generate/pat request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json  request body for pat generation request",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		logger.Error("Failed to validate request body for pat generation request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		logger.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// set csrf to empty string to avoid sending it upstream
	cmd.Csrf = ""

	// get s2s token for s2s service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceS2s)
	if err != nil {
		logger.Error("failed to get s2s token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// send request to s2s service to generate pat
	response, err := connect.PostToService[pat.GeneratePatCmd, pat.Pat](
		ctx,
		h.s2s,
		"/generate/pat",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		logger.Error("failed to generate pat", "err", err.Error())
		h.s2s.RespondUpstreamError(err, w)
		return
	}

	logger.Info(fmt.Sprintf("successfully generated pat for client %s", cmd.Slug))

	// respond with pat to ui
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode generated pat: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode generated pat",
		}
		e.SendJsonErr(w)
		return
	}
}
