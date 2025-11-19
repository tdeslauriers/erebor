package tasks

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
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// AllowanceHandler is an interface for handling requests for allowances.
type AllowanceHandler interface {

	// HanldeAccount handles a users request for their own allowance account
	HandleAccount(w http.ResponseWriter, r *http.Request)

	// HandleAllowances handles the requests against the /allowances/slug... endpoint
	HandleAllowances(w http.ResponseWriter, r *http.Request)
}

// NewAllowanceHandler returns a pointer to the concrete implementation of the AllowanceHandler interface.
func NewAllowanceHandler(
	ux uxsession.Service,
	p provider.S2sTokenProvider,
	iam *connect.S2sCaller,
	task *connect.S2sCaller,
) AllowanceHandler {

	return &allowanceHandler{
		session:  ux,
		provider: p,
		iam:      iam,
		task:     task,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowanceHandler = (*allowanceHandler)(nil)

// allowanceHandler is the concrete implementation of the AllowanceHandler interface.
type allowanceHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	iam      *connect.S2sCaller
	task     *connect.S2sCaller

	logger *slog.Logger
}

// HanldeAccount handles a users request for their own allowance account
// when requested from /allowance endpoint.
func (h *allowanceHandler) HandleAccount(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	switch r.Method {
	case http.MethodGet:
		h.handleGetAccount(w, r, tel, log)
		return
	case http.MethodPut:
		h.handleUpdateAccount(w, r, tel, log)
		return
	default:
		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAccount handles the GET request to get a users allowance account when requested from /allowance endpoint.
func (h *allowanceHandler) handleGetAccount(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to get access token from session token for /account", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	svcToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// forward request to allowance account service
	allowance, err := connect.GetServiceData[tasks.Allowance](
		ctx,
		h.task,
		"/account",
		svcToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get allowance account from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info("successfully retrieved allowance account for user", "username", allowance.Username)

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error("failed to encode allowance data to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdateAccount handles the PUT request to update a users allowance account when requested from /allowance endpoint.
func (h *allowanceHandler) handleUpdateAccount(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exhange session token for access token for /account update", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd tasks.UpdateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in /account request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("error validating request body for /account update", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token for /account update", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare for upstream submission
	cmd.Csrf = ""

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	svcToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// forward request to allowance account service
	allowance, err := connect.PostToService[tasks.UpdateAllowanceCmd, tasks.Allowance](
		ctx,
		h.task,
		"/account",
		svcToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to update allowance account from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info("successfully updated allowance account for user", "username", allowance.Username)

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error("failed to encode updated allowance account data to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleAllowances is the concrete implementation of the interface
// function that handles the requests to get all or create a new allowance account(s).
func (h *allowanceHandler) HandleAllowances(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	switch r.Method {
	case http.MethodGet:
		// check for a slug -> get all vs get one
		// get slug if it exists
		slug := r.PathValue("slug")
		if slug == "" {

			h.handleGetAll(w, r, tel, log)
			return
		} else {
			h.handleGetAllowance(w, r, tel, log)
			return
		}
	case http.MethodPost:
		h.handleCreate(w, r, tel, log)
		return
	case http.MethodPut:
		h.handleUpdateAllowance(w, r, tel, log)
		return
	default:
		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return

	}
}

// handleGetAll handles the GET request to get all allowance accounts when requested from /allowances endpoint.
func (h *allowanceHandler) handleGetAll(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token for /allowances", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// forward request to allowance account service
	allowances, err := connect.GetServiceData[[]tasks.Allowance](
		ctx,
		h.task,
		"/allowances",
		taskToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get all allowance accounts from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d allowance accounts", len(allowances)))

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(allowances); err != nil {
		log.Error("failed to encode allowance accounts to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode allowance accounts",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAllowance handles the GET request to get a specific allowance account when requested from /allowances/{slug} endpoint.
func (h *allowanceHandler) handleGetAllowance(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token for /allowances", "err", err.Error())
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

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// forward request to allowance account service
	allowance, err := connect.GetServiceData[tasks.Allowance](
		ctx,
		h.task,
		fmt.Sprintf("/allowances/%s", slug),
		taskToken,
		accessToken,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get allowance account for slug %s from tasks service", slug), "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved allowance account for slug %s", slug))

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error("failed to encode allowance account to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleCreate handles the POST request to create a new allowance account when posted to /allowances endpoint.
func (h *allowanceHandler) handleCreate(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token for /allowances", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var cmd CreateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in /allowances request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json in request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate request body for /allowances create cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token for /allowances create cmd", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare for upstream submission
	cmd.Csrf = ""

	// post request to allowance service
	allowance, err := connect.PostToService[CreateAllowanceCmd, tasks.Allowance](
		ctx,
		h.task,
		"/allowances",
		taskToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to create allowance account from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully created allowance account for user %s", allowance.Username))

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error("failed to encode json response for created allowance account", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdateAllowance handles the PUT request to update an existing allowance account when posted to /allowances/{slug} endpoint.
func (h *allowanceHandler) handleUpdateAllowance(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token for /allowances", "err", err.Error())
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

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var cmd tasks.UpdateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in /allowances/{slug} request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode json in request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate request body for /allowances/{slug} update cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token for /allowances/{slug} update cmd", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare for upstream submission
	cmd.Csrf = ""

	// forward request to allowance account service
	allowance, err := connect.PostToService[tasks.UpdateAllowanceCmd, tasks.Allowance](
		ctx,
		h.task,
		fmt.Sprintf("/allowances/%s", slug),
		taskToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update allowance account for slug %s from tasks service", slug), "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated allowance account for slug %s", slug))

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error("failed to encode json response for updated allowance account", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}
