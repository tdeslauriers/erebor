package tasks

import (
	"context"
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/tdeslauriers/apprentice/pkg/api/tasks"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// TaskHandler is an interface that defines the methods for handling tasks.
type TaskHandler interface {

	// HandleTasks handles requests to the /tasks endpoint, including validating query parameters, etc.
	HandleTasks(w http.ResponseWriter, r *http.Request)
}

// NewTaskHandler creates a new TaskHandler instance, returning a concrete implementation of the interface.
func NewTaskHandler(ux uxsession.Service, p provider.S2sTokenProvider, task *connect.S2sCaller) TaskHandler {
	return &taskHandler{
		ux:   ux,
		tkn:  p,
		task: task,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTasks)),
	}
}

var _ TaskHandler = (*taskHandler)(nil)

type taskHandler struct {
	ux   uxsession.Service
	tkn  provider.S2sTokenProvider
	task *connect.S2sCaller

	logger *slog.Logger
}

// HandleTasks is a concrete implementation of the Task Handler method,
// handling requests to the /tasks endpoint, including validating query parameters, etc.
// Includes GET and POST for queries and new tasks respectively.
func (h *taskHandler) HandleTasks(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetTasks(w, r)
		return
	case http.MethodPatch:
		h.handlePatchTasks(w, r)
	default:
		// generate telemetry
		tel := connect.NewTelemetry(r, h.logger)
		log := h.logger.With(tel.TelemetryFields()...)

		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetTasks handles GET requests to the /tasks endpoint, including validating query parameters, etc.
// validates request parameters, including the CSRF token and session, and then forwards
// the request to the task service.
func (h *taskHandler) handleGetTasks(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request headers
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error(fmt.Sprintf("invalid session token on GET /tasks request: %v", err))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// check for query params and validate them if they exist
	params := r.URL.Query()
	if len(params) > 0 {
		if err := tasks.ValidateQueryParams(params); err != nil {
			log.Error("invalid query parameters for GET /tasks request", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusBadRequest,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get service token
	s2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call the tasks service for tasks data
	tasks, err := connect.GetServiceData[[]tasks.Task](
		ctx,
		h.task,
		buildTasksUrl("/tasks", params),
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get tasks from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d tasks from tasks service", len(tasks)))

	// send the tasks back to the client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tasks); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode tasks response for GET /tasks: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePatchTasks handles PATCH requests to the /tasks endpoint
// validates request cmd, including the CSRF token and session, and then forwards
// the request to the task service.
func (h *taskHandler) handlePatchTasks(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request headers
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get request body
	var cmd tasks.TaskStatusCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode JSON in request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode JSON in request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request cmd
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate task status update command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid CSRF token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	// get service token
	s2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call the tasks service to update the task status
	task, err := connect.PatchToService[tasks.TaskStatusCmd, tasks.Task](
		ctx,
		h.task,
		"/tasks",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to update task status in tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated task %s status", task.TaskSlug))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(task); err != nil {
		log.Error("failed to encode task response for PATCH /tasks", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode task response to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// buildTasksUrl is a helper function that builds a request to the tasks service
// /tasks endpoint including query parameters.
func buildTasksUrl(url string, params url.Values) string {

	var sb strings.Builder
	sb.WriteString(url)

	if len(params) > 0 {
		sb.WriteString("?")
		sb.WriteString(params.Encode())
	}

	return sb.String()
}
