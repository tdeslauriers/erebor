package tasks

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// TaskHandler is an interface that defines the methods for handling tasks.
type TaskHandler interface {

	// HandleTasks handles requests to the /tasks endpoint, including validating query parameters, etc.
	HandleTasks(w http.ResponseWriter, r *http.Request)
}

// NewTaskHandler creates a new TaskHandler instance, returning a concrete implementation of the interface.
func NewTaskHandler(ux uxsession.Service, p provider.S2sTokenProvider, task connect.S2sCaller) TaskHandler {
	return &taskHandler{
		ux:   ux,
		tkn:  p,
		task: task,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTasks)),
	}
}

var _ TaskHandler = (*taskHandler)(nil)

type taskHandler struct {
	ux   uxsession.Service
	tkn  provider.S2sTokenProvider
	task connect.S2sCaller

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
		h.logger.Error("only GET requests are allowed to /tasks endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetTasks handles GET requests to the /tasks endpoint, including validating query parameters, etc.
// validates request parameters, including the CSRF token and session, and then forwards
// the request to the task service.
func (h *taskHandler) handleGetTasks(w http.ResponseWriter, r *http.Request) {

	// get session token from request headers
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on /tasks request: %v", err))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// check for query params and validate them if they exist
	params := r.URL.Query()
	if len(params) > 0 {
		if err := tasks.ValidateQueryParams(params); err != nil {
			h.logger.Error(fmt.Sprintf("invalid query parameters on /tasks request: %v", err))
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
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for GET /tasks: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get service token
	s2sToken, err := h.tkn.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service for GET /tasks: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var tasks []tasks.Task
	if err := h.task.GetServiceData(buildTasksUrl("/tasks", params), s2sToken, accessToken, &tasks); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get tasks from tasks service for GET /tasks: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

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

	// get session token from request headers
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on PATCH /tasks request: %v", err))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for PATCH /tasks: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get request body
	var cmd tasks.TaskStatusCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode request body for PATCH /tasks: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request cmd
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid request cmd for PATCH /tasks: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid csrf token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	// get service token
	s2sToken, err := h.tkn.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service for PATCH /tasks: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var task tasks.Task
	if err := h.task.PostToService("/tasks", s2sToken, accessToken, cmd, &task); err != nil {
		h.logger.Error(fmt.Sprintf("failed to post to PATCH /tasks: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	fmt.Printf("task: %+v\n", task)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(task); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode tasks response for PATCH /tasks: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
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
