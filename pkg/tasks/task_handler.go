package tasks

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
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
		h.handleTasks(w, r)
		return
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

// handleTasks handles GET requests to the /tasks endpoint, including validating query parameters, etc.
// validates request parameters, including the CSRF token and session, and then forwards
// the request to the task service.
func (h *taskHandler) handleTasks(w http.ResponseWriter, r *http.Request) {

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
	if err := h.task.GetServiceData(buildTasksUrl("/tasks", params), accessToken, s2sToken, &tasks); err != nil {
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

// buildTasksUrl is a helper function that builds a request to the tasks service
// /tasks endpoint including query parameters.
func buildTasksUrl(url string, params map[string][]string) string {

	var sb strings.Builder
	sb.WriteString(url)

	if len(params) > 0 {
		sb.WriteString("?")
		counter := 0
		for k, v := range params {
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(strings.Join(v, ","))

			if counter < len(params)-1 {
				sb.WriteString("&")
			}
			counter++
		}
	}

	return sb.String()
}
