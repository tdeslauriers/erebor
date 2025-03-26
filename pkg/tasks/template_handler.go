package tasks

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"

	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// TemplateHandler is an interface that handles template related requests.
type TemplateHandler interface {

	// HandleGetAssignees is a method that handles the request to get (all possible) assignees,
	// eg. for listing users in a menu, etc.
	HandleGetAssignees(w http.ResponseWriter, r *http.Request)

	// HandleTemplates is a method that handles requests to the templates endpoint.
	HandleTemplates(w http.ResponseWriter, r *http.Request)
}

// NewTemplateHandler is a function that returns a new TemplateHandler interface with underlying implementation.
func NewTemplateHandler(ux uxsession.Service, p provider.S2sTokenProvider, task connect.S2sCaller) TemplateHandler {
	return &templateHandler{
		ux:   ux,
		tkn:  p,
		task: task,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTemplate)),
	}
}

var _ TemplateHandler = (*templateHandler)(nil)

// templateHandler is a struct that implements the TemplateHandler interface.
type templateHandler struct {
	ux   uxsession.Service
	tkn  provider.S2sTokenProvider
	task connect.S2sCaller

	logger *slog.Logger
}

// HandleGetAssignees is a method that handles the request to get assignees.
func (h *templateHandler) HandleGetAssignees(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token found in authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session cookie found in request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight validation of session token
	if len(session) < 16 || len(session) > 64 {
		h.logger.Error("invalid session token provided in get /users/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session token provided",
		}
		e.SendJsonErr(w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.tkn.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// get assignees
	var assignees []profile.User
	if err := h.task.GetServiceData("/templates/assignees", taskToken, accessToken, &assignees); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get assignees: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(assignees); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode allowance assignees: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleTemplates is the concrete implementation of the interface  method that handles requests to the templates endpoint.
func (h *templateHandler) HandleTemplates(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
	// h.getTemplates(w, r)
	// return
	case "POST":
		h.createTemplate(w, r)
		return
	default:
		h.logger.Error("only GET and POST requests are allowed to /templates endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET and POST requests are allowed to /templates endpoint",
		}
		e.SendJsonErr(w)
	}
}

// TODO: implement getTemplates

// createTemplate is a method that handles the request to create a new template.
func (h *templateHandler) createTemplate(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token found in authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session cookie found in request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight validation of session token
	if len(session) < 16 || len(session) > 64 {
		h.logger.Error("invalid session token provided in post /templates request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session token provided",
		}
		e.SendJsonErr(w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd tasks.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json in template request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("invalid template request: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
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
	taskToken, err := h.tkn.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// post template to the tasks service
	var template tasks.Template
	if err := h.task.PostToService("/templates", taskToken, accessToken, cmd, template); err != nil {
		h.logger.Error(fmt.Sprintf("failed to post template: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("template successfully created: %s", template.Slug))

	// send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(template); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode template: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
