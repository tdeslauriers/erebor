package tasks

import (
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

// TemplateHandler is an interface that handles template related requests.
type TemplateHandler interface {

	// HandleGetAssignees is a method that handles the request to get (all possible) assignees,
	// eg. for listing users in a menu, etc.
	HandleGetAssignees(w http.ResponseWriter, r *http.Request)

	// HandleTemplates is a method that handles requests to the templates endpoint.
	HandleTemplates(w http.ResponseWriter, r *http.Request)

	// HandleTemplate is a method that handles requests to the template/slug endpoint.
	HandleTemplate(w http.ResponseWriter, r *http.Request)
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

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /templates/assignees endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed to /templates/assignees endpoint",
		}
		e.SendJsonErr(w)
		return
	}

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("session token for /templates/assignees request is invalid: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
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
	var assignees []tasks.Assignee
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
		h.getTemplates(w, r)
		return
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

// HandleTemplate is the concrete implementation of the interface method that handles requests to the template/slug endpoint.
func (h *templateHandler) HandleTemplate(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		h.getTemplate(w, r)
		return
	case "PUT":
		h.updateTemplate(w, r)
		return
	case "DELETE":
		// h.deleteTemplate(w, r)
		// return
	default:
		h.logger.Error("only GET, PUT, and DELETE requests are allowed to /templates/{slug} endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET, PUT, and DELETE requests are allowed to /templates/{slug} endpoint",
		}
		e.SendJsonErr(w)
	}
}

// getTemplates is a concrete implementation of the interface method that handles the request to get templates.
func (h *templateHandler) getTemplates(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on /templates get request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
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

	// get templates from the tasks service
	var templates []tasks.Template
	if err := h.task.GetServiceData("/templates", taskToken, accessToken, &templates); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get templates: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// send response to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(templates); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode templates: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error: gateway failed to json encode templates",
		}
		e.SendJsonErr(w)
		return
	}
}

// createTemplate is a method that handles the request to create a new template.
func (h *templateHandler) createTemplate(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on /templates post request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
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
	if err := h.task.PostToService("/templates", taskToken, accessToken, cmd, &template); err != nil {
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

// getTemplate is a method that handles the request to get a template.
func (h *templateHandler) getTemplate(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
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

	// get the template slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid template slug: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid template slug",
		}
		e.SendJsonErr(w)
		return
	}

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

	// get template from the tasks service
	var template tasks.Template
	if err := h.task.GetServiceData(fmt.Sprintf("/templates/%s", slug), taskToken, accessToken, &template); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get template: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// send response to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(template); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode template: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error: gateway failed to json encode template record",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateTemplate is a method that handles the request to update a template.
func (h *templateHandler) updateTemplate(w http.ResponseWriter, r *http.Request) {

	fmt.Println("UPDATEING")

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
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

	// get the template slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid template slug: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid template slug",
		}
		e.SendJsonErr(w)
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
		errMsg := fmt.Sprintf("invalid template update command object: %s", err.Error())
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

	// update template in the tasks service
	var template tasks.Template
	if err := h.task.PostToService(fmt.Sprintf("/templates/%s", slug), taskToken, accessToken, cmd, &template); err != nil {
		h.logger.Error(fmt.Sprintf("failed to put template: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("template successfully updated: %s", template.Slug))

	// send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
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
