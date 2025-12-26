package tasks

import (
	"context"
	"encoding/json"
	"erebor/internal/authentication/uxsession"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/apprentice/pkg/api/templates"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// TemplateHandler is an interface that handles template related requests.
type TemplateHandler interface {

	// HandleTemplates is a method that handles requests to the templates endpoint.
	HandleTemplates(w http.ResponseWriter, r *http.Request)
}

// NewTemplateHandler is a function that returns a new TemplateHandler interface with underlying implementation.
func NewTemplateHandler(ux uxsession.Service, p provider.S2sTokenProvider, task *connect.S2sCaller) TemplateHandler {
	return &templateHandler{
		ux:   ux,
		tkn:  p,
		task: task,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTemplate)),
	}
}

var _ TemplateHandler = (*templateHandler)(nil)

// templateHandler is a struct that implements the TemplateHandler interface.
type templateHandler struct {
	ux   uxsession.Service
	tkn  provider.S2sTokenProvider
	task *connect.S2sCaller

	logger *slog.Logger
}

// HandleTemplates is the concrete implementation of the interface  method that handles requests to the templates endpoint.
func (h *templateHandler) HandleTemplates(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		// check for a slug -> get all vs get one
		// get slug if it exists
		slug := r.PathValue("slug")
		switch slug {
		case "":
			h.getTemplates(w, r)
			return
		case "assignees":
			h.getAssignees(w, r)
			return
		default:
			// this will handle slugs that are not well formed.
			h.getTemplate(w, r)
			return
		}
	case http.MethodPost:
		h.createTemplate(w, r)
		return
	case http.MethodPut:
		h.updateTemplate(w, r)
		return
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

// HandleGetAssignees is a method that handles the request to get assignees.
func (h *templateHandler) getAssignees(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token", "err", err.Error())
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

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// get assignees from the tasks service
	assignees, err := connect.GetServiceData[[]templates.Assignee](
		ctx,
		h.task,
		"/templates/assignees",
		taskToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get assignees from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d assignees from tasks service", len(assignees)))

	// send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(assignees); err != nil {
		log.Error("failed to json encode assignees", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode assignees",
		}
		e.SendJsonErr(w)
		return
	}
}

// getTemplates is a concrete implementation of the interface method that handles the request to get templates.
func (h *templateHandler) getTemplates(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
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

	// get service token
	taskToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// get templates from the tasks service
	templates, err := connect.GetServiceData[[]templates.Template](
		ctx,
		h.task,
		"/templates",
		taskToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get templates from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d templates from tasks service", len(templates)))

	// send response to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(templates); err != nil {
		log.Error("failed to json encode templates", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode templates",
		}
		e.SendJsonErr(w)
		return
	}
}

// createTemplate is a method that handles the request to create a new template.
func (h *templateHandler) createTemplate(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
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

	// decode the request body
	var cmd templates.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in template request body command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to decode json in template request body command",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid template create command object", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	// get service token
	taskToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// post template to the tasks service
	template, err := connect.PostToService[templates.TemplateCmd, templates.Template](
		ctx,
		h.task,
		"/templates/",
		taskToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to post template to tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("template successfully created template %s: %s", template.Slug, template.Name))

	// send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(template); err != nil {
		log.Error("failed to json encode created template", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode created template",
		}
		e.SendJsonErr(w)
		return
	}
}

// getTemplate is a method that handles the request to get a template.
func (h *templateHandler) getTemplate(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
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

	// get the template slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("invalid template slug", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid template slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
	taskToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// get template from the tasks service
	template, err := connect.GetServiceData[templates.Template](
		ctx,
		h.task,
		fmt.Sprintf("/templates/%s", slug),
		taskToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get template from tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved template %s: %s", template.Slug, template.Name))

	// send response to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(template); err != nil {
		log.Error("failed to json encode template", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode template record",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateTemplate is a method that handles the request to update a template.
func (h *templateHandler) updateTemplate(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from the request header
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

	// get the template slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("invalid template slug", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var cmd templates.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in template update request body command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid template update command object", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// csrf token no longer needed, set to empty string
	cmd.Csrf = ""

	// get service token
	taskToken, err := h.tkn.GetServiceToken(ctx, util.ServiceTasks)
	if err != nil {
		log.Error("failed to get service token for tasks service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// update template in the tasks service
	template, err := connect.PutToService[templates.TemplateCmd, templates.Template](
		ctx,
		h.task,
		fmt.Sprintf("/templates/%s", slug),
		taskToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to update template in tasks service", "err", err.Error())
		h.task.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("template successfully updated: %s", template.Slug))

	// send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(template); err != nil {
		log.Error("failed to json encode updated template", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode updated template",
		}
		e.SendJsonErr(w)
		return
	}
}
