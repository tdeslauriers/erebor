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

// AllowanceHandler is an interface for handling requests for allowances.
type AllowanceHandler interface {
	// HandleAllowances handles the requests to get all or create a new allowance account(s).
	HandleAllowances(w http.ResponseWriter, r *http.Request)

	// HandleAllowance handles the requests to get a specific allowance account.
	HandleAllowance(w http.ResponseWriter, r *http.Request)
}

// NewAllowanceHandler returns a pointer to the concrete implementation of the AllowanceHandler interface.
func NewAllowanceHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam, task connect.S2sCaller) AllowanceHandler {
	return &allowanceHandler{
		session:  ux,
		provider: p,
		iam:      iam,
		task:     task,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowanceHandler = (*allowanceHandler)(nil)

// allowanceHandler is the concrete implementation of the AllowanceHandler interface.
type allowanceHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	iam      connect.S2sCaller
	task     connect.S2sCaller

	logger *slog.Logger
}

// HandleAllowances is the concrete implementation of the interface
// function that handles the requests to get all or create a new allowance account(s).
func (h *allowanceHandler) HandleAllowances(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.provider.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetAll(w, r, taskToken, accessToken)
		return
	case http.MethodPost:
		h.handleCreate(w, r, session, taskToken, accessToken)
		return
	default:
		h.logger.Error("only GET and POST requests are allowed to /allowances endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET and POST requests are allowed to /allowances endpoint",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleAllowance is the concrete implementation of the interface
// function that handles the requests to get a specific allowance account.
func (h *allowanceHandler) HandleAllowance(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for /allowance/{slug}: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid slug",
		}
		e.SendJsonErr(w)
		return
	}

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	svcToken, err := h.provider.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get allowance account due to internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// handle the request based on the http method
	switch r.Method {
	case http.MethodGet:
		h.handleGetAllowance(w, slug, svcToken, accessToken)
		return
	case http.MethodPut:
		h.handleUpdateAllowance(w, r, slug, session, svcToken, accessToken)
		return
	default:
		h.logger.Error("only GET requests are allowed to /allowances/{slug} endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed to /allowances/{slug} endpoint",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAll handles the GET request to get all allowance accounts when requested from /allowances endpoint.
func (h *allowanceHandler) handleGetAll(w http.ResponseWriter, r *http.Request, svcToken, accessToken string) {

	// forward request to allowance account service
	var allowances []tasks.Allowance
	if err := h.task.GetServiceData("/allowances", svcToken, accessToken, &allowances); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get all allowance accounts: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(allowances); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode json response for all allowance accounts: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode all allowance accounts",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAllowance handles the GET request to get a specific allowance account when requested from /allowances/{slug} endpoint.
func (h *allowanceHandler) handleGetAllowance(w http.ResponseWriter, slug, svcToken, accessToken string) {

	// forward request to allowance account service
	var allowance tasks.Allowance
	if err := h.task.GetServiceData(fmt.Sprintf("/allowances/%s", slug), svcToken, accessToken, &allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get allowance account: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode json response for allowance/%s account: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleCreate handles the POST request to create a new allowance account when posted to /allowances endpoint.
func (h *allowanceHandler) handleCreate(w http.ResponseWriter, r *http.Request, session, taskToken, accessToken string) {

	// decode the request body
	var cmd CreateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json in /allowances request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("error validating request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid csrf token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare for upstream submission
	cmd.Csrf = ""

	var allowance tasks.Allowance
	if err := h.task.PostToService("/allowances", taskToken, accessToken, cmd, &allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to create %s's allowance account: %s", cmd.Username, err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode json response for %s's allowance account: %s", cmd.Username, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to json encode %s's allowance account to due to internal server error", cmd.Username),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdateAllowance handles the PUT request to update an existing allowance account when posted to /allowances/{slug} endpoint.
func (h *allowanceHandler) handleUpdateAllowance(w http.ResponseWriter, r *http.Request, slug, session, svcToken, accessToken string) {

	// decode the request body
	var cmd tasks.UpdateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json in /allowances/%s request body: %s", slug, err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	fmt.Printf("cmd: %+v\n", cmd)

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("error validating request body: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid csrf token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare for upstream submission
	cmd.Csrf = ""

	// forward request to allowance account service
	var allowance tasks.Allowance
	if err := h.task.PostToService(fmt.Sprintf("/allowances/%s", slug), svcToken, accessToken, cmd, &allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update allowance account: %s", err.Error()))
		h.task.RespondUpstreamError(err, w)
		return
	}

	// respond to client
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode json response for allowance/%s account: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode allowance data to json",
		}
		e.SendJsonErr(w)
		return
	}
}
