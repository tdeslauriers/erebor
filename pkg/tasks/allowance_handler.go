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

	switch r.Method {
	// case http:MethodGet:
	// 	h.handleGet(w, r)
	// return
	case http.MethodPost:
		h.handlePost(w, r)
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

// handlePost handles the POST request to create a new allowance account when posted to /allowances endpoint.
func (h *allowanceHandler) handlePost(w http.ResponseWriter, r *http.Request) {

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
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

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

	// forward request to allowance account service
	// allowance service will validate user is real, authorized, and not already have an allowance account
	taskToken, err := h.provider.GetServiceToken(util.ServiceTasks)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for tasks service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to create %s's allowance account to due to internal server error", cmd.Username),
		}
		e.SendJsonErr(w)
		return
	}

	// prepare for upstream submission
	cmd.Csrf = ""

	var allowance tasks.Allowance
	if err := h.task.PostToService("/allowances", taskToken, accessToken, cmd, allowance); err != nil {
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
