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
)

// TemplateHandler is an interface that handles template related requests.
type TemplateHandler interface {
	HandleGetAssignees(w http.ResponseWriter, r *http.Request)
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
		h.logger.Error(err.Error())
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
