package user

import (
	"context"
	"encoding/json"
	"erebor/internal/authentication/uxsession"
	"erebor/internal/permissions"
	"erebor/internal/util"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/shaw/pkg/api/user"
)

// PermissionsHandler defines the interface for handling user permissions requests.
type PermissionsHandler interface {
	// HandlePermissions handles a request from the client by submitting it against the user permissions service.
	HandlePermissions(w http.ResponseWriter, r *http.Request)
}

// NewPermissionsHandler returns a pointer to the concrete implementation of the PermissionsHandler interface.
func NewPermissionsHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam, task, g *connect.S2sCaller) PermissionsHandler {
	return &permissionsHandler{
		session:  ux,
		provider: p,
		identity: iam,
		tasks:    task,
		gallery:  g,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUserPermissions)),
	}
}

var _ PermissionsHandler = (*permissionsHandler)(nil)

// permissionsHandler is the concrete implementation of the PermissionsHandler interface.
type permissionsHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity *connect.S2sCaller
	tasks    *connect.S2sCaller
	gallery  *connect.S2sCaller

	logger *slog.Logger
}

// HandlePermissions is the concrete implementation of the interface function that handles a request from the client by submitting it against the user permissions service.
func (h *permissionsHandler) HandlePermissions(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodPut:
		h.updateUserPermissions(w, r)
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

// updateUserPermissions is a helper method which handles the request to update user permissions.
func (h *permissionsHandler) updateUserPermissions(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token", slog.String("err", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to get access token from session token", slog.String("err", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body into a permissions command
	var cmd permissions.UpdatePermissionsCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in user permissions update command request body", slog.String("err", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		log.Error("invalid user permissions update command request body", slog.String("err", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token in user permissions update command request body", slog.String("err", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// fetch the user name from iam service
	// downstream services need the user name to update permissions
	s2sIamTkn, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get service token for identity service", slog.String("err", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// get u data from identity service to get the username
	u, err := connect.GetServiceData[user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/s2s/users/%s", cmd.EntitySlug),
		s2sIamTkn,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get user data from identity service", slog.String("err", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// divide up permssions into lists for their respective services: pixie, apprentice, etc...
	// Note: upstream services will validate whether the submitted permissions are valid -> actually exist
	var galleryPermissions []string
	var tasksPermissions []string
	for _, perm := range cmd.ServicePermissions {

		switch perm.ServiceName {
		case util.ServiceGallery:
			galleryPermissions = append(galleryPermissions, perm.PermissionSlug)
		case util.ServiceTasks:
			tasksPermissions = append(tasksPermissions, perm.PermissionSlug)
		default:
			h.logger.Error(fmt.Sprintf("unknown service name in permissions update: %s", perm.ServiceName))
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnprocessableEntity,
				Message:    fmt.Sprintf("unknown service name in permissions update: %s", perm.ServiceName),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// build each service's permissions command
	// and prepare request resources
	// NOTE: no length check because an empty permissions slice => remove all permissions
	var (
		wg    sync.WaitGroup
		errCh = make(chan error, 2) // buffered channel to collect errors
	)

	wg.Add(1)
	go func(eChan chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		galleryCmd := exo.UpdatePermissionsCmd{
			Entity:      u.Username,
			Permissions: galleryPermissions,
		}

		// get service token for gallery service
		galleryToken, err := h.provider.GetServiceToken(ctx, util.ServiceGallery)
		if err != nil {
			eChan <- fmt.Errorf("failed to get service token for gallery service: %s", err.Error())
			return
		}

		// make request to the gallery service
		_, err = connect.PutToService[exo.UpdatePermissionsCmd, struct{}](
			ctx,
			h.gallery,
			"/patrons/permissions",
			galleryToken,
			accessToken,
			galleryCmd,
		)
		if err != nil {
			eChan <- fmt.Errorf("failed to update gallery permissions: %s", err.Error())
			return
		}
	}(errCh, &wg)

	wg.Add(1)
	go func(eChan chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		tasksCmd := exo.UpdatePermissionsCmd{
			Entity:      u.Username,
			Permissions: tasksPermissions,
		}

		// get service token for tasks service
		tasksToken, err := h.provider.GetServiceToken(ctx, util.ServiceTasks)
		if err != nil {
			eChan <- fmt.Errorf("failed to get service token for tasks service: %s", err.Error())
			return
		}

		// make request to the tasks service
		_, err = connect.PutToService[exo.UpdatePermissionsCmd, struct{}](
			ctx,
			h.tasks,
			"/allowances/permissions",
			tasksToken,
			accessToken,
			tasksCmd,
		)
		if err != nil {
			eChan <- fmt.Errorf("failed to update tasks permissions: %s", err.Error())
			return
		}
	}(errCh, &wg)

	wg.Wait()
	close(errCh)

	// check for errors from goroutines
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		errMsg := fmt.Sprintf("failed to update permissions: %s", errors.Join(errs...))
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to update permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// no response is expected from the identity service --> 204 No Content
	h.logger.Info(fmt.Sprintf("permissions updated for user %s", u.Slug))
	w.WriteHeader(http.StatusNoContent)
}
