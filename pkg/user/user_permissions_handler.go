package user

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"erebor/pkg/permissions"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// PermissionsHandler defines the interface for handling user permissions requests.
type PermissionsHandler interface {
	// HandlePermissions handles a request from the client by submitting it against the user permissions service.
	HandlePermissions(w http.ResponseWriter, r *http.Request)
}

// NewPermissionsHandler returns a pointer to the concrete implementation of the PermissionsHandler interface.
func NewPermissionsHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam, task, g connect.S2sCaller) PermissionsHandler {
	return &permissionsHandler{
		session:  ux,
		provider: p,
		identity: iam,
		tasks:    task,
		gallery:  g,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUserPermissions)).
			With(slog.String(util.SerivceKey, util.ServiceGateway)),
	}
}

var _ PermissionsHandler = (*permissionsHandler)(nil)

// permissionsHandler is the concrete implementation of the PermissionsHandler interface.
type permissionsHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity connect.S2sCaller
	tasks    connect.S2sCaller
	gallery  connect.S2sCaller

	logger *slog.Logger
}

// HandlePermissions is the concrete implementation of the interface function that handles a request from the client by submitting it against the user permissions service.
func (h *permissionsHandler) HandlePermissions(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	// case http.MethodGet:

	// 	return
	case http.MethodPut:
		h.updateUserPermissions(w, r)
		return
	default:
		h.logger.Error("unsupported method for /user/permissions endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "unsupported method for /user/permissions endpoint",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateUserPermissions is a helper method which handles the request to update user permissions.
func (h *permissionsHandler) updateUserPermissions(w http.ResponseWriter, r *http.Request) {

	// get session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to get session token", slog.String("error", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token", slog.String("error", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body into a permissions command
	var cmd permissions.UpdatePermissionsCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := "failed to decode json in user permissions request body: " + err.Error()
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		errMsg := "invalid user permissions request: " + err.Error()
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

	// fetch the user name from iam service
	// downstream services need the user name to update permissions
	s2sIamTkn, err := h.provider.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		errMsg := fmt.Sprintf("failed to get s2s token for identity service: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user permissions request failed: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var user profile.User
	if err := h.identity.GetServiceData(fmt.Sprintf("/s2s/users/%s", cmd.EntitySlug), s2sIamTkn, "", &user); err != nil {
		errMsg := fmt.Sprintf("failed to get user data from identity service: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
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

	// wg.Add(1)
	// go func(eChan chan error, wg *sync.WaitGroup) {
	// 	defer wg.Done()

	// 	galleryCmd := exo.UpdatePermissionsCmd{
	// 		Entity:      user.Username,
	// 		Permissions: galleryPermissions,
	// 	}

	// 	// get service token for gallery service
	// 	galleryToken, err := h.provider.GetServiceToken(util.ServiceGallery)
	// 	if err != nil {
	// 		eChan <- fmt.Errorf("failed to get service token for gallery service: %s", err.Error())
	// 		return
	// 	}

	// 	// make request to the gallery service
	// 	if err := h.gallery.PostToService("/patrons/permissions", galleryToken, accessToken, galleryCmd, nil); err != nil {
	// 		eChan <- fmt.Errorf("failed to update gallery permissions: %s", err.Error())
	// 		return
	// 	}
	// }(errCh, &wg)

	wg.Add(1)
	go func(eChan chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		tasksCmd := exo.UpdatePermissionsCmd{
			Entity:      user.Username,
			Permissions: tasksPermissions,
		}

		// get service token for tasks service
		tasksToken, err := h.provider.GetServiceToken(util.ServiceTasks)
		if err != nil {
			eChan <- fmt.Errorf("failed to get service token for tasks service: %s", err.Error())
			return
		}

		// make request to the tasks service
		if err := h.tasks.PostToService("/allowances/permissions", tasksToken, accessToken, tasksCmd, nil); err != nil {
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
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// no response is expected from the identity service --> 204 No Content
	h.logger.Info(fmt.Sprintf("user permissions updated for user %s", user.Username))
	w.WriteHeader(http.StatusNoContent)
}
