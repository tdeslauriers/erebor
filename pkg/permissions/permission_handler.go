package permissions

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Handler is an interface that defines methods for handling permissions-related endpoint requests.
type Handler interface {

	// HandlePermissions is a method that handles requests against the /permissions endpoint.
	HandlePermissions(w http.ResponseWriter, r *http.Request)

	// HandlePermission is a method that handles requests against the /permissions/{slug} endpoint.
	HandlePermission(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new instance of a permissions handler interface
// returning an underlying concrete implementation.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, t, g connect.S2sCaller) Handler {
	return &handler{
		session: ux,
		token:   p,
		tasks:   t,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.ComponentKey, util.ComponentPermissions)).
			With(slog.String(util.PackageKey, util.PackagePermissions)),
	}
}

var _ Handler = (*handler)(nil)

// handler is a concrete implementation of the Handler interface.
type handler struct {
	session uxsession.Service
	token   provider.S2sTokenProvider
	tasks   connect.S2sCaller
	gallery connect.S2sCaller

	logger *slog.Logger
}

// HandlePermissions is the concret implementation of the a method
// that handles requests against the /permissions endpoint.
func (h *handler) HandlePermissions(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.getAllPermissions(w, r)
		return
	case http.MethodPost:
		h.createPermission(w, r)
		return
	default:
		h.logger.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// HandlePermission is the concret implementation of the a method
// that handles requests against the /permissions/{slug} endpoint.
func (h *handler) HandlePermission(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.getPermissionBySlug(w, r)
		return
	case http.MethodPut:
		h.updatePermission(w, r)
	default:
		h.logger.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// getAllPermissions is a helper method which  handles the GET request to the /permissions endpoint,
// retrieving and collating/combining all permissions records from
// all down stream services that use them.
func (h *handler) getAllPermissions(w http.ResponseWriter, r *http.Request) {

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token: %v", err))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the user access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token provided: %v", err))
		h.session.HandleSessionErr(err, w)
		return
	}

	// call down stream services to get permissions
	var (
		wg           sync.WaitGroup
		permissionCh = make(chan []permissions.Permission, 2)
		errCh        = make(chan error, 2)
	)

	wg.Add(2)
	go h.getServicePermissions(util.ServiceTasks, accessToken, h.tasks, permissionCh, errCh, &wg)
	go h.getServicePermissions(util.ServiceGallery, accessToken, h.gallery, permissionCh, errCh, &wg)

	wg.Wait()
	close(permissionCh)
	close(errCh)

	// check for errors
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		e := errors.Join(errs...)
		h.logger.Error(fmt.Sprintf("failed to get permissions from downstream services: %v", e))
		errRes := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to get permissions from downstream services: %v", e),
		}
		errRes.SendJsonErr(w)
		return
	}

	// collect all permissions from the channels
	var all []permissions.Permission
	for ps := range permissionCh {
		all = append(all, ps...)
	}

	// send the permissions as a JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(all); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permissions to JSON: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode permissions to JSON: %v", err),
		}
		e.SendJsonErr(w)
		return
	}
}

// getServicePermissions is a helper method retrieves permissions from a specific service
// based on the service name provided.
func (h *handler) getServicePermissions(service string, accessToken string, svc connect.S2sCaller, pmCh chan<- []permissions.Permission, errCh chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	// get service token
	serviceToken, err := h.token.GetServiceToken(service)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to fetch service token for %s: %v", service, err))
		errCh <- err
		return
	}

	// get permissions from the service
	var ps []permissions.Permission
	if err := svc.GetServiceData("/permissions", serviceToken, accessToken, &ps); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get permissions from %s: %v", service, err))
		errCh <- err
		return
	}

	h.logger.Info(fmt.Sprintf("successfully retrieved %d permissions from %s", len(ps), service))
	pmCh <- ps
}

// getPermisionBySlug is a helper method that handles the GET request to the /permissions/{slug} endpoint,
// retrieving a specific permission record by its slug from the downstream services.
func (h *handler) getPermissionBySlug(w http.ResponseWriter, r *http.Request) {

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the user access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// parse the path and slug from the request URL
	// trim the prefix
	path := strings.TrimPrefix(r.URL.Path, "/permissions/")
	parts := strings.SplitN(path, "/", 2)

	// there should only be service and slug in the path
	if len(parts) != 2 {
		h.logger.Error("invalid path in permission/{service}/{slug} in request URL")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid path in permission/{service}/{slug} in request URL",
		}
		e.SendJsonErr(w)
		return
	}

	// determine which service to send the permission to
	service, err := selectService(parts[0])
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to select service for permission: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to select service for permission: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	slug := parts[1]
	if valid := validate.IsValidUuid(slug); !valid {
		h.logger.Error(fmt.Sprintf("invalid permission slug: %s", slug))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid permission slug: %s", slug),
		}
		e.SendJsonErr(w)
		return
	}

	// get the service token for the selected service
	s2sToken, err := h.token.GetServiceToken(service)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	var p permissions.Permission
	switch service {
	case util.ServiceTasks:
		if err := h.tasks.GetServiceData(fmt.Sprintf("/permissions/%s", slug), s2sToken, accessToken, &p); err != nil {
			h.logger.Error(fmt.Sprintf("failed to get permission from tasks service: %s", err.Error()))
			h.tasks.RespondUpstreamError(err, w)
			return
		}
	case util.ServiceGallery:
		if err := h.gallery.GetServiceData(fmt.Sprintf("/permissions/%s", slug), s2sToken, accessToken, &p); err != nil {
			h.logger.Error(fmt.Sprintf("failed to get permission from gallery service: %s", err.Error()))
			h.gallery.RespondUpstreamError(err, w)
			return
		}
	default:
		h.logger.Error(fmt.Sprintf("unsupported service %s for permission retrieval", service))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("unsupported service %s for permission retrieval", service),
		}
		e.SendJsonErr(w)
		return
	}

	h.logger.Info(fmt.Sprintf("successfully retrieved permission %s for service %s", p.Name, service))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(p); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permission to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode permission to JSON: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}
}

// createPermission is a helper method that handles the POST request to the /permissions endpoint,
// creating a new permission record in the downstream services.
func (h *handler) createPermission(w http.ResponseWriter, r *http.Request) {

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from add-permission request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the user access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the request body
	var cmd permissions.Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode request body to permission command: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("failed to decode request body to permission command: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the command
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate permission command: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to validate permission command: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid session or csrf token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command -> not needed upstream
	cmd.Csrf = ""

	// determine which service to send the permission to
	service, err := selectService(cmd.ServiceName)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to select service for permission: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to select service for permission: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// get service token for the selected service
	s2sToken, err := h.token.GetServiceToken(service)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// post to applicable service
	var p permissions.Permission
	switch service {
	case util.ServiceTasks:
		if err := h.tasks.PostToService("/permissions", s2sToken, accessToken, cmd, &p); err != nil {
			h.logger.Error(fmt.Sprintf("failed to post permission to tasks service: %s", err.Error()))
			h.tasks.RespondUpstreamError(err, w)
			return
		}
	case util.ServiceGallery:
		if err := h.gallery.PostToService("/permissions", s2sToken, accessToken, cmd, &p); err != nil {
			h.logger.Error(fmt.Sprintf("failed to post permission to gallery service: %s", err.Error()))
			h.tasks.RespondUpstreamError(err, w)
			return
		}
	default:
		h.logger.Error(fmt.Sprintf("unsupported service %s for permission creation", service))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("unsupported service %s for permission creation", service),
		}
		e.SendJsonErr(w)
		return
	}

	h.logger.Info(fmt.Sprintf("successfully created permission %s for service %s", p.Name, service))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permission to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode permission to JSON: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}
}

// updatePermission is a helper method that handles the PUT request to the /permissions/{slug} endpoint,
// updating an existing permission record in the downstream services.
func (h *handler) updatePermission(w http.ResponseWriter, r *http.Request) {

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for /scope/slug call to s2s service: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// parse the path and slug from the request URL
	// trim the prefix
	path := strings.TrimPrefix(r.URL.Path, "/permissions/")
	parts := strings.SplitN(path, "/", 2)

	// there should only be service and slug in the path
	if len(parts) != 2 {
		h.logger.Error("invalid path in permission/{service}/{slug} in request URL")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid path in permission/{service}/{slug} in request URL",
		}
		e.SendJsonErr(w)
		return
	}

	// determine which service to send the permission to
	service, err := selectService(parts[0])
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to select service for permission: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to select service for permission: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	slug := parts[1]
	if valid := validate.IsValidUuid(slug); !valid {
		h.logger.Error(fmt.Sprintf("invalid permission slug: %s", slug))
		e := connect.ErrorHttp{
			
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid permission slug: %s", slug),
		}
		e.SendJsonErr(w)
		return
	}

	// parse the request body to get the updated permission data
	var cmd permissions.Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode request body to permission command: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to decode request body to permission command: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the command
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate permission command: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to validate permission command: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid session or csrf token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command -> not needed upstream
	cmd.Csrf = ""

	// check url path service matches command service
	// this is a redundant check since it will be dropped, but it would suggest
	// tampering with the request if the service in the URL does not match the command
	if cmd.ServiceName != service {
		h.logger.Error(fmt.Sprintf("service in URL %s does not match service in update command %s", service, cmd.ServiceName))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("service in URL %s does not match service in update command %s", service, cmd.ServiceName),
		}
		e.SendJsonErr(w)
		return
	}

	// get the service token for the selected service
	s2sToken, err := h.token.GetServiceToken(service)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	var p permissions.Permission
	switch service {
	case util.ServiceTasks:
		if err := h.tasks.PostToService(fmt.Sprintf("/permissions/%s", slug), s2sToken, accessToken, cmd, &p); err != nil {
			h.logger.Error(fmt.Sprintf("failed to update permission in tasks service: %s", err.Error()))
			h.tasks.RespondUpstreamError(err, w)
			return
		}
	case util.ServiceGallery:
		if err := h.gallery.PostToService(fmt.Sprintf("/permissions/%s", slug), s2sToken, accessToken, cmd, &p); err != nil {
			h.logger.Error(fmt.Sprintf("failed to update permission in gallery service: %s", err.Error()))
			h.gallery.RespondUpstreamError(err, w)
			return
		}
	default:
		h.logger.Error(fmt.Sprintf("unsupported service %s for permission update", service))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("unsupported service %s for permission update", service),
		}
		e.SendJsonErr(w)
		return
	}

	h.logger.Info(fmt.Sprintf("successfully updated permission %s for service %s", p.Name, service))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(p); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permission to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode permission to JSON: %s", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}
}
