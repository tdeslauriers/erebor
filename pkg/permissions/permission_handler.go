package permissions

import (
	"context"
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
}

// NewHandler creates a new instance of a permissions handler interface
// returning an underlying concrete implementation.
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, t, g *connect.S2sCaller) Handler {
	return &handler{
		session: ux,
		token:   p,
		tasks:   t,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentPermissions)).
			With(slog.String(util.PackageKey, util.PackagePermissions)),
	}
}

var _ Handler = (*handler)(nil)

// handler is a concrete implementation of the Handler interface.
type handler struct {
	session uxsession.Service
	token   provider.S2sTokenProvider
	tasks   *connect.S2sCaller
	gallery *connect.S2sCaller

	logger *slog.Logger
}

// HandlePermissions is the concret implementation of the a method
// that handles requests against the /permissions/{slug...} endpoint.
func (h *handler) HandlePermissions(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// ckeck for a slug to determine if this is a request for all permissions or a specific permission
		// get the slug from the path if it exists
		slug := r.PathValue("slug")
		if slug == "" {

			h.getAllPermissions(w, r)
			return
		} else {

			h.getPermissionBySlug(w, r)
			return
		}
	case http.MethodPut:
		h.updatePermission(w, r)
		return
	case http.MethodPost:
		h.createPermission(w, r)
		return
	default:
		// generate telemetry
		telemetry := connect.NewTelemetry(r, h.logger)
		logger := h.logger.With(telemetry.TelemetryFields()...)

		logger.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
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

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the user access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
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
	go h.getServicePermissions(ctx, util.ServiceTasks, accessToken, h.tasks, permissionCh, errCh, &wg)
	go h.getServicePermissions(ctx, util.ServiceGallery, accessToken, h.gallery, permissionCh, errCh, &wg)

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
		log.Error("failed to get permissions from downstream services", "err", e.Error())
		errRes := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions from downstream services",
		}
		errRes.SendJsonErr(w)
		return
	}

	// collect all permissions from the channels
	var all []permissions.Permission
	for ps := range permissionCh {
		all = append(all, ps...)
	}

	log.Info(fmt.Sprintf("successfully retrieved %d permissions from downstream services", len(all)))

	// send the permissions as a JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(all); err != nil {
		log.Error("failed to encode permissions to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode permissions to json: %v", err),
		}
		e.SendJsonErr(w)
		return
	}
}

// getServicePermissions is a helper method retrieves permissions from a specific service
// based on the service name provided.
func (h *handler) getServicePermissions(
	ctx context.Context,
	service string,
	accessToken string,
	svc *connect.S2sCaller,
	pmCh chan<- []permissions.Permission,
	errCh chan<- error, wg *sync.WaitGroup,
) {

	defer wg.Done()

	// get service token
	serviceToken, err := h.token.GetServiceToken(ctx, service)
	if err != nil {
		errCh <- err
		return
	}

	// get permissions from the service
	ps, err := connect.GetServiceData[[]permissions.Permission](
		ctx,
		svc,
		"/permissions",
		serviceToken,
		accessToken,
	)
	if err != nil {
		errCh <- fmt.Errorf("failed to get permissions from %s: %v", service, err)
		return
	}

	pmCh <- ps
}

// getPermisionBySlug is a helper method that handles the GET request to the /permissions/{slug} endpoint,
// retrieving a specific permission record by its slug from the downstream services.
func (h *handler) getPermissionBySlug(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the user access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// parse the path and slug from the request URL
	// trim the prefix
	path := strings.TrimPrefix(r.URL.Path, "/permissions/")
	parts := strings.SplitN(path, "/", 2)

	// there should only be service and slug in the path
	if len(parts) != 2 {
		log.Error("invalid path in /permissions/{service}/{slug} in request URL")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid path in /permissions/{service}/{slug} in request URL",
		}
		e.SendJsonErr(w)
		return
	}

	// determine which service to send the permission to
	service, err := selectService(parts[0])
	if err != nil {
		log.Error("failed to select service for permission retrieval", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	slug := parts[1]
	if valid := validate.IsValidUuid(slug); !valid {
		log.Error(fmt.Sprintf("invalid permission slug: %s", slug))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid permission slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get the service token for the selected service
	s2sToken, err := h.token.GetServiceToken(ctx, service)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get service token for %s", service), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	var p permissions.Permission
	switch service {
	case util.ServiceTasks:
		permission, err := connect.GetServiceData[permissions.Permission](
			ctx,
			h.tasks,
			fmt.Sprintf("/permissions/%s", slug),
			s2sToken,
			accessToken,
		)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get permission %s for %s service", slug, util.ServiceTasks), "err", err.Error())
			h.tasks.RespondUpstreamError(err, w)
			return
		}

		// set permission to the retrieved permission
		p = permission
	case util.ServiceGallery:
		permission, err := connect.GetServiceData[permissions.Permission](
			ctx,
			h.gallery,
			fmt.Sprintf("/permissions/%s", slug),
			s2sToken,
			accessToken,
		)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get permission %s for %s service", slug, util.ServiceGallery), "err", err.Error())
			h.gallery.RespondUpstreamError(err, w)
			return
		}

		// set permission to the retrieved permission
		p = permission
	default:
		log.Error(fmt.Sprintf("unsupported service %s for permission retrieval", service))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "unsupported service for permission retrieval",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved permission %s for service %s", p.Name, service))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(p); err != nil {
		log.Error("failed to encode permission to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode permission to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// createPermission is a helper method that handles the POST request to the /permissions endpoint,
// creating a new permission record in the downstream services.
func (h *handler) createPermission(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the user access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the request body
	var cmd permissions.Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body to permission creation command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the command
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate permission creation command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error(fmt.Sprintf("invalid session or csrf token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command -> not needed upstream
	cmd.Csrf = ""

	// determine which service to send the permission to
	service, err := selectService(cmd.ServiceName)
	if err != nil {
		log.Error(fmt.Sprintf("failed to provide valid service for permission creation: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get service token for the selected service
	s2sToken, err := h.token.GetServiceToken(ctx, service)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get service token for %s: %s", service, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// post to applicable service
	var p permissions.Permission
	switch service {
	case util.ServiceTasks:
		permission, err := connect.PostToService[permissions.Permission, permissions.Permission](
			ctx,
			h.tasks,
			"/permissions/",
			s2sToken,
			accessToken,
			cmd,
		)
		if err != nil {
			log.Error(fmt.Sprintf("failed to create permission for %s service", util.ServiceTasks), "err", err.Error())
			h.tasks.RespondUpstreamError(err, w)
			return
		}

		// set permission to the created permission
		p = permission
	case util.ServiceGallery:
		permission, err := connect.PostToService[permissions.Permission, permissions.Permission](
			ctx,
			h.gallery,
			"/permissions/",
			s2sToken,
			accessToken,
			cmd,
		)
		if err != nil {
			log.Error(fmt.Sprintf("failed to create permission for %s service", util.ServiceGallery), "err", err.Error())
			h.gallery.RespondUpstreamError(err, w)
			return
		}

		// set permission to the created permission
		p = permission
	default:
		log.Error(fmt.Sprintf("invalid service %s for permission creation", service))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid service for permission creation",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully created permission %s for service %s", p.Name, p.ServiceName))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		log.Error(fmt.Sprintf("failed to encode created permission %s for service %s to json", p.Name, p.ServiceName), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode created permission %s for service %s to json", p.Name, p.ServiceName),
		}
		e.SendJsonErr(w)
		return
	}
}

// updatePermission is a helper method that handles the PUT request to the /permissions/{slug} endpoint,
// updating an existing permission record in the downstream services.
func (h *handler) updatePermission(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get session token from request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token and get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// parse the path and slug from the request URL
	// trim the prefix
	path := strings.TrimPrefix(r.URL.Path, "/permissions/")
	parts := strings.SplitN(path, "/", 2)

	// there should only be service and slug in the path
	if len(parts) != 2 {
		log.Error("invalid path in permission/{service}/{slug} in request URL")
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
		log.Error("failed to select valid service for permission update", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to select valid service for permission update",
		}
		e.SendJsonErr(w)
		return
	}

	slug := parts[1]
	if valid := validate.IsValidUuid(slug); !valid {
		log.Error(fmt.Sprintf("invalid permission slug: %s", slug))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid permission slug",
		}
		e.SendJsonErr(w)
		return
	}

	// parse the request body to get the updated permission data
	var cmd permissions.Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to json decode request body to permission command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to json decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the command
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate permission update command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid session or csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command -> not needed upstream
	cmd.Csrf = ""

	// check url path service matches command service
	// this is a redundant check since it will be dropped, but it would suggest
	// tampering with the request if the service in the URL does not match the command
	if cmd.ServiceName != service {
		log.Error(fmt.Sprintf("service in URL %s does not match service in update command %s", service, cmd.ServiceName))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "service in URL does not match service in update command",
		}
		e.SendJsonErr(w)
		return
	}

	// get the service token for the selected service
	s2sToken, err := h.token.GetServiceToken(ctx, service)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get service token for %s", service), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	var p permissions.Permission
	switch service {
	case util.ServiceTasks:

		// send the update request to the tasks service
		permission, err := connect.PutToService[permissions.Permission, permissions.Permission](
			ctx,
			h.tasks,
			fmt.Sprintf("/permissions/%s", slug),
			s2sToken,
			accessToken,
			cmd,
		)
		if err != nil {
			log.Error(fmt.Sprintf("failed to update permission %s for %s service", slug, util.ServiceTasks), "err", err.Error())
			h.tasks.RespondUpstreamError(err, w)
			return
		}

		// set permission to the updated permission
		p = permission
	case util.ServiceGallery:

		// send the update request to the gallery service
		permission, err := connect.PutToService[permissions.Permission, permissions.Permission](
			ctx,
			h.gallery,
			fmt.Sprintf("/permissions/%s", slug),
			s2sToken,
			accessToken,
			cmd,
		)
		if err != nil {
			log.Error(fmt.Sprintf("failed to update permission %s for %s service", slug, util.ServiceGallery), "err", err.Error())
			h.gallery.RespondUpstreamError(err, w)
			return
		}

		// set permission to the updated permission
		p = permission
	default:
		log.Error(fmt.Sprintf("unsupported service %s for permission update", service))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "unsupported service for permission update",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated permission %s for service %s", p.Name, p.ServiceName))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(p); err != nil {
		log.Error(fmt.Sprintf("failed to encode updated permission %s for service %s to JSON", p.Name, p.ServiceName), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode updated permission %s for service %s to JSON", p.Name, p.ServiceName),
		}
		e.SendJsonErr(w)
		return
	}
}
