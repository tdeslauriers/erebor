package permissions

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// Handler is an interface that defines methods for handling permissions-related endpoint requests.
type Handler interface {

	// HandlePermissions is a method that handles requests against the /permissions endpoint.
	HandlePermissions(w http.ResponseWriter, r *http.Request)
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
	// h.createPermission(w, r)
	// return
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
