package user

import (
	"context"
	"encoding/json"
	"erebor/gen"
	"erebor/internal/authentication"
	"erebor/internal/authentication/uxsession"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"google.golang.org/grpc"
)

// PhoneHandler is the interface that defines the method that handles requests to the /phones endpoint.
type PhoneHandler interface {

	// HandlePhone is the method that handles requests to the /phone endpoint.
	HandlePhones(w http.ResponseWriter, r *http.Request)
}

// NewPhoneHandler creates a new instance of PhoneHandler, returning
// a pointer to a concrete implementation of the interface.
func NewPhoneHandler(
	ux uxsession.Service,
	p provider.S2sTokenProvider,
	pcc grpc.ClientConnInterface,
) PhoneHandler {

	return &phoneHandler{
		session:  ux,
		provider: p,
		profile:  gen.NewPhonesClient(pcc),

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentPhones)),
	}
}

var _ PhoneHandler = (*phoneHandler)(nil)

// phoneHandler is the concrete implementation of the PhoneHandler interface.
// It implements the HandlePhone method, which handles requests to the /phones endpoint.
type phoneHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	profile  gen.PhonesClient

	logger *slog.Logger
}

// HandlePhones is the method that handles requests to the /phones endpoint.
func (h *phoneHandler) HandlePhones(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodPost:
		h.createPhone(w, r)
	case http.MethodPut:
		h.updatePhone(w, r)
		return
	case http.MethodDelete:
		h.deletePhone(w, r)
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

// createPhone handles the creation of a new phone number for a user.
func (h *phoneHandler) createPhone(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add to logger
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

	// get session from token request
	uxSession, err := h.session.GetValidSession(session)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	var cmd PhoneCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body into PhoneCmd struct", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate input fields
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("phone command failed validation", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check csrf token
	if strings.TrimSpace(cmd.Csrf) != uxSession.CsrfToken {
		log.Error("invalid CSRF token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "invalid CSRF token",
		}
		e.SendJsonErr(w)
		return
	}

	// build the request for the service call
	extension := strings.TrimSpace(cmd.Phone.GetExtension())

	req := &gen.CreatePhoneRequest{
		Username:    strings.TrimSpace(cmd.Username),
		CountryCode: strings.TrimSpace(cmd.Phone.CountryCode),
		PhoneNumber: strings.TrimSpace(cmd.Phone.PhoneNumber),
		Extension:   &extension,
		PhoneType:   cmd.Phone.PhoneType,
		IsCurrent:   cmd.Phone.IsCurrent,
		IsPrimary:   cmd.Phone.IsPrimary,
	}

	// call profile service to create phone
	phone, err := h.profile.CreatePhone(
		ctx,
		req,
		authentication.WithUserRequired(uxSession.SessionToken),
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create phone for user %s", strings.TrimSpace(cmd.Username)), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully created phone with slug %s for user %s", phone.GetSlug(), strings.TrimSpace(cmd.Username)))

	// return success response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(phone); err != nil {
		log.Error("failed to encode phone response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// updatePhone handles the updating of an existing phone number for a user.
func (h *phoneHandler) updatePhone(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
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

	// get valid session
	uxSession, err := h.session.GetValidSession(session)
	if err != nil {
		log.Error("invalid session token provided", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	var cmd PhoneCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body into PhoneCmd struct", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate input fields
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("phone command failed validation", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check csrf token
	if strings.TrimSpace(cmd.Csrf) != uxSession.CsrfToken {
		log.Error("invalid CSRF token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "invalid CSRF token",
		}
		e.SendJsonErr(w)
		return
	}

	// prepare fields for service call
	extenstion := strings.TrimSpace(cmd.Phone.GetExtension())

	// build the request for the service call
	req := &gen.UpdatePhoneRequest{
		Username:    strings.TrimSpace(cmd.Username),
		PhoneSlug:   strings.TrimSpace(cmd.Slug),
		CountryCode: strings.TrimSpace(cmd.Phone.CountryCode),
		PhoneNumber: strings.TrimSpace(cmd.Phone.PhoneNumber),
		Extension:   &extenstion,
		PhoneType:   cmd.Phone.PhoneType,
		IsCurrent:   cmd.Phone.IsCurrent,
		IsPrimary:   cmd.Phone.IsPrimary,
	}

	// call profile service to update phone
	phone, err := h.profile.UpdatePhone(
		ctx,
		req,
		authentication.WithUserRequired(uxSession.SessionToken),
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update phone with slug %s for user %s", cmd.Phone.Slug, strings.TrimSpace(cmd.Username)), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated phone with slug %s for user %s", phone.GetSlug(), strings.TrimSpace(cmd.Username)))

	// return success response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(phone); err != nil {
		log.Error("failed to encode phone response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// deletePhone handles the deletion of an existing phone number for a user.
func (h *phoneHandler) deletePhone(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
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

	// get valid session
	uxSession, err := h.session.GetValidSession(session)
	if err != nil {
		log.Error("invalid session token provided", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	var cmd DeletePhoneCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body into DeletePhoneCmd struct", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate input fields
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("delete phone command failed validation", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check csrf token
	if strings.TrimSpace(cmd.Csrf) != uxSession.CsrfToken {
		log.Error("invalid CSRF token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "invalid CSRF token",
		}
		e.SendJsonErr(w)
		return
	}

	// build the request for the service call
	req := &gen.DeletePhoneRequest{
		Username:  strings.TrimSpace(cmd.Username),
		PhoneSlug: strings.TrimSpace(cmd.Slug),
	}

	// call profile service to delete phone
	_, err = h.profile.DeletePhone(
		ctx,
		req,
		authentication.WithUserRequired(uxSession.SessionToken),
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to delete phone with slug %s for user %s", strings.TrimSpace(cmd.Slug), strings.TrimSpace(cmd.Username)), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully deleted phone with slug %s for user %s", strings.TrimSpace(cmd.Slug), strings.TrimSpace(cmd.Username)))

	// return success response
	w.WriteHeader(http.StatusNoContent)
}
