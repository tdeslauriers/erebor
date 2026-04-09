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

// AddressHandler is the interface that defines the method that handles requests to the /address endpoint.
type AddressHandler interface {

	// HandleAddress is the method that handles requests to the /address endpoint.
	HandleAddress(w http.ResponseWriter, r *http.Request)
}

// NewAddressHandler returns a new instance of AddressHandler with a pointer to the concrete implementation of the AddressHandler interface.
func NewAddressHandler(
	ux uxsession.Service,
	p provider.S2sTokenProvider,
	pcc grpc.ClientConnInterface,
) AddressHandler {
	return &addressHandler{
		session:  ux,
		provider: p,
		profile:  gen.NewAddressesClient(pcc),

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentAddresses)),
	}
}

var _ AddressHandler = (*addressHandler)(nil)

// addressHandler is the concrete implementation of the AddressHandler interface.
type addressHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	profile  gen.AddressesClient

	logger *slog.Logger
}

// HandleAddress is the concrete implementation of the method that handles requests to the /address endpoint.
func (h *addressHandler) HandleAddress(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodPut:
		h.updateAddress(w, r)
		return
	case http.MethodPost:
		h.createAddress(w, r)
		return
	case http.MethodDelete:
		h.deleteAddress(w, r)
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

// createAddress is the method that handles POST requests to the /address endpoint.
func (h *addressHandler) createAddress(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get sessionToken token from request
	sessionToken, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get valid session
	uxSession, err := h.session.GetValidSession(sessionToken)
	if err != nil {
		log.Error("invalid session token provided", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get response body
	var cmd AddressCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body into AddressCmd struct", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("address command validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check csrf token
	if uxSession.CsrfToken != strings.TrimSpace(cmd.Csrf) {
		log.Error("invalid csrf token provided in request body")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "invalid csrf token",
		}
		e.SendJsonErr(w)
		return
	}

	// build request for profile service
	trimmedStreetAddress_2 := strings.TrimSpace(cmd.Address.GetStreetAddress_2())

	req := &gen.CreateAddressRequest{
		Username:        strings.TrimSpace(cmd.Username),
		StreetAddress:   strings.TrimSpace(cmd.Address.StreetAddress),
		StreetAddress_2: &trimmedStreetAddress_2,
		City:            strings.TrimSpace(cmd.Address.City),
		StateProvince:   strings.TrimSpace(cmd.Address.StateProvince),
		PostalCode:      strings.TrimSpace(cmd.Address.PostalCode),
		Country:         strings.TrimSpace(cmd.Address.Country),
		IsCurrent:       cmd.Address.IsCurrent,
		IsPrimary:       cmd.Address.IsPrimary,
	}

	// call profile service to create address
	address, err := h.profile.CreateAddress(
		ctx,
		req,
		authentication.WithUserRequired(uxSession.SessionToken),
	)
	if err != nil {
		log.Error("failed to create address in profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully created address with slug %s for uesr %s", address.GetSlug(), strings.TrimSpace(cmd.Username)))

	// return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(address); err != nil {
		log.Error("failed to encode address into response body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response body",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateAddress is the method that handles PUT requests to the /address endpoint.
func (h *addressHandler) updateAddress(w http.ResponseWriter, r *http.Request) {

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

	// get response body
	var cmd AddressCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body into AddressCmd struct", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("address command validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid request body: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// check csrf token
	if uxSession.CsrfToken != strings.TrimSpace(cmd.Csrf) {
		log.Error("invalid csrf token provided in request body")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "invalid csrf token",
		}
		e.SendJsonErr(w)
		return
	}

	// build request for profile service
	trimmedStreetAddress_2 := strings.TrimSpace(cmd.Address.GetStreetAddress_2())

	updated := &gen.UpdateAddressRequest{
		Username:        strings.TrimSpace(cmd.Username),
		Slug:            strings.TrimSpace(cmd.Slug),
		StreetAddress:   strings.TrimSpace(cmd.Address.StreetAddress),
		StreetAddress_2: &trimmedStreetAddress_2,
		City:            strings.TrimSpace(cmd.Address.City),
		StateProvince:   strings.TrimSpace(cmd.Address.StateProvince),
		PostalCode:      strings.TrimSpace(cmd.Address.PostalCode),
		Country:         strings.TrimSpace(cmd.Address.Country),
		IsCurrent:       cmd.Address.IsCurrent,
		IsPrimary:       cmd.Address.IsPrimary,
	}

	// call profile service to update address
	address, err := h.profile.UpdateAddress(
		ctx,
		updated,
		authentication.WithUserRequired(uxSession.SessionToken),
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update address (slug %s) in profile service", cmd.Slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully updated address with slug %s", cmd.Slug))

	// return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(address); err != nil {
		log.Error("failed to encode address into response body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response body",
		}
		e.SendJsonErr(w)
		return
	}
}

// deleteAddress is the method that handles DELETE requests to the /address endpoint.
func (h *addressHandler) deleteAddress(w http.ResponseWriter, r *http.Request) {

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

	// decode response body
	var cmd DeleteAddressCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body into DeleteAddressCmd struct", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("delete address command validation failed", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid request body: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// check csrf token
	if uxSession.CsrfToken != strings.TrimSpace(cmd.Csrf) {
		log.Error("invalid csrf token provided in request body")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "invalid csrf token",
		}
		e.SendJsonErr(w)
		return
	}

	// call profile service to delete address
	_, err = h.profile.DeleteAddress(
		ctx,
		&gen.DeleteAddressRequest{
			Username: strings.TrimSpace(cmd.Username),
			Slug:     strings.TrimSpace(cmd.Slug),
		},
		authentication.WithUserRequired(uxSession.SessionToken),
	)
	if err != nil {
		log.Error("failed to delete address in profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to delete address",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(
		fmt.Sprintf("successfully deleted address %s from %s's user profile",
			strings.TrimSpace(cmd.Slug),
			strings.TrimSpace(cmd.Username),
		),
	)

	// return success response
	w.WriteHeader(http.StatusNoContent)
}
