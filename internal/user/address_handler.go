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
	case http.MethodPost:
		h.createAddress(w, r)
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
	trimmedStreetAddress_2 := strings.TrimSpace(*cmd.Address.StreetAddress_2)

	req := &gen.CreateAddressRequest{
		Username:        strings.TrimSpace(cmd.Username),
		StreetAddress:   strings.TrimSpace(cmd.Address.StreetAddress),
		StreetAddress_2: &trimmedStreetAddress_2,
		City:            strings.TrimSpace(cmd.Address.City),
		StateProvince:   strings.TrimSpace(cmd.Address.StateProvince),
		PostalCode:      strings.TrimSpace(cmd.Address.PostalCode),
		Country:         strings.TrimSpace(cmd.Address.Country),
		IsCurrent:       cmd.Address.IsCurrent,
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
			Message:    "failed to create address",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully created address with slug %s", address.Slug))

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
