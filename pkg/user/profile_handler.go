package user

import (
	"context"
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// ProfileHandler is the interface for handling profile requests from the client.
// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
type ProfileHandler interface {
	// HandleProfile handles the profile request from the client by submitting it against the user auth service and user profile service.
	// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
	HandleProfile(w http.ResponseWriter, r *http.Request)
}

// NewProfileHandler returns a pointer to a concrete implementation of the ProfileHandler interface.
func NewProfileHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam *connect.S2sCaller) ProfileHandler {
	return &profileHandler{
		session:  ux,
		provider: p,
		identity: iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentProfile)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}
}

var _ ProfileHandler = (*profileHandler)(nil)

// profileHandler is the concrete implementation of the ProfileHandler interface.
type profileHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity *connect.S2sCaller
	// profile connect.S2sCaller: silhoutte service, ie, non-identity data that is part of user profile, address, phone, preferences, etc

	logger *slog.Logger
}

// HandleProfile handles the profile requests from the client by submitting it against the user auth service and user profile service.
// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
func (h *profileHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	switch r.Method {
	case http.MethodGet:
		// get user profile
		h.handleGet(w, r, tel, log)
		return
	case http.MethodPut:
		// update user profile
		h.handlePut(w, r, tel, log)
		return
	default:
		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGet handles the GET request for a user's profile.
func (h *profileHandler) handleGet(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get user access token from session
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchage session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get s2s token for call to iam profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internl service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get user data from identity service
	user, err := connect.GetServiceData[profile.User](
		ctx,
		h.identity,
		"/profile",
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get user profile from identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// TODO: place holder for getting silhouette data from silhouette service

	// build profile model from user data + silhoutte data
	profile := ProfileCmd{
		// NEVER RETURN SESSION TOKEN/CRSF TO CLIENT: it is only used for server-side validation
		// and will be dropped from the model before sending to the client anyway

		Username:       user.Username,
		Firstname:      user.Firstname,
		Lastname:       user.Lastname,
		Slug:           user.Slug,
		CreatedAt:      user.CreatedAt,
		Enabled:        user.Enabled,
		AccountExpired: user.AccountExpired,
		AccountLocked:  user.AccountLocked,
	}

	// add date of birth fields to profile model if birthdate is present
	if user.BirthDate != "" {
		dob, err := time.Parse("2006-01-02", user.BirthDate)
		if err != nil {
			log.Error("failed to parse user birthdate", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to parse user birthdate",
			}
			e.SendJsonErr(w)
			return
		}
		profile.BirthMonth = int(dob.Month())
		profile.BirthDay = dob.Day()
		profile.BirthYear = dob.Year()
	}

	// profile model will be returned to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		log.Error("failed to encode user profile to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode user profile to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *profileHandler) handlePut(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get user access token from session
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchage session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get request body
	var cmd ProfileCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in user profile request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of the profile request
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid profile request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare user data update cmd (build dob string if all dob fields are present)
	var dob string
	if cmd.BirthMonth != 0 && cmd.BirthDay != 0 && cmd.BirthYear != 0 {
		dob = fmt.Sprintf("%d-%02d-%02d", cmd.BirthYear, cmd.BirthMonth, cmd.BirthDay)
	}

	user := profile.User{
		Id:             cmd.Id,       // possibly "", but doesnt matter because it is not used in the update
		Username:       cmd.Username, // possibly "", but dropped from update cmd upstream: usename/subject will be taken from token
		Firstname:      cmd.Firstname,
		Lastname:       cmd.Lastname,
		BirthDate:      dob,
		Slug:           cmd.Slug,           // possibly "", not used in the update (profile only, is used in admin user update)
		CreatedAt:      cmd.CreatedAt,      // possibly "", not used in the update
		Enabled:        cmd.Enabled,        // passed, but dropped upstream because user not allowed to change enabled status
		AccountExpired: cmd.AccountExpired, // passed, but dropped upstream because user not allowed to change account expired status
		AccountLocked:  cmd.AccountLocked,  // passed, but dropped upstream because user not allowed to change account locked status
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get s2s token for call to iam profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internl service error",
		}
		e.SendJsonErr(w)
		return
	}

	// update user data in identity service
	updated, err := connect.PutToService[profile.User, profile.User](
		ctx,
		h.identity,
		"/profile",
		s2sToken,
		accessToken,
		user,
	)
	if err != nil {
		log.Error("failed to update user profile in identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// TODO: placeholder for updating silhouette data in silhouette service

	// build profile model from user data + silhoutte data
	profile := ProfileCmd{
		// drop id no need for it in the response
		Username:       updated.Username,
		Firstname:      updated.Firstname,
		Lastname:       updated.Lastname,
		Slug:           updated.Slug,
		CreatedAt:      updated.CreatedAt,
		Enabled:        updated.Enabled,
		AccountExpired: updated.AccountExpired,
		AccountLocked:  updated.AccountLocked,
	}

	// add date of birth fields to profile model if birthdate is present
	if updated.BirthDate != "" {
		birthdate, err := time.Parse("2006-01-02", updated.BirthDate)
		if err != nil {
			log.Error("failed to parse user birthdate returned from identity service", "err", err.Error())
			h.identity.RespondUpstreamError(err, w)
			return
		}
		profile.BirthMonth = int(birthdate.Month())
		profile.BirthDay = birthdate.Day()
		profile.BirthYear = birthdate.Year()
	}

	w.Header().Set("Content-Type", "application/json")
	// cant be 204 because will need to return the new csrf token to the client,
	// TODO: replace used csrf with new one
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		log.Error("failed to encode user profile to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode user profile to json",
		}
		e.SendJsonErr(w)
		return
	}
}
