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
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	shaw "github.com/tdeslauriers/shaw/pkg/api/user"
)

// ProfileHandler is the interface for handling profile requests from the client.
// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
type ProfileHandler interface {
	// HandleProfile handles the profile request from the client by submitting it against the user auth service and user profile service.
	// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
	HandleProfile(w http.ResponseWriter, r *http.Request)
}

// NewProfileHandler returns a pointer to a concrete implementation of the ProfileHandler interface.
func NewProfileHandler(
	ux uxsession.Service,
	p provider.S2sTokenProvider,
	iam *connect.S2sCaller,
	pcc gen.ProfilesClient,
) ProfileHandler {
	return &profileHandler{
		session:  ux,
		provider: p,
		identity: iam,
		profile:  pcc,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentProfile)),
	}
}

var _ ProfileHandler = (*profileHandler)(nil)

// profileHandler is the concrete implementation of the ProfileHandler interface.
type profileHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity *connect.S2sCaller
	profile  gen.ProfilesClient

	logger *slog.Logger
}

// HandleProfile handles the profile requests from the client by submitting it against the user auth service and user profile service.
// Note: this is for a user's profile only, and is not meant handle admin-level (any)user requests.
func (h *profileHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		// get user profile
		h.handleGet(w, r)
		return
	case http.MethodPut:
		// update user profile
		h.handlePut(w, r)
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

// handleGet handles the GET request for a user's profile.
func (h *profileHandler) handleGet(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

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
	user, err := connect.GetServiceData[shaw.User](
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

	// get profile data from silhouette service
	p, err := h.profile.GetProfile(
		ctx,
		&gen.GetProfileRequest{
			Username: user.Username,
		},
		authentication.WithUserRequired(session),
	)
	if err != nil {
		log.Error("failed to get profile data from profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internl service error",
		}
		e.SendJsonErr(w)
		return
	}

	// build profile model from user data + silhoutte data
	profile := ProfileResponse{
		Username:       user.Username,
		Firstname:      user.Firstname,
		Lastname:       user.Lastname,
		NickName:       p.GetNickName(),
		DarkMode:       p.GetDarkMode(),
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

	// add addresses if they exist
	if len(p.Address) > 0 {
		profile.Addresses = p.Address
	}

	// add phones if they exist
	if len(p.Phone) > 0 {
		profile.Phones = p.Phone
	}

	log.Info(fmt.Sprintf("successfully retrieved %+v", profile))

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

func (h *profileHandler) handlePut(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

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

	user := shaw.User{
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
	updatedUser, err := connect.PutToService[shaw.User, shaw.User](
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

	// update profile data in silhouette service
	updatedProfile, err := h.profile.UpdateProfile(
		ctx,
		&gen.UpdateProfileRequest{
			Username: cmd.Username,
			NickName: &cmd.NickName,
			DarkMode: cmd.DarkMode,
		},
		authentication.WithUserRequired(session),
	)
	if err != nil {
		log.Error("failed to update profile data in profile service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internl service error",
		}
		e.SendJsonErr(w)
		return
	}

	// build profile model from user data + silhoutte data
	profile := ProfileCmd{
		// drop id no need for it in the response
		Username:       updatedUser.Username,
		Firstname:      updatedUser.Firstname,
		Lastname:       updatedUser.Lastname,
		NickName:       updatedProfile.GetNickName(),
		DarkMode:       updatedProfile.GetDarkMode(),
		Slug:           updatedUser.Slug,
		CreatedAt:      updatedUser.CreatedAt,
		Enabled:        updatedUser.Enabled,
		AccountExpired: updatedUser.AccountExpired,
		AccountLocked:  updatedUser.AccountLocked,
	}

	// add date of birth fields to profile model if birthdate is present
	if updatedUser.BirthDate != "" {
		birthdate, err := time.Parse("2006-01-02", updatedUser.BirthDate)
		if err != nil {
			log.Error("failed to parse user birthdate returned from identity service", "err", err.Error())
			h.identity.RespondUpstreamError(err, w)
			return
		}
		profile.BirthMonth = int(birthdate.Month())
		profile.BirthDay = birthdate.Day()
		profile.BirthYear = birthdate.Year()
	}

	log.Info(fmt.Sprintf("successfully updated %s's profile", updatedUser.Username))

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
