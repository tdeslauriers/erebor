package user

import (
	"context"
	"encoding/json"
	"erebor/gen"
	"erebor/internal/authentication"
	"erebor/internal/authentication/uxsession"
	"erebor/internal/util"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/shaw/pkg/api/user"
)

// UserHandler is an interface for handling user requests
type UserHandler interface {
	// HandleUsers handles all requests to the identity service gateway endpoints
	// once initial validation is done in the gateway, the request is forwarded to the identity service
	HandleUsers(w http.ResponseWriter, r *http.Request)
}

func NewUserHandler(
	ux uxsession.Service,
	pvdr provider.S2sTokenProvider,
	i *connect.S2sCaller,
	t *connect.S2sCaller,
	g *connect.S2sCaller,
	p gen.ProfilesClient,
) UserHandler {

	return &userHandler{
		session:  ux,
		provider: pvdr,
		identity: i,
		tasks:    t,
		gallery:  g,
		profile:  p,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ UserHandler = (*userHandler)(nil)

type userHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity *connect.S2sCaller
	tasks    *connect.S2sCaller
	gallery  *connect.S2sCaller
	profile  gen.ProfilesClient

	logger *slog.Logger
}

func (h *userHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// get slug if exists
		slug := r.PathValue("slug")
		if slug == "" {
			h.getAllUsers(w, r)
			return
		} else {
			h.getUser(w, r)
			return
		}
	case http.MethodPut:
		h.putUser(w, r)
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

func (h *userHandler) getAllUsers(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to retrieve session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get s2s token for identity service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get users from identity service
	users, err := connect.GetServiceData[[]user.User](
		ctx,
		h.identity,
		"/users",
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get users from identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d users from identity service", len(users)))

	// respond with users to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		log.Error("failed to encode users to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode users to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *userHandler) getUser(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to retrieve session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token; get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get s2s token for identity service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get user from identity service
	user, err := connect.GetServiceData[user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/users/%s", slug),
		s2sToken,
		accessToken,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get user %s from identity service: %s", slug, err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved user %s from identity service", slug))

	// get profile data
	p, err := h.profile.GetProfile(
		ctx,
		&gen.GetProfileRequest{Username: user.Username},
		authentication.WithUserRequired(session),
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get profile for user %s from profile service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get user profile",
		}
		e.SendJsonErr(w)
		return
	}

	// get permissions for the user from applicable services
	ps, err := h.getPermissions(ctx, user.Username, accessToken)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get permissions for user %s", user.Slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions for user",
		}
		e.SendJsonErr(w)
		return
	}

	// build profile model for user data + silhouette data
	profile := ProfileResponse{
		Id:             user.Id,
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
		Scopes:         user.Scopes,
		Permissions:    ps,
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

	// respond with user profile to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		log.Error(fmt.Sprintf("failed to encode user %s profile to json: %s", user.Slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode user profile to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *userHandler) putUser(w http.ResponseWriter, r *http.Request) {

	// build/collect telemetry and add fields to the logger
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to retrieve session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token; get access token
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var cmd ProfileCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in request body update command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid user update command in request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token in user update request command", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare user data update cmd (build dob string if all dob fields are present)
	var dob string
	if cmd.BirthMonth != 0 && cmd.BirthDay != 0 && cmd.BirthYear != 0 {
		dob = fmt.Sprintf("%d-%02d-%02d", cmd.BirthYear, cmd.BirthMonth, cmd.BirthDay)
	}

	// prep data for identity service
	u := user.User{
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
		log.Error("failed to get s2s token for identity service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// forward the update request to the identity service
	updatedUser, err := connect.PutToService[user.User, user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/users/%s", slug),
		s2sToken,
		accessToken,
		u,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update user %s in identity service: %s", slug, err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// update data in silhouette service
	p, err := h.profile.UpdateProfile(
		ctx,
		&gen.UpdateProfileRequest{
			Username: updatedUser.Username,
			NickName: &cmd.NickName,
			DarkMode: cmd.DarkMode,
		},
		authentication.WithUserRequired(session),
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update user %s profile in profile service: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to update user profile data",
		}
		e.SendJsonErr(w)
		return
	}

	// build profile model for user data + silhouette data
	profile := ProfileCmd{
		Id:             updatedUser.Id,
		Username:       updatedUser.Username,
		Firstname:      updatedUser.Firstname,
		Lastname:       updatedUser.Lastname,
		NickName:       p.GetNickName(),
		DarkMode:       p.GetDarkMode(),
		Slug:           updatedUser.Slug,
		CreatedAt:      updatedUser.CreatedAt,
		Enabled:        updatedUser.Enabled,
		AccountExpired: updatedUser.AccountExpired,
		AccountLocked:  updatedUser.AccountLocked,
	}

	if updatedUser.BirthDate != "" {
		dob, err := time.Parse("2006-01-02", updatedUser.BirthDate)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		log.Error(fmt.Sprintf("failed to encode updated user %s profile to json: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated user profile to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getPermissions is a helper function which  fetches permissions for a user from multiple services concurrently.
// it mostly exists to make the code more readable and to avoid code duplication.
func (h *userHandler) getPermissions(
	ctx context.Context,
	username string,
	accessToken string,
) ([]permissions.PermissionRecord, error) {

	// check user scopes to determine which services to call for permissions
	jot, err := jwt.BuildTokenFromRaw(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to build JWT from access token: %v", err)
	}

	hasTasksScope := hasScope(util.ServiceTasks, jot.Claims.Scopes)
	hasGalleryScope := hasScope(util.ServiceGallery, jot.Claims.Scopes)

	// get permissions from tasks and gallery services
	var (
		wg     sync.WaitGroup
		permCh = make(chan []permissions.PermissionRecord, 2)
		errCh  = make(chan error, 2)
	)

	if hasTasksScope {
		wg.Add(1)
		go h.getServicePermissions(ctx, username, util.ServiceTasks, accessToken, permCh, errCh, &wg)
	}
	if hasGalleryScope {
		wg.Add(1)
		go h.getServicePermissions(ctx, username, util.ServiceGallery, accessToken, permCh, errCh, &wg)
	}

	wg.Wait()
	close(permCh)
	close(errCh)

	// determine if there were any errors from the goroutines
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to get permissions from services: %s", errors.Join(errs...))
	}

	// collect permissions from channels
	var all []permissions.PermissionRecord
	for perms := range permCh {
		all = append(all, perms...)
	}

	return all, nil
}

// is a helper method to fetch permissions for a user from a specific service
// mostly it exists to make the code more readable and to avoid code duplication
func (h *userHandler) getServicePermissions(
	ctx context.Context,
	username string,
	service string,
	accessToken string,
	pCh chan<- []permissions.PermissionRecord,
	errCh chan<- error, wg *sync.WaitGroup,
) {

	defer wg.Done()

	// get service token for the service
	token, err := h.provider.GetServiceToken(ctx, service)
	if err != nil {
		errCh <- fmt.Errorf("failed to get service token for %s service: %s", service, err.Error())
		return
	}

	switch service {
	case util.ServiceTasks:
		permissions, err := connect.GetServiceData[[]permissions.PermissionRecord](
			ctx,
			h.tasks,
			fmt.Sprintf("/allowances/permissions?username=%s", username),
			token,
			accessToken,
		)
		if err != nil {
			errCh <- fmt.Errorf("failed to get permissions from %s service: %s", service, err.Error())
			return
		}
		pCh <- permissions
		return
	case util.ServiceGallery:
		permissions, err := connect.GetServiceData[[]permissions.PermissionRecord](
			ctx,
			h.gallery,
			fmt.Sprintf("/patrons/permissions?username=%s", username),
			token,
			accessToken,
		)
		if err != nil {
			errCh <- fmt.Errorf("failed to get permissions from %s service: %s", service, err.Error())
			return
		}
		pCh <- permissions
		return
	default:
		errCh <- fmt.Errorf("unknown service: %s", service)
		return
	}
}

// hasScope checks if the user has a services's scope in their access token to determine
// if they should call the service or skip it
func hasScope(service string, scopes string) bool {

	// scopes is a space-separated string of scopes, e.g. "tasks:read tasks:write gallery:read"
	scps := strings.Split(scopes, " ")
	if len(scps) == 0 {
		return false
	}

	// check if the scope slice has the service name in it.
	for _, s := range scps {
		if strings.Contains(s, service) {
			return true
		}
	}
	return false
}
