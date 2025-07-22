package user

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
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// UserHandler is an interface for handling user requests
type UserHandler interface {
	// HandleUsers returns a list of users by forwarding the request to the identity service.
	HandleUsers(w http.ResponseWriter, r *http.Request)

	// HandleUser handles a request from the client by submitting it against the user identity service and user profile service.
	HandleUser(w http.ResponseWriter, r *http.Request)
}

func NewUserHandler(ux uxsession.Service, p provider.S2sTokenProvider, c connect.S2sCaller) UserHandler {
	return &userHandler{
		session:  ux,
		provider: p,
		identity: c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentUser)),
	}
}

var _ UserHandler = (*userHandler)(nil)

type userHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity connect.S2sCaller

	logger *slog.Logger
}

func (h *userHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET requests are allowed to /users endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get session token from request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for identity service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token for identity service",
		}
		e.SendJsonErr(w)
		return
	}

	// get users from identity service
	var users []profile.User
	if err := h.identity.GetServiceData("/users", s2sToken, accessToken, &users); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get /users from identity service: %s", err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// respond with users to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode users to json: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode users to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *userHandler) HandleUser(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetUser(w, r)
		return
	case http.MethodPut:
		h.handlePutUser(w, r)
		return
	default:
		h.logger.Error("only GET and PUT requests are allowed to /users/{slug} endpoint")
	}
}

func (h *userHandler) handleGetUser(w http.ResponseWriter, r *http.Request) {

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to retrieve session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token; get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for get /users/slug request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for identity service for get /users/slug request: %s", err.Error()))
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
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get user from identity service
	var user profile.User
	if err := h.identity.GetServiceData(fmt.Sprintf("/users/%s", slug), s2sToken, accessToken, &user); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get /users/%s from identity service: %s", slug, err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// TODO: placeholder for geting silhouette data from silhouette service

	// get permissions for the user from applicable services
	ps, err := h.getPermissions(user.Username, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get permissions for user %s: %s", user.Username, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions for user",
		}
		e.SendJsonErr(w)
		return
	}

	// build profile model for user data + silhouette data
	profile := ProfileCmd{
		// NEVER RETURN THE CSRF/SESSION TOKEN TO THE CLIENT
		// even if it is returned, will be dropped by the client

		Id:             user.Id,
		Username:       user.Username,
		Firstname:      user.Firstname,
		Lastname:       user.Lastname,
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
			h.logger.Error("failed to parse user birthdate", "err", err.Error())
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

	// respond with user profile to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(profile); err != nil {
		errMsg := fmt.Sprintf("failed to encode user %s profile to json: %s", user.Username, err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *userHandler) handlePutUser(w http.ResponseWriter, r *http.Request) {

	// get the user token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to retrieve session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// validate session token; get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for put /users/slug request: %s", err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
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
		errMsg := fmt.Sprintf("failed to decode json in put /users/%s request: %s", slug, err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("error validating request body in put /users/%s request: %s", slug, err.Error())
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
		h.logger.Error(fmt.Sprintf("invalid csrf token in put /users/%s request: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// prepare user data update cmd (build dob string if all dob fields are present)
	var dob string
	if cmd.BirthMonth != 0 && cmd.BirthDay != 0 && cmd.BirthYear != 0 {
		dob = fmt.Sprintf("%d-%02d-%02d", cmd.BirthYear, cmd.BirthMonth, cmd.BirthDay)
	}

	// prep data for identity service
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

	// access token retrieved above to validate session

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for identity service for put /users/%s request: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// make the update request to the identity service
	var updated profile.User
	if err := h.identity.PostToService(fmt.Sprintf("/users/%s", slug), s2sToken, accessToken, user, &updated); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update user %s in identity service: %s", slug, err.Error()))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// TODO: placeholder for updating silhouette data in silhouette service

	// build profile model for user data + silhouette data
	profile := ProfileCmd{
		Id:             updated.Id,
		Username:       updated.Username,
		Firstname:      updated.Firstname,
		Lastname:       updated.Lastname,
		Slug:           updated.Slug,
		CreatedAt:      updated.CreatedAt,
		Enabled:        updated.Enabled,
		AccountExpired: updated.AccountExpired,
		AccountLocked:  updated.AccountLocked,
	}

	if updated.BirthDate != "" {
		dob, err := time.Parse("2006-01-02", updated.BirthDate)
		if err != nil {
			h.logger.Error("failed to parse user birthdate", "err", err.Error())
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
		errMsg := fmt.Sprintf("failed to encode updated user %s profile to json: %s", updated.Username, err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}
}

// getPermissions is a helper function which  fetches permissions for a user from multiple services concurrently.
// it mostly exists to make the code more readable and to avoid code duplication.
func (h *userHandler) getPermissions(username, accessToken string) ([]permissions.Permission, error) {

	// check user scopes to determine which services to call for permissions
	jot, err := jwt.BuildFromToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to build JWT from access token: %v", err)
	}

	hasTasksScope := hasScope(util.ServiceTasks, jot.Claims.Scopes)
	hasGalleryScope := hasScope(util.ServiceGallery, jot.Claims.Scopes)

	// get permissions from tasks and gallery services
	var (
		wg     sync.WaitGroup
		permCh = make(chan []permissions.Permission, 2)
		errCh  = make(chan error, 2)
	)

	if hasTasksScope {
		wg.Add(1)
		go h.getServicePermissions(username, util.ServiceTasks, accessToken, permCh, errCh, &wg)
	}
	if hasGalleryScope {
		wg.Add(1)
		go h.getServicePermissions(username, util.ServiceGallery, accessToken, permCh, errCh, &wg)
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
	var all []permissions.Permission
	for perms := range permCh {
		all = append(all, perms...)
	}

	return all, nil
}

// is a helper method to fetch permissions for a user from a specific service
// mostly it exists to make the code more readable and to avoid code duplication
func (h *userHandler) getServicePermissions(username, service, accessToken string, pCh chan<- []permissions.Permission, errCh chan<- error, wg *sync.WaitGroup) {

	defer wg.Done()

	// get service token for the service
	token, err := h.provider.GetServiceToken(service)
	if err != nil {
		errCh <- fmt.Errorf("failed to get service token for %s service: %s", service, err.Error())
		return
	}

	var prefix string
	switch service {
	case util.ServiceTasks:
		prefix = "/allowances"
	case util.ServiceGallery:
		prefix = "/patrons"
	default:
		errCh <- fmt.Errorf("unknown service: %s", service)
		return
	}

	// make request to the service
	var permissions []permissions.Permission
	if err := h.identity.GetServiceData(fmt.Sprintf("%s/permissions?email=%s", prefix, username), token, accessToken, &permissions); err != nil {
		errCh <- fmt.Errorf("failed to get permissions from %s service: %s", service, err.Error())
		return
	}

	pCh <- permissions
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
