package user

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
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
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token provided in request Authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token provided in request Authorization header",
		}
		e.SendJsonErr(w)
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

	// get the url slug from the request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		errMsg := "no user slug provided in get /users/{slug} request"
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// light weight validation of slug
	if len(slug) < 16 || len(slug) > 64 {
		h.logger.Error("invalid user slug provided in get /users/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid user slug provided",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token provided in get /users/{slug} request Authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token provided in get /users/{slug} request Authorization header",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight validation of session token
	if len(session) < 16 || len(session) > 64 {
		h.logger.Error("invalid session token provided in get /users/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session token provided",
		}
		e.SendJsonErr(w)
		return
	}

	// validate session token; get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for get /users/%s request: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
		return
	}

	// get s2s token for identity service
	s2sToken, err := h.provider.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for identity service for get /users/%s request: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
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

	// get the url slug from the request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		errMsg := "no user slug provided in put /users/{slug} request"
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// light weight validation of slug
	if len(slug) < 16 || len(slug) > 64 {
		h.logger.Error("invalid user slug provided in put /users/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid user slug provided",
		}
		e.SendJsonErr(w)
		return
	}

	// get the user token from the request
	session := r.Header.Get("Authorization")
	if session == "" {
		h.logger.Error("no session token provided in put /users/{slug} request Authorization header")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "no session token provided in put /users/{slug} request Authorization header",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight validation of session token
	if len(session) < 16 || len(session) > 64 {
		h.logger.Error("invalid session token provided in put /users/{slug} request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid session token provided",
		}
		e.SendJsonErr(w)
		return
	}

	// validate session token; get access token
	accessToken, err := h.session.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token for put /users/%s request: %s", slug, err.Error()))
		h.session.HandleSessionErr(err, w)
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
