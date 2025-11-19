package user

import (
	"context"
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// ResetHandler is an interface for handling user-initiated password resets
// or updates, where the users knows their current password.
type ResetHandler interface {
	// HandleReset handles the password reset request where a user knows their current password.
	HandleReset(w http.ResponseWriter, r *http.Request)
}

// NewResetHandler returns a pointer to the concrete implementation of the ResetHandler interface.
func NewResetHandler(ux uxsession.Service, p provider.S2sTokenProvider, iam *connect.S2sCaller) ResetHandler {
	return &resetHandler{
		session:  ux,
		provider: p,
		identity: iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageUser)).
			With(slog.String(util.ComponentKey, util.ComponentResetUser)),
	}
}

var _ ResetHandler = (*resetHandler)(nil)

type resetHandler struct {
	session  uxsession.Service
	provider provider.S2sTokenProvider
	identity *connect.S2sCaller

	logger *slog.Logger
}

// HandleReset is the concrete implementation of the interface function that handles the password reset request where a user knows their current password.
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /reset endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the user has an active, authenticated session
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to retrieve session token from request", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	// NOTE: at this point, there is nothing that says the subject/principal in the access token
	// is the same as the user making the request since the session does not have the users identity.
	// This will validated by the identity service when the request is made, ie, the identity service
	// will only attempt to update the password of the access token subject IF that access token is valid.
	// The user has no ability to determine or target password changes for any user, not even themselves.
	accessToken, err := h.session.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to retrieve access token from session", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// decode the request body
	var cmd profile.ResetCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode json in user reset request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of the reset request
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("invalid reset request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.session.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid csrf token", "err", err.Error())
		h.session.HandleSessionErr(err, w)
		return
	}

	// csrf no longer needed, set to empty string
	cmd.Csrf = ""

	// get s2s token for the identity service
	s2sToken, err := h.provider.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		h.logger.Error("failed to retrieve s2s token for iam service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	jot, err := jwt.BuildFromToken(accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to build jwt from access token: %v", err))
		// no error needed since this is a convenience function
	}

	// send the request to the identity service to update the password
	// there will be no response body, only a status code -> identity will not return password data
	_, err = connect.PutToService[profile.ResetCmd, struct{}](
		ctx,
		h.identity,
		"/reset",
		s2sToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to reset user password in identity service", "username", jot.Claims.Subject, "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info("user password reset successful", "username", jot.Claims.Subject)
	w.WriteHeader(http.StatusNoContent)
}
