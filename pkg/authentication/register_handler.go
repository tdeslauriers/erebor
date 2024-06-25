package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"erebor/internal/util"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type RegistrationHandler interface {
	// HandleRegistration handles the registration request from the client by submitting it against the user auth service.
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewRegistrationHandler(oauth config.OauthRedirect, provider session.S2sTokenProvider, caller connect.S2sCaller) RegistrationHandler {
	return &registrationHandler{
		oauth:       oauth,
		s2sProvider: provider,
		caller:      caller,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	oauth       config.OauthRedirect
	s2sProvider session.S2sTokenProvider
	caller      connect.S2sCaller

	logger *slog.Logger
}

func (h *registrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /register endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd session.UserRegisterCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("unable to decode json in user registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("unable to validate fields in registration request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get shaw service token
	s2sToken, err := h.s2sProvider.GetServiceToken(util.ServiceUserIdentity)
	if err != nil {
		h.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "User registration failed due to internal server error.",
		}
		e.SendJsonErr(w)
		return
	}

	// TODO: add logic to choose which client to add to user's registration request
	// for now this is the primary website's client id
	cmd.ClientId = h.oauth.CallbackClientId // association required for user login after registation

	// call identity service with registration request
	var registered session.UserRegisterCmd
	if err := h.caller.PostToService("/register", s2sToken, "", cmd, &registered); err != nil {
		h.logger.Error(fmt.Sprintf("failed to register user (%s)", cmd.Username), "err", err.Error())
		h.caller.RespondUpstreamError(err, w)
		return
	}

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	
	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered user data is a convenience only, omit on error
		h.logger.Error("unable to marshal/send user registration response body", "err", err.Error())
		return
	}
}
