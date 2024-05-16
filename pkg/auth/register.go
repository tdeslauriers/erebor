package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"erebor/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type RegistrationHandler interface {
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

func NewRegistrationHandler(provider session.S2sTokenProvider, caller connect.S2sCaller) RegistrationHandler {
	return &registrationHandler{
		s2sProvider: provider,
		caller:      caller,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuth)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

type registrationHandler struct {
	s2sProvider session.S2sTokenProvider
	caller      connect.S2sCaller
	logger      *slog.Logger
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
		h.logger.Error("unable to decode json in user registration request body", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("unable to validate fields in registration request body", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get shaw service token
	s2sToken, err := h.s2sProvider.GetServiceToken("shaw")
	if err != nil {
		h.logger.Error("unable to retreive shaw s2s token", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "user registration failed due to internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var registered session.UserRegisterCmd
	if err := h.caller.PostToService("/register", s2sToken, "", cmd, &registered); err != nil {
		if strings.Contains(err.Error(), "username unavailable") {
			h.logger.Error("registration failed", err)
			e := connect.ErrorHttp{
				StatusCode: http.StatusConflict,
				Message:    "username unavailable",
			}
			e.SendJsonErr(w)
			return
		} else {
			h.logger.Error("registration failed", err)
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "user registration failed due to internal server error",
			}
			e.SendJsonErr(w)
			return
		}
	}

	// respond 201 + registered user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(registered); err != nil {
		// returning successfully registered user data is a convenience only, omit on error
		h.logger.Error("unable to marshal/send user registration response body", err)
		return
	}
}
