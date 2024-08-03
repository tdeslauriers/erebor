package authentication

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/oauth"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"strings"
	"sync"
	"time"

	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	callback "github.com/tdeslauriers/carapace/pkg/session/types"
)

type CallbackHandler interface {
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

func NewCallbackHandler(p provider.S2sTokenProvider, c connect.S2sCaller, o oauth.Service, ux uxsession.Service, v jwt.Verifier) CallbackHandler {
	return &callbackHandler{
		s2sToken:  p,
		caller:    c,
		oAuth:     o,
		uxSession: ux,
		verifier:  v,

		logger: slog.Default().With(slog.String(util.PackageKey, util.PackageAuth)).With(slog.String(util.ComponentKey, util.ComponentCallback)),
	}
}

var _ CallbackHandler = (*callbackHandler)(nil)

type callbackHandler struct {
	s2sToken  provider.S2sTokenProvider
	caller    connect.S2sCaller
	oAuth     oauth.Service
	uxSession uxsession.Service
	verifier  jwt.Verifier

	logger *slog.Logger
}

func (h *callbackHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.logger.Error("only POST requests are allowed to /callback endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd callback.AuthCodeCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("failed to decode json in user callback request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation of the callback request
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("invalid callback request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate oauth variables (state, nonce, client id, redirect) against the session token
	if err := h.oAuth.Validate(cmd); err != nil {
		h.oAuth.HandleServiceErr(err, w)
	}

	// get service token
	s2sToken, err := h.s2sToken.GetServiceToken(util.ServiceUserIdentity)
	if err != nil {
		h.logger.Error("failed to retreive s2s token")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "login unsuccessful: internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// build the access token request cmd
	payload := callback.AccessTokenCmd{
		Grant:       callback.AuthorizationCode,
		AuthCode:    cmd.AuthCode,
		ClientId:    cmd.ClientId,
		RedirectUrl: cmd.Redirect,
	}

	// send request to identity service to get access, request, and id tokens
	var access provider.UserAuthorization
	if err := h.caller.PostToService("/callback", s2sToken, "", payload, &access); err != nil {
		h.logger.Error("call to identity service callback endpoint failed", "err", err.Error())
		h.caller.RespondUpstreamError(err, w)
		return
	}

	// validate and build the id and access token
	if access.IdTokenExpires.Before(time.Now().UTC()) {
		h.logger.Error("id token has expired")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "id token has expired",
		}
		e.SendJsonErr(w)
		return
	}

	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 2)

		idToken     *jwt.Token
		accessToken *jwt.Token
	)

	wg.Add(2)
	go h.verify(access.IdToken, ErrVerifyIdToken, idToken, errChan, &wg)
	go h.verify(access.AccessToken, ErrVerifyAccessToken, accessToken, errChan, &wg)

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errChan {
			builder.WriteString(err.Error())
			if count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		h.logger.Error("failed to parse callback token", "err", builder.String())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to parse callback tokens",
		}
		e.SendJsonErr(w)
		return
	}

	render := h.buildRender(accessToken.Claims.Audience)

	// update the user session
	session, err := h.uxSession.Build(uxsession.Authenticated)
	if err != nil {
		h.logger.Error("failed to create session", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to create user session",
		}
		e.SendJsonErr(w)
		return
	}

	// TODO: persist the authenticated session, access/refresh tokens, and xref

	// TODO: invalidate the unauthenticated session

	// return authentication data
	response := CallbackResponse{
		Session: session.SessionToken,

		Authenticated: session.Authenticated,
		Username:      idToken.Claims.Email,
		Fullname:      idToken.Claims.Name,
		Firstname:     idToken.Claims.GivenName,
		Lastname:      idToken.Claims.FamilyName,
		// Birthdate: idToken.Claims.Birthdate,

		Ux: render,
	}
}

// verify verifies the token's signature and sets the values of the passed in jwt.Token struct
func (h *callbackHandler) verify(token, errMsg string, jot *jwt.Token, ch chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	tkn, err := jwt.BuildFromToken(token)
	if err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
		return
	}

	if err := h.verifier.VerifySignature(tkn.BaseString, tkn.Signature); err != nil {
		ch <- fmt.Errorf("%s: %v", errMsg, err)
	}

	*jot = *tkn
}

func (h *callbackHandler) buildRender(audiences []string) Render {

	var render Render

	for _, audience := range audiences {

		switch audience {
		case util.ServiceS2sIdentity:
			// identity and profile service are the same from ui perspective
			render.Profile = true
		case util.ServiceBlog:
			render.Blog = true
		case util.ServiceGallery:
			render.Gallery = true
		}
	}

	return render
}
