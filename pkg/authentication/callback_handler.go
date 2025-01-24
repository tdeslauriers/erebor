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

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAuth)).
			With(slog.String(util.ComponentKey, util.ComponentCallback)),
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
		fmt.Printf("FAIL: %v\n", err)
		h.oAuth.HandleServiceErr(err, w)
	}

	// get service token
	s2sToken, err := h.s2sToken.GetServiceToken(util.ServiceIdentity)
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

	// validate  id and access token
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
		wgVerify      sync.WaitGroup
		errVerifyChan = make(chan error, 2)

		idToken     jwt.Token
		accessToken jwt.Token
	)

	wgVerify.Add(2)
	go h.verify(access.IdToken, uxsession.ErrVerifyIdToken, &idToken, errVerifyChan, &wgVerify)
	go h.verify(access.AccessToken, uxsession.ErrVerifyAccessToken, &accessToken, errVerifyChan, &wgVerify)

	wgVerify.Wait()
	close(errVerifyChan)

	if len(errVerifyChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errVerifyChan {
			builder.WriteString(err.Error())
			if count < len(errVerifyChan)-1 {
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

	render := BuildRender(accessToken.Claims.Scopes)

	var (
		wgPersist sync.WaitGroup

		session uxsession.UxSession
		token   uxsession.AccessToken

		errPersistChan = make(chan error, 2)
	)

	wgPersist.Add(1)
	go func(session *uxsession.UxSession, ch chan error, wg *sync.WaitGroup) {
		defer wgPersist.Done()

		// build and persist new authenticated session
		s, err := h.uxSession.Build(uxsession.Authenticated)
		if err != nil {
			ch <- fmt.Errorf("failed to create session: %v", err)
			return
		}

		*session = *s
	}(&session, errPersistChan, &wgPersist)

	// persist access/refresh tokens
	wgPersist.Add(1)
	go func(access *provider.UserAuthorization, tok *uxsession.AccessToken, ch chan error, wg *sync.WaitGroup) {
		defer wgPersist.Done()

		a, err := h.uxSession.PersistToken(access)
		if err != nil {
			ch <- fmt.Errorf("failed to persist access token: %v", err)
			return
		}

		*tok = *a

	}(&access, &token, errPersistChan, &wgPersist)

	wgPersist.Wait()
	close(errPersistChan)

	if len(errPersistChan) > 0 {
		var builder strings.Builder
		count := 0
		for err := range errPersistChan {
			builder.WriteString(err.Error())
			if count < len(errPersistChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		h.logger.Error("failed to build authenticated session", "err", builder.String())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to persist callback session",
		}
		e.SendJsonErr(w)
		return
	}

	// perist xref between session and access/refresh tokens
	xref := uxsession.SessionAccessXref{
		UxsessionId:   session.Id,
		AccessTokenId: token.Id,
	}

	if err := h.uxSession.PersistXref(xref); err != nil {
		h.logger.Error("failed to persist session access xref", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to persist session access xref",
		}
		e.SendJsonErr(w)
		return
	}

	// // destroy previous anonymous session
	// // do not wait to return callback response
	// go func() {
	// 	if err := h.uxSession.DestroySession(cmd.Session); err != nil {
	// 		h.logger.Error("failed to destroy anonymous session", "err", err.Error())
	// 		return
	// 	}
	// }()

	// return authentication data
	response := CallbackResponse{
		Session:       session.SessionToken,
		Authenticated: session.Authenticated,

		Username:   idToken.Claims.Email,
		Fullname:   idToken.Claims.Name,
		GivenName:  idToken.Claims.GivenName,
		FamilyName: idToken.Claims.FamilyName,
		// Birthdate: idToken.Claims.Birthdate,

		Ux: render,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode callback response to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode callback response to json",
		}
		e.SendJsonErr(w)
		return
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
