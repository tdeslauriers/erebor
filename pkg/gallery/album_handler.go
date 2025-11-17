package gallery

import (
	"context"
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/pixie/pkg/api"
)

// AlbumHandler is an interface that defines methods for handling album-related operations.
type AlbumHandler interface {
	// HandleAlbum is a method that handles requests to the /album/{slug...} endpoint and
	// forwards to the gallery service if necessary.
	HandleAlbums(w http.ResponseWriter, r *http.Request)
}

// NewAlbumHandler creates a new instance of AlbumHandler, returning a pointer to the concrete implementation.
func NewAlbumHandler(ux uxsession.Service, p provider.S2sTokenProvider, g *connect.S2sCaller) AlbumHandler {
	return &albumHandler{
		ux:      ux,
		tkn:     p,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageGallery)).
			With(slog.String(util.ComponentKey, util.ComponentAlbums)),
	}
}

var _ AlbumHandler = (*albumHandler)(nil)

// albumHandler implements the AlbumHandler interface.
type albumHandler struct {
	ux      uxsession.Service
	tkn     provider.S2sTokenProvider
	gallery *connect.S2sCaller

	logger *slog.Logger
}

// HandleAlbums in the concrete implementation of the interface method which handles requests to
// the albums endpoint and forwards them to the gallery service if necessary.
func (h *albumHandler) HandleAlbums(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r)
	log := h.logger.With(tel.TelemetryFields()...)

	switch r.Method {
	case http.MethodGet:

		// check for a slug -> get all vs get one
		// get slug if it exists
		slug := r.PathValue("slug")
		if slug == "" {

			h.getAlbums(w, r, tel, log)
			return
		} else {
			h.getAlbum(w, r, tel, log)
			return
		}
	case http.MethodPost:
		h.postAlbum(w, r, tel, log)
		return
	case http.MethodPut:
		h.updateAlbum(w, r, tel, log)
		return
	// case http.MethodDelete:
	// 	h.deleteAlbum(w, r)
	// 	return
	default:

		return
	}
}

// getAlbums handles the GET request to retrieve albums.
func (h *albumHandler) getAlbums(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to get access token from session token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the service token for the gallery service
	galleryToken, err := h.tkn.GetServiceToken(ctx, util.ServiceGallery)
	if err != nil {
		log.Error("failed to get service token for gallery service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service to get the albums
	albums, err := connect.GetServiceData[[]api.Album](
		ctx,
		h.gallery,
		"/albums",
		galleryToken,
		accessToken,
	)
	if err != nil {
		log.Error("failed to get albums from gallery service", "err", err.Error())
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d albums", len(albums)))

	// respond with the retrieved albums
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // 200 OK
	if err := json.NewEncoder(w).Encode(albums); err != nil {
		log.Error("failed to encode albums to JSON:", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode albums to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getAlbum handles the GET request to retrieve a specific album by slug.
func (h *albumHandler) getAlbum(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the album slug from the request URL
	// get the slug to determine if user is going to /albums/staged or /albums/{slug}
	slug := r.PathValue("slug")

	if slug == "" || (slug != "staged" && !validate.IsValidUuid(slug)) {
		log.Error("invalid album slug submitted to gateway")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid album slug submitted to gateway",
		}
		e.SendJsonErr(w)
		return
	}

	// get service token for gallery service
	galleryToken, err := h.tkn.GetServiceToken(ctx, util.ServiceGallery)
	if err != nil {
		log.Error("failed to get service token for gallery service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// get alubm data from gallery service
	albumData, err := connect.GetServiceData[api.Album](
		ctx,
		h.gallery,
		fmt.Sprintf("/albums/%s", slug),
		galleryToken,
		accessToken,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get album data for slug %s", slug), "err", err.Error())
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved album data for slug %s", slug))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(albumData); err != nil {
		log.Error("failed to encode album data to JSON", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode album data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateAlbum handles the PUT request to update an existing album.
func (h *albumHandler) updateAlbum(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the album slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("invalid album slug", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid album slug",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body into an album update command
	var cmd api.AlbumUpdateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode JSON in album update request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate album update command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid session or csrf token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command before sending to the gallery service
	cmd.Csrf = ""

	// get the service token for the gallery service
	galleryToken, err := h.tkn.GetServiceToken(ctx, util.ServiceGallery)
	if err != nil {
		log.Error("internal service error for gallery service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get service token",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service to update the album
	_, err = connect.PutToService[api.AlbumUpdateCmd, struct{}](
		ctx,
		h.gallery,
		fmt.Sprintf("/albums/%s", slug),
		galleryToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update album with slug %s", slug), "err", err.Error())
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	// log the successful album update
	log.Info(fmt.Sprintf("album '%s' successfully updated", slug))

	// respond with a success message
	w.WriteHeader(http.StatusNoContent) // 204 No Content
}

// postAlbum handles the POST request to create a new album.
func (h *albumHandler) postAlbum(w http.ResponseWriter, r *http.Request, tel *connect.Telemetry, log *slog.Logger) {

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		log.Error("failed to get session token from request")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(ctx, session)
	if err != nil {
		log.Error("failed to exchange session token for access token", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// decode the request body into an album creation command
	var cmd api.AddAlbumCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode JSON in album creation request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate album creation command", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		log.Error("invalid session or csrf token:", "err", err.Error())
		h.ux.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command before sending to the gallery service
	cmd.Csrf = ""

	// get the service token for the gallery service
	galleryToken, err := h.tkn.GetServiceToken(ctx, util.ServiceGallery)
	if err != nil {
		log.Error("failed to get service token for gallery service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service to create the album
	created, err := connect.PostToService[api.AddAlbumCmd, api.Album](
		ctx,
		h.gallery,
		"/albums",
		galleryToken,
		accessToken,
		cmd,
	)
	if err != nil {
		log.Error("failed to create album in gallery service", "err", err.Error())
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	// log the successful album creation
	log.Info(fmt.Sprintf("album '%s' successfully created", created.Title))

	// respond with the created album
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201 Created
	if err := json.NewEncoder(w).Encode(created); err != nil {
		log.Error("failed to encode created album to JSON", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode created album to json",
		}
		e.SendJsonErr(w)
		return
	}
}
