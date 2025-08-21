package gallery

import (
	"encoding/json"
	"erebor/internal/util"
	"erebor/pkg/authentication/uxsession"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/pixie/pkg/api"
)

// AlbumHandler is an interface that defines methods for handling album-related operations.
type AlbumHandler interface {
	// HandleAlbum is a method that handles requests to the /album/slug endpoint and
	// forwards to the gallery service if necessary.
	HandleAlbums(w http.ResponseWriter, r *http.Request)

	// HandleAlbum is a method that handles requests to the /albums/slug endpoint and
	// forwards to the gallery service if necessary.
	HandleAlbum(w http.ResponseWriter, r *http.Request)
}

// NewAlbumHandler creates a new instance of AlbumHandler, returning a pointer to the concrete implementation.
func NewAlbumHandler(ux uxsession.Service, p provider.S2sTokenProvider, g connect.S2sCaller) AlbumHandler {
	return &albumHandler{
		ux:      ux,
		tkn:     p,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageGallery)).
			With(slog.String(util.ComponentKey, util.ComponentAlbums)),
	}
}

var _ AlbumHandler = (*albumHandler)(nil)

// albumHandler implements the AlbumHandler interface.
type albumHandler struct {
	ux      uxsession.Service
	tkn     provider.S2sTokenProvider
	gallery connect.S2sCaller

	logger *slog.Logger
}

// HandleAlbum in the concrete implementation of the interface method which handles requests to
// the /albums/slug endpoint and forwards them to the gallery service if necessary.
func (h *albumHandler) HandleAlbum(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getAlbum(w, r)
		return
	case http.MethodPut:
		h.updateAlbum(w, r)
		return
	default:
		h.logger.Error("unsupported method for /albums/slug endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s", r.Method),
		}
		e.SendJsonErr(w)
		return
	}

}

// HandleAlbums in the concrete implementation of the interface method which handles requests to
// the albums endpoint and forwards them to the gallery service if necessary.
func (h *albumHandler) HandleAlbums(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getAlbums(w, r)
		return
	case http.MethodPost:
		h.postAlbum(w, r)
		return
	// case http.MethodPut:
	// 	h.updateAlbum(w, r)
	// 	return
	// case http.MethodDelete:
	// 	h.deleteAlbum(w, r)
	// 	return
	default:
		h.logger.Error("unsupported method for /albums endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s", r.Method),
		}
		e.SendJsonErr(w)
		return
	}
}

// getAlbums handles the GET request to retrieve albums.
func (h *albumHandler) getAlbums(w http.ResponseWriter, r *http.Request) {

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to get session token from request")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the service token for the gallery service
	galleryToken, err := h.tkn.GetServiceToken(util.ServiceGallery)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for gallery service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get service token",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service to get the albums
	var albums []api.Album
	if err := h.gallery.GetServiceData("/albums", galleryToken, accessToken, &albums); err != nil {
		h.logger.Error(fmt.Sprintf("failed to retrieve albums: %s", err.Error()))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	// respond with the retrieved albums
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // 200 OK
	if err := json.NewEncoder(w).Encode(albums); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode albums to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode albums to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getAlbum handles the GET request to retrieve a specific album by slug.
func (h *albumHandler) getAlbum(w http.ResponseWriter, r *http.Request) {

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to get session token from request")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the album slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid album slug: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid album slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get service token for gallery service
	galleryToken, err := h.tkn.GetServiceToken(util.ServiceGallery)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for gallery service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	var albumData api.Album
	if err := h.gallery.GetServiceData(fmt.Sprintf("/albums/%s", slug), galleryToken, accessToken, &albumData); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get album data for slug %s: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(albumData); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode album data to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode album data to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateAlbum handles the PUT request to update an existing album.
func (h *albumHandler) updateAlbum(w http.ResponseWriter, r *http.Request) {

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to get session token from request")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the album slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid album slug: %s", err.Error()))
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
		h.logger.Error(fmt.Sprintf("failed to decode JSON in album update request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate album update command: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid session or csrf token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command before sending to the gallery service
	cmd.Csrf = ""

	// get the service token for the gallery service
	galleryToken, err := h.tkn.GetServiceToken(util.ServiceGallery)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for gallery service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get service token",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service to update the album
	if err := h.gallery.PostToService(fmt.Sprintf("/albums/%s", slug), galleryToken, accessToken, cmd, nil); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update album: %s", err.Error()))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	// log the successful album update
	h.logger.Info(fmt.Sprintf("album '%s' successfully updated", slug))

	// respond with a success message
	w.WriteHeader(http.StatusNoContent) // 204 No Content
}

// postAlbum handles the POST request to create a new album.
func (h *albumHandler) postAlbum(w http.ResponseWriter, r *http.Request) {

	// get the session token from the request
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error("failed to get session token from request")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the access token tied to the session
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error("failed to get access token from session token")
		h.ux.HandleSessionErr(err, w)
		return
	}

	// decode the request body into an album creation command
	var cmd api.AddAlbumCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode JSON in album creation request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate album creation command: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate the csrf token
	if valid, err := h.ux.IsValidCsrf(session, cmd.Csrf); !valid {
		h.logger.Error(fmt.Sprintf("invalid session or csrf token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// remove the csrf token from the command before sending to the gallery service
	cmd.Csrf = ""

	// get the service token for the gallery service
	galleryToken, err := h.tkn.GetServiceToken(util.ServiceGallery)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get service token for gallery service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get service token",
		}
		e.SendJsonErr(w)
		return
	}

	// call the gallery service to create the album
	var created api.Album
	if err := h.gallery.PostToService("/albums", galleryToken, accessToken, cmd, &created); err != nil {
		h.logger.Error(fmt.Sprintf("failed to create album: %s", err.Error()))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	// log the successful album creation
	h.logger.Info(fmt.Sprintf("album '%' successfully created", created.Title))

	// respond with the created album
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201 Created
	if err := json.NewEncoder(w).Encode(created); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode created album to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode created album to json",
		}
		e.SendJsonErr(w)
		return
	}
}
