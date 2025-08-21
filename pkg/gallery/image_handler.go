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

// ImageHandler defines the interface for handling and forwarding image-related operations against the gallery service.
type ImageHandler interface {

	// HandleImage is a method that handles requests to the image/slug endpoint and forwards to the gallery service if necessary.
	HandleImage(w http.ResponseWriter, r *http.Request)
}

// NewImageHandler creates a new instance of ImageHandler, returning a pointer to the concrete implementation.
func NewImageHandler(ux uxsession.Service, p provider.S2sTokenProvider, g connect.S2sCaller) ImageHandler {

	return &imageHandler{
		ux:      ux,
		tkn:     p,
		gallery: g,

		logger: slog.Default().
			With(slog.String(util.SerivceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageGallery)).
			With(slog.String(util.ComponentKey, util.ComponentImages)),
	}
}

var _ ImageHandler = (*imageHandler)(nil)

// imageHandler implements the ImageHandler interface.
type imageHandler struct {
	ux      uxsession.Service
	tkn     provider.S2sTokenProvider
	gallery connect.S2sCaller

	logger *slog.Logger
}

// HandleImage in the concrete implementation of the interface method which handles requests to
// the image/slug endpoint and forwards them to the gallery service if necessary.
func (h *imageHandler) HandleImage(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.getImageData(w, r)
		return
	case http.MethodPut: // /images/slug --> slug will be the slug for PUTs
		h.updateImageData(w, r)
		return
	case http.MethodPost: // /images/upload --> upload will be the slug for POSTs
		h.postImageData(w, r)
		return
	default:
		errMsg := fmt.Sprintf("unsupported method %s", r.Method)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
	}
}

// getImageData handles the GET request to retrieve image data by slug.
func (h *imageHandler) getImageData(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on /images/slug get request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the template slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid image slug: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid template slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get service token
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

	var img api.ImageData
	if err := h.gallery.GetServiceData(fmt.Sprintf("/images/%s", slug), galleryToken, accessToken, &img); err != nil {
		h.logger.Error(fmt.Sprintf("failed to get image data for slug %s: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(img); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode image data to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateImageData handles the PUT request to update image data by slug.
func (h *imageHandler) updateImageData(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on /images/slug put request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get the template slug from the request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid image slug: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid template slug",
		}
		e.SendJsonErr(w)
		return
	}

	var cmd api.UpdateMetadataCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode JSON in image metadata update request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate image metadata update command: %s", err.Error()))
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

	// csrf token from the command
	cmd.Csrf = ""

	// get service token
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

	// post update cmd to gallery service
	if err := h.gallery.PostToService(fmt.Sprintf("/images/%s", slug), galleryToken, accessToken, cmd, nil); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update image data for slug %s: %s", slug, err.Error()))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("image data successfully updated for image slug %s", slug))
	w.WriteHeader(http.StatusNoContent) // 204 No Content
}

// postImageData handles the POST request to upload image data.
func (h *imageHandler) postImageData(w http.ResponseWriter, r *http.Request) {

	// get session token from the request header
	session, err := connect.GetSessionToken(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("invalid session token on /images/upload post request: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// get access token tied to the session
	// validates the session is active and authenticated
	accessToken, err := h.ux.GetAccessToken(session)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get access token from session token: %s", err.Error()))
		h.ux.HandleSessionErr(err, w)
		return
	}

	// getting the slug is unnecessary for /images/upload

	// get request body
	var cmd api.AddMetaDataCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode JSON in image upload request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate image upload command: %s", err.Error()))
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

	// remove csrf token from the command
	cmd.Csrf = ""

	// get service token
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

	var data api.ImageData
	if err := h.gallery.PostToService("/images/upload", galleryToken, accessToken, cmd, &data); err != nil {
		h.logger.Error(fmt.Sprintf("failed to upload image data: %s", err.Error()))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("placeholder image data successfully created for slug %s", data.Slug))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode image data to JSON: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode image data to json",
		}
		e.SendJsonErr(w)
		return
	}
}
