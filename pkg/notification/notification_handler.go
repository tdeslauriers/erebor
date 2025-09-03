package notification

import (
	"encoding/json"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/storage"
)

// required scopes for upload notification
var requiredScopes = []string{"w:erebor:*", "w:erebor:images:notify:upload:*"}

// Handler handles external service notification-related operations.
type Handler interface {

	// HandleImageUploadNotification handles notifications of image uploads from the object storage service.
	HandleImageUploadNotification(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new instance of Handler, returning a pointer to the concrete implementation.
func NewHandler(p provider.S2sTokenProvider, g connect.S2sCaller, pat pat.Verifier) Handler {
	return &handler{
		token:   p,
		gallery: g,
		pat:     pat,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceGateway)).
			With(slog.String(util.PackageKey, util.PackageNotification)).
			With(slog.String(util.ComponentKey, util.ComponentNotificationHandler)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	token   provider.S2sTokenProvider
	gallery connect.S2sCaller
	pat     pat.Verifier

	logger *slog.Logger
}

// HandleImageUploadNotification is a concrete implementation of the Handler interface method which
// handles notifications of image uploads from the object storage service.
func (h *handler) HandleImageUploadNotification(w http.ResponseWriter, r *http.Request) {

	// validate method
	if r.Method != http.MethodPost {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// TODO: add pat validation call
	pat := r.Header.Get("Authorization")

	// clip "Bearer " prefix if present
	if len(pat) > 7 && pat[0:7] == "Bearer " {
		pat = pat[7:]
	}

	// validate the PAT
	authorized, err := h.pat.BuildAuthorized(requiredScopes, pat)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate PAT in image upload notification request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to validate PAT",
		}
		e.SendJsonErr(w)
		return
	}

	// decode the request body
	var webhook storage.WebhookPutObject
	if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode JSON in image upload notification request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "improperly formatted json in webhook request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the webhook payload
	if err := webhook.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid webhook payload in image upload notification request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	h.logger.Info(fmt.Sprintf("%s sent push notification that %s was uploaded to bucket %s: forwarding to gallery service",
		authorized.ServiceName, webhook.MinioKey, webhook.Records[0].S3.Bucket.Name))

	// get s2s token for gallery service
	s2sToken, err := h.token.GetServiceToken(util.ServiceGallery)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get s2s token for gallery service: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get s2s token for gallery service",
		}
		e.SendJsonErr(w)
		return
	}

	// send notification to gallery service
	if err := h.gallery.PostToService("/images/notify/upload", s2sToken, pat, webhook, nil); err != nil {
		h.logger.Error(fmt.Sprintf("failed to notify gallery service of image upload: %s", err.Error()))
		h.gallery.RespondUpstreamError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("successfully notified gallery service of image upload %s", webhook.MinioKey))

	w.WriteHeader(http.StatusOK)
	return
}
