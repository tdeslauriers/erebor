package notification

import (
	"encoding/json"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/storage"
)

// Handler handles external service notification-related operations.
type Handler interface {

	// HandleImageUploadNotification handles notifications of image uploads from the object storage service.
	HandleImageUploadNotification(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new instance of Handler, returning a pointer to the concrete implementation.
func NewHandler(p provider.S2sTokenProvider, s2s, g connect.S2sCaller) Handler {
	return &handler{
		token:   p,
		s2s:     s2s,
		gallery: g,

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
	s2s     connect.S2sCaller

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

	// TODO: send notification to gallery service

	w.WriteHeader(http.StatusNoContent)
	return

}
