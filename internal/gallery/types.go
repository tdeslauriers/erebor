package gallery

import (
	"erebor/internal/authentication/uxsession"
	"erebor/internal/notification"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Handler is a composite interface that aggregates all gallery-service-related handlers.
type Handler interface {
	AlbumHandler
	ImageHandler
	notification.Handler
	PermissionsHandler
}

// NewHandler creates a new instance of Handler, returning a pointer to the concrete implementation(s).
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, g *connect.S2sCaller, pat pat.Verifier) Handler {
	return &handler{
		AlbumHandler:       NewAlbumHandler(ux, p, g),
		ImageHandler:       NewImageHandler(ux, p, g),
		Handler:            notification.NewHandler(p, g, pat),
		PermissionsHandler: NewPermissionsHandler(ux, p, g),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	AlbumHandler
	ImageHandler
	notification.Handler
	PermissionsHandler
}

// DeleteImageCmd is the model for issuing a delete image call to
// the gallery service
type DeleteImageCmd struct {
	Csrf string `json:"csrf"`
}

// Validate checks the DeleteImageCmd fields are well formed.
func (cmd *DeleteImageCmd) Validate() error {

	// check the csrf is a valid uuid
	if err := validate.ValidateUuid(cmd.Csrf); err != nil {
		return fmt.Errorf("invalid csrf token")
	}

	return nil
}
