package gallery

import (
	"erebor/pkg/authentication/uxsession"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// Handler is a composite interface that aggregates all gallery-service-related handlers.
type Handler interface {
	AlbumHandler
	ImageHandler
	PermissionsHandler
}

// NewHandler creates a new instance of Handler, returning a pointer to the concrete implementation(s).
func NewHandler(ux uxsession.Service, p provider.S2sTokenProvider, g connect.S2sCaller) Handler {
	return &handler{
		AlbumHandler:       NewAlbumHandler(ux, p, g),
		ImageHandler:       NewImageHandler(ux, p, g),
		PermissionsHandler: NewPermissionsHandler(ux, p, g),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	AlbumHandler
	ImageHandler
	PermissionsHandler
}
