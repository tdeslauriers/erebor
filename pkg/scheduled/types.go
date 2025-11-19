package scheduled

import (
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/schedule"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// Service is an aggregate interface that defines the methods available for scheduled tasks
// by consolidating the various task-related interfaces.
type Service interface {
	exo.Cleanup
	UserAccountService
}

// NewService returns a new instance of Service, which is an aggregate interface
// that combines the methods from exo.Cleanup and ScheduledService.
func NewService(sql data.SqlRepository, tkn provider.S2sTokenProvider, iam, g *connect.S2sCaller) Service {
	return &service{
		Cleanup:            exo.NewCleanup(sql),
		UserAccountService: NewUserAccountService(tkn, iam, g),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface.
type service struct {
	exo.Cleanup
	UserAccountService
}
