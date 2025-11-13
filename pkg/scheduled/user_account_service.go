package scheduled

import (
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/pixie/pkg/patron"
)

// UserAccountService is an interface that defines the methods available for scheduled tasks.
type UserAccountService interface {

	// ReconcileGalleryAccounts is a method that creates any missing
	// gallery ghost acocunts (patrons) for users that have registered
	ReconcileGalleryAccounts()
}

// NewUserAccountService returns a new instance of ScheduledService.
func NewUserAccountService(tkn provider.S2sTokenProvider, iam, g *connect.S2sCaller) UserAccountService {
	return &userAccountService{
		token:    tkn,
		identity: iam,
		gallery:  g,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageScheduled)).
			With(slog.String(util.ComponentKey, util.ComponentScheduledUserAccount)).
			With(slog.String(util.ServiceKey, util.ServiceGateway)),
	}
}

var _ UserAccountService = (*userAccountService)(nil)

// userAccountService is the concrete implementation of the ScheduledService interface.
// It implements the methods defined in the ScheduledService interface.
type userAccountService struct {
	token    provider.S2sTokenProvider
	identity *connect.S2sCaller
	gallery  *connect.S2sCaller

	logger *slog.Logger
}

// ReconcileGalleryAccounts is the concrete implementation of the method that creates any missing
// gallery ghost accounts (patrons) for users that have registered.
func (s *userAccountService) ReconcileGalleryAccounts() {
	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {

			// using local time to make sure in low traffic conditions
			now := time.Now()

			// calc the next 3 am
			next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			jitter := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(jitter)

			duration := time.Until(next)
			s.logger.Info(fmt.Sprintf("next identity -> gallery user account reconcile will run at %s", next.Format(time.RFC3339)))

			timer := time.NewTimer(duration)
			<-timer.C

			// get users from identity service
			s2sIamToken, err := s.token.GetServiceToken(util.ServiceIdentity)
			if err != nil {
				s.logger.Error(fmt.Sprintf("failed to get service token for identity service: %s", err.Error()))
				continue
			}

			var users []profile.User
			if err := s.identity.GetServiceData("/s2s/users", s2sIamToken, "", &users); err != nil {
				s.logger.Error(fmt.Sprintf("failed to get users from identity service: %s", err.Error()))
				continue
			}

			s.logger.Info(fmt.Sprintf("reconciling %d gallery accounts", len(users)))
			for _, user := range users {
				// create ghost account in gallery service
				s2sGalleryToken, err := s.token.GetServiceToken(util.ServiceGallery)
				if err != nil {
					s.logger.Error(fmt.Sprintf("failed to get service token for gallery service: %s", err.Error()))
					continue
				}

				if err := s.gallery.PostToService("/s2s/patrons/register", s2sGalleryToken, "", patron.PatronRegisterCmd{Username: user.Username}, nil); err != nil {
					s.logger.Error(fmt.Sprintf("failed to create gallery patron for user %s: %s", user.Username, err.Error()))
					continue
				}

				s.logger.Info(fmt.Sprintf("gallery patron account successfully created for user %s", user.Username))
			}
		}
	}()
}
