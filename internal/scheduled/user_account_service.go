package scheduled

import (
	"context"
	"erebor/internal/authentication"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/pixie/pkg/api"
	"github.com/tdeslauriers/shaw/pkg/api/user"

	"erebor/gen"
)

// UserAccountService is an interface that defines the methods available for scheduled tasks.
type UserAccountService interface {

	// ReconcileGalleryAccounts is a method that creates any missing
	// gallery ghost acocunts (patrons) for users that have registered
	ReconcileGalleryAccounts()

	// ReconcileProfileAccounts is a method that creates any missing
	// profile ghost accounts (silhouettes) for users that have registered
	ReconcileProfileAccounts()
}

// NewUserAccountService returns a new instance of ScheduledService.
func NewUserAccountService(tkn provider.S2sTokenProvider, iam, g *connect.S2sCaller, p gen.ProfilesClient) UserAccountService {
	return &userAccountService{
		token:    tkn,
		identity: iam,
		gallery:  g,
		profile:  p,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageScheduled)).
			With(slog.String(util.ComponentKey, util.ComponentScheduledUserAccount)),
	}
}

var _ UserAccountService = (*userAccountService)(nil)

// userAccountService is the concrete implementation of the ScheduledService interface.
// It implements the methods defined in the ScheduledService interface.
type userAccountService struct {
	token    provider.S2sTokenProvider
	identity *connect.S2sCaller
	gallery  *connect.S2sCaller
	profile  gen.ProfilesClient

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

			// generate httpTelemetry -> in this case just a trace parent for web calls
			httpTelemetry := &connect.Telemetry{
				Traceparent: *connect.GenerateTraceParent(),
			}

			log := s.logger.With(httpTelemetry.TelemetryFields()...)

			// add telemetry to context for downstream calls
			ctx := context.WithValue(context.Background(), connect.TelemetryKey, httpTelemetry)

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
			log.Info(fmt.Sprintf("next identity -> gallery user account reconcile will run at %s", next.Format(time.RFC3339)))

			timer := time.NewTimer(duration)
			<-timer.C

			// get users from identity service
			s2sIamToken, err := s.token.GetServiceToken(ctx, util.ServiceIdentity)
			if err != nil {
				log.Error("failed to get service token for identity service", "err", err.Error())
				continue
			}

			// get users from identity service
			users, err := connect.GetServiceData[[]user.User](
				ctx,
				s.identity,
				"/s2s/users",
				s2sIamToken,
				"",
			)
			if err != nil {
				log.Error("failed to get users from identity service", "err", err.Error())
				continue
			}

			log.Info(fmt.Sprintf("reconciling %d gallery accounts", len(users)))
			s2sGalleryToken, err := s.token.GetServiceToken(ctx, util.ServiceGallery)
			for _, user := range users {

				// create ghost account in gallery service
				if err != nil {
					log.Error("failed to get service token for gallery service", "err", err.Error())
					continue
				}

				// post to gallery service to create patron ghost account for user
				_, err = connect.PostToService[api.PatronRegisterCmd, api.Patron](
					ctx,
					s.gallery,
					"/s2s/patrons/register",
					s2sGalleryToken,
					"",
					api.PatronRegisterCmd{Username: user.Username},
				)
				if err != nil {
					log.Error(fmt.Sprintf("failed to create gallery patron for user %s", user.Username), "err", err.Error())
					continue
				}

				log.Info(fmt.Sprintf("gallery patron account successfully created for user %s", user.Username))
			}
		}
	}()
}

// ReconcileProfileAccounts is the concrete implementation of the method that creates any missing
// profile ghost accounts (silhouettes) for users that have registered.
func (s *userAccountService) ReconcileProfileAccounts() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {

		for {

			// generate httpTelemetry -> in this case just a trace parent for web calls
			httpTelemetry := connect.NewTelemetry(nil, s.logger)

			log := s.logger.With(httpTelemetry.TelemetryFields()...)

			// add telemetry to context for downstream calls
			ctx := context.WithValue(context.Background(), connect.TelemetryKey, httpTelemetry)

			// using local time to make sure in low traffic conditions
			now := time.Now()

			// calc the next 3 am
			next := time.Date(now.Year(), now.Month(), now.Day(), 1, 0, 0, 0, now.Location())
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			jitter := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(jitter)

			duration := time.Until(next)
			log.Info(fmt.Sprintf("next identity -> profile account reconcile will run at %s", next.Format(time.RFC3339)))

			timer := time.NewTimer(duration)
			<-timer.C

			// get users from identity service
			s2sIamToken, err := s.token.GetServiceToken(ctx, util.ServiceIdentity)
			if err != nil {
				log.Error("failed to get service token for identity service", "err", err.Error())
				continue
			}

			// get users from identity service
			users, err := connect.GetServiceData[[]user.User](
				ctx,
				s.identity,
				"/s2s/users",
				s2sIamToken,
				"",
			)
			if err != nil {
				log.Error("failed to get users from identity service", "err", err.Error())
				continue
			}

			log.Info(fmt.Sprintf("reconciling %d profile accounts", len(users)))
			for _, user := range users {

				// call perfile service to create profile ghost account for user
				if _, err := s.profile.CreateProfile(
					ctx,
					&gen.CreateProfileRequest{
						Username: user.Username,
					},
					authentication.WithS2SOnly(),
				); err != nil {
					// log as warning since vast majority of time the user will already exist
					log.Warn(fmt.Sprintf("failed to create profile in profile service for user %s", user.Username),
						"err", err.Error(),
					)
					continue
				}

				log.Info(fmt.Sprintf("profile account successfully created for user %s", user.Username))
			}
		}
	}()

}
