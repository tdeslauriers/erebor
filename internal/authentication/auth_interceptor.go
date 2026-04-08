package authentication

import (
	"context"
	"erebor/internal/authentication/uxsession"
	"erebor/internal/util"
	"fmt"
	"log/slog"
	"strings"

	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// AuthInterceptor is an interface that defines methods for authentication interceptors
// to apply to client grpc calls.
type AuthInterceptor interface {

	// Unary returns a unary client interceptor that applies authentication to unary grpc calls.
	Unary() grpc.UnaryClientInterceptor
}

// NewAuthInterceptor creates a new instance of the AuthInterceptor, returning
// a pointer to the concrete implementation.
func NewAuthInterceptor(p provider.S2sTokenProvider, s uxsession.Service) *authInterceptor {
	return &authInterceptor{
		tknProvider: p,
		session:     s,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAuth)).
			With(slog.String(util.ComponentKey, util.ComponentAuthInterceptor)),
	}
}

var _ AuthInterceptor = (*authInterceptor)(nil)

// authInterceptor is the concrete implementation of the AuthInterceptor interface which
// defines methods for authentication interceptors to apply to client grpc calls.
type authInterceptor struct {
	tknProvider provider.S2sTokenProvider
	session     uxsession.Service

	logger *slog.Logger
}

// Unary returns a unary client interceptor that applies authentication to unary grpc calls.
// in this implementation, it adds a the s2s and iam jwts to the grpc metadata.
func (a *authInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		// introspect the method to determine service name and method name
		grpcSvcName, methodName := parseMethod(method)

		// get telemetry
		telemetry, ok := exo.GetTelemetryFromContext(ctx)
		if !ok {
			a.logger.Error("failed to extract telemetry from context in client auth interceptor")
		}
		log := a.logger.With(telemetry.TelemetryFields()...)

		// extract auth mode from options to determine if user token is required
		// and if so, pull session from options
		mode := AuthModeDefault
		var session string
		for _, opt := range opts {
			if authOpt, ok := opt.(*AuthOption); ok {
				mode = authOpt.Mode
				session = authOpt.Session
				break
			}
		}

		svcName, err := parseServiceName(grpcSvcName)
		if err != nil {
			log.Error(fmt.Sprintf("failed to parse service name from grpc service name: %s", grpcSvcName),
				"err", err.Error(),
			)
			return err
		}

		// set service token
		s2sToken, err := a.tknProvider.GetServiceToken(ctx, svcName)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get s2s token for %s %s call", grpcSvcName, methodName),
				"err", err.Error(),
			)
			return err
		}

		// create metadata with tokens
		ctx = metadata.AppendToOutgoingContext(ctx,
			"service-authorization", fmt.Sprintf("Bearer %s", s2sToken),
		)

		// determine if user token is required
		switch mode {
		case AuthModeS2SOnly:
			// don't add user token, proceed
		default: // should be the case almost always

			// check if session is empty:  it should never be, but just in case
			if session == "" {
				log.Error(fmt.Sprintf("failed to provide session token to %s %s grpc client call", grpcSvcName, methodName))
				return fmt.Errorf("session required for user token")
			}

			// get user token from session service
			userToken, err := a.session.GetAccessToken(ctx, session)
			if err != nil {
				log.Error(fmt.Sprintf("failed to get user token for %s %s call", grpcSvcName, methodName),
					"err", err.Error(),
				)
				return fmt.Errorf("user token required: %w", err)
			}

			ctx = metadata.AppendToOutgoingContext(ctx,
				"authorization", fmt.Sprintf("Bearer %s", userToken),
			)
		}

		// proceed with invoker
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// parseMethod extracts service and method name from full gRPC method string
func parseMethod(fullMethod string) (service, method string) {

	// Remove leading '/' if it exists
	if len(fullMethod) > 0 && fullMethod[0] == '/' {
		fullMethod = fullMethod[1:]
	}

	// Split by '/'
	parts := []rune(fullMethod)
	lastSlash := -1
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '/' {
			lastSlash = i
			break
		}
	}

	// remove last slash
	if lastSlash == -1 {
		return "", ""
	}

	service = string(parts[:lastSlash])
	method = string(parts[lastSlash+1:])

	return service, method
}

// helper method to get the service name from the full grpc service name
// e.g., com.silhouette.api.v1.Profiles -> silhouette
func parseServiceName(grpcSvcName string) (string, error) {

	// split by '.'
	parts := strings.Split(grpcSvcName, ".")

	// service name should be the second to last part of the grpc service name
	// validate there are enough parts to extract service name
	// it should never happen that they're are not, but just in case
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid grpc service name: %s", grpcSvcName)
	}

	return parts[1], nil
}

// used to determine if call method is s2s only or if a user token is required
type authMode int

const (
	AuthModeDefault authMode = iota
	AuthModeS2SOnly
	AuthModeUserRequired
)

// authOption is a grpc.CallOption that specifies the authentication mode for a gRPC call.
type AuthOption struct {
	grpc.EmptyCallOption
	Mode    authMode // custom field to hold auth mode so the interceptor can read it
	Session string   // custom field to hold the ux session if auth mode requires user token
}

func WithS2SOnly() grpc.CallOption {
	return &AuthOption{Mode: AuthModeS2SOnly}
}

func WithUserRequired(session string) grpc.CallOption {
	return &AuthOption{
		Mode:    AuthModeUserRequired,
		Session: session,
	}
}
