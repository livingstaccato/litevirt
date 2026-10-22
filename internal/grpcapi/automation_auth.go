package grpcapi

import (
	"context"
	"errors"
	"github.com/litevirt/litevirt/internal/corrosion"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type automationPrincipalContextKey struct{}
type verifiedAutomationPrincipal struct {
	clusterUID, principalUID string
	session                  *corrosion.AutomationOwnerSession
}

func callerAutomationPrincipal(ctx context.Context) (verifiedAutomationPrincipal, bool) {
	if ctx == nil {
		return verifiedAutomationPrincipal{}, false
	}
	p, ok := ctx.Value(automationPrincipalContextKey{}).(verifiedAutomationPrincipal)
	return p, ok && p.clusterUID != "" && p.principalUID != ""
}

func clearAutomationPrincipal(ctx context.Context) context.Context {
	return context.WithValue(ctx, automationPrincipalContextKey{}, verifiedAutomationPrincipal{})
}

func automationCredentialUnavailable(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return status.Error(codes.Unavailable, "automation credential proof unavailable; retry login")
}
