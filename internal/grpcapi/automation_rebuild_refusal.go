package grpcapi

import (
	"context"
	"errors"

	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Only the actual owner calls this after permission and forwarding, before any
// LUN/runtime/storage effects. No public automation activation check may bypass it.
func (s *Server) retainedManagedRebuildRefusal(ctx context.Context, name string) error {
	return retainedManagedRebuildError(s.db.CheckRetainedManagedRebuildRefusal(ctx, name))
}

func retainedManagedRebuildError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled:
		return status.Error(codes.Canceled, "rebuild request canceled")
	case errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded:
		return status.Error(codes.DeadlineExceeded, "rebuild request deadline exceeded")
	case errors.Is(err, corrosion.ErrRetainedManagedRebuild):
		return status.Error(codes.FailedPrecondition, "managed VM cannot be rebuilt through the native API")
	default:
		return status.Error(codes.Unavailable, "retained automation state unavailable for rebuild")
	}
}
