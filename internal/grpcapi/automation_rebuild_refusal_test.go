package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRetainedManagedRebuildError(t *testing.T) {
	const secret = "SQL private retained payload"
	for _, tc := range []struct {
		name string
		err  error
		code codes.Code
	}{
		{"nil", nil, codes.OK},
		{"managed", corrosion.ErrRetainedManagedRebuild, codes.FailedPrecondition},
		{"wrapped-managed", fmt.Errorf("%s: %w", secret, corrosion.ErrRetainedManagedRebuild), codes.FailedPrecondition},
		{"canceled", fmt.Errorf("%s: %w", secret, context.Canceled), codes.Canceled},
		{"deadline", fmt.Errorf("%s: %w", secret, context.DeadlineExceeded), codes.DeadlineExceeded},
		{"grpc-canceled", status.Error(codes.Canceled, secret), codes.Canceled},
		{"grpc-deadline", status.Error(codes.DeadlineExceeded, secret), codes.DeadlineExceeded},
		{"raw-sql", errors.New(secret), codes.Unavailable},
		{"unknown-precondition", status.Error(codes.FailedPrecondition, secret), codes.Unavailable},
		{"sentinel-text-only", errors.New(corrosion.ErrRetainedManagedRebuild.Error()), codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := retainedManagedRebuildError(tc.err)
			if status.Code(got) != tc.code {
				t.Fatalf("code=%v want %v: %v", status.Code(got), tc.code, got)
			}
			if tc.err == nil && got != nil {
				t.Fatal("nil error changed", got)
			}
			if got != nil && strings.Contains(got.Error(), secret) {
				t.Fatal("adapter leaked private diagnostic")
			}
		})
	}
}
