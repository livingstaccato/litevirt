package grpcapi

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// An account write the account moved under is Aborted, which a caller may
// retry; a write granting several accounts at once is FailedPrecondition; any
// other failure stays Internal (re-review 2, M3; re-review 3, M1).
//
// Mutations: userWriteStatus always Internal — red; ErrUserMultiAccountGrant
// unmapped — red.
func TestUserWriteStatus_AccountChangedIsAborted(t *testing.T) {
	moved := fmt.Errorf("exec batch: %w", corrosion.ErrUserAccountChanged)
	if got := status.Code(userWriteStatus(moved, "create user")); got != codes.Aborted {
		t.Errorf("account changed: code %v, want Aborted", got)
	}
	if got := status.Code(userWriteStatus(corrosion.ErrUserMultiAccountGrant, "insert binding")); got != codes.FailedPrecondition {
		t.Errorf("multi-account grant: code %v, want FailedPrecondition", got)
	}
	if got := status.Code(userWriteStatus(errors.New("disk full"), "create user")); got != codes.Internal {
		t.Errorf("other failure: code %v, want Internal", got)
	}
}
