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
// retry; any other failure stays Internal (re-review 2, M3).
//
// Mutation: userWriteStatus always Internal — red.
func TestUserWriteStatus_AccountChangedIsAborted(t *testing.T) {
	moved := fmt.Errorf("exec batch: %w", corrosion.ErrUserAccountChanged)
	if got := status.Code(userWriteStatus(moved, "create user")); got != codes.Aborted {
		t.Errorf("account changed: code %v, want Aborted", got)
	}
	if got := status.Code(userWriteStatus(errors.New("disk full"), "create user")); got != codes.Internal {
		t.Errorf("other failure: code %v, want Internal", got)
	}
}
