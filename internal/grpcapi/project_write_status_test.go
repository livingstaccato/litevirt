package grpcapi

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A grant or quota the project moved under (deleted or re-created while it
// was prepared) is Aborted, which the caller may retry, not Internal.
//
// Mutation: ErrProjectChanged left out of userWriteStatus — red.
func TestUserWriteStatus_ProjectChangedIsAborted(t *testing.T) {
	err := userWriteStatus(fmt.Errorf("wrapped: %w", corrosion.ErrProjectChanged), "insert binding")
	if status.Code(err) != codes.Aborted {
		t.Fatalf("code = %v (%v), want Aborted", status.Code(err), err)
	}
}
