package grpcapi

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// userWriteStatus is the status of a failed account write. A write the
// account moved under (corrosion.ErrUserAccountChanged: it was deleted or
// re-created while the write was prepared) is Aborted, which a caller may
// retry; a write that grants several accounts at once
// (corrosion.ErrUserMultiAccountGrant) is FailedPrecondition; anything else
// is Internal.
func userWriteStatus(err error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if errors.Is(err, corrosion.ErrUserAccountChanged) {
		return status.Errorf(codes.Aborted, "%s: %v; retry", msg, err)
	}
	if errors.Is(err, corrosion.ErrUserMultiAccountGrant) {
		return status.Errorf(codes.FailedPrecondition, "%s: %v: grant or loosen one account per write", msg, err)
	}
	return status.Errorf(codes.Internal, "%s: %v", msg, err)
}
