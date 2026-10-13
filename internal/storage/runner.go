package storage

import (
	"context"
	"errors"

	"github.com/litevirt/litevirt/internal/cmdbound"
)

// ErrUnimplemented is returned by a driver operation that has no implementation
// yet, so callers fail loudly instead of acting on a half-provisioned resource.
var ErrUnimplemented = errors.New("storage: operation not implemented")

// cmdRunner runs an external command and returns its combined output. Drivers
// shell out to tool binaries (rbd, zfs, …); routing those calls through a
// runner lets tests exercise failure/rollback paths without the real binaries.
type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// realCmd is the production runner: an exec with combined output, bounded by
// ctx (cmdbound): at the deadline the command's whole process group is
// killed, and a child that still holds the output pipe (mount's mount.nfs,
// say) does not keep it waiting past cmdbound.WaitDelay.
func realCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	return cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, name, args...))
}
