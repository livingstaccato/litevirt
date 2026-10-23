package fencessh

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// FailHostFenceSSHListForTest makes the cloned-key check's row listing fail
// with err, and returns the function that restores it.
func FailHostFenceSSHListForTest(err error) (restore func()) {
	prev := listHostFenceSSH
	listHostFenceSSH = func(context.Context, *corrosion.Client) ([]corrosion.HostFenceSSHRow, error) { return nil, err }
	return func() { listHostFenceSSH = prev }
}

// ProbeTimeoutForTest and FreshWindowForTest let the external tests size a
// re-evaluation's bound around the self-check's window.
const (
	ProbeTimeoutForTest = probeTimeout
	FreshWindowForTest  = freshSelfCheckWindow
)
