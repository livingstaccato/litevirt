package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/firewall"
)

// TestNICGuardLabelValue (re-review m2): the label a daemon sets at start is
// derived from its build — its version, which a rolled-back host no longer
// reports — and is cleared on a host whose kernel refuses the per-NIC table,
// where no guard can be enforced.
func TestNICGuardLabelValue(t *testing.T) {
	if got := NICGuardLabelValue("v2", firewall.AppliedState{}); got != "v2" {
		t.Errorf("label for a build that enforces guards = %q, want its version", got)
	}
	if got := NICGuardLabelValue("v2", firewall.AppliedState{NICTableError: "Operation not supported"}); got != "" {
		t.Errorf("label for a host whose kernel refuses the per-NIC table = %q, want cleared", got)
	}
}
