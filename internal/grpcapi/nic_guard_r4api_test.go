package grpcapi

import "testing"

// TestNICGuardLabelValue (re-review m2, m5): the label a daemon sets after
// each firewall pass is derived from its build — its version, which a
// rolled-back host no longer reports — and is cleared while the per-NIC table
// is not proven in force (refused, failed or timed out).
func TestNICGuardLabelValue(t *testing.T) {
	if got := NICGuardLabelValue("v2", true); got != "v2" {
		t.Errorf("label for a host enforcing guards = %q, want its version", got)
	}
	if got := NICGuardLabelValue("v2", false); got != "" {
		t.Errorf("label for a host whose last pass did not put the per-NIC table in force = %q, want cleared", got)
	}
}
