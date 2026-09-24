package compose

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A stack deployed before undeclared NIC networks resolved to the cluster
// network stored its NIC as "<stack>_<name>". Re-applying the same file now
// asks for "<name>". That is the same NIC moving to the right bridge, not a
// new VM: it must not classify as a network-topology change, because every
// update strategy applies a recreate by deleting the VM and its disks.
func TestClassify_StackScopedNICToClusterNetworkIsARetargetNotARecreate(t *testing.T) {
	st := baseSpec()
	st.StackName = "hc"
	st.Network = []*pb.NetworkAttachment{{Name: "hc_hc", Model: "virtio", Mac: "52:54:00:aa:bb:01"}}
	d := baseSpec()
	d.StackName = "hc"
	d.Network = []*pb.NetworkAttachment{{Name: "hc"}}

	p := Classify(d, st, StoredDisksFromSpec(st))
	if len(p.RecreateReasons) != 0 {
		t.Fatalf("recreate reasons %v for a NIC moving from hc_hc to hc", p.RecreateReasons)
	}
	if len(p.NICRetargets) != 1 {
		t.Fatalf("NICRetargets = %+v, want one (nic 0 hc_hc→hc)", p.NICRetargets)
	}
	if r := p.NICRetargets[0]; r.Ordinal != 0 || r.From != "hc_hc" || r.To != "hc" {
		t.Errorf("retarget = %+v, want nic 0 hc_hc→hc", r)
	}
	if got := p.Max(); got != ActionLive {
		t.Errorf("Max() = %v, want live (the NIC is re-plugged in place)", got)
	}
	if !strings.Contains(p.Reasons(), "hc_hc→hc") {
		t.Errorf("Reasons() = %q does not say the NIC moves", p.Reasons())
	}
}

// Anything else that renames a NIC's network is still a topology change.
func TestClassify_OtherNICNetworkChangesStillRecreate(t *testing.T) {
	for _, tc := range []struct{ stored, desired string }{
		{"hc_lan", "wan"},  // different network, not the stack-scoped form
		{"other_hc", "hc"}, // another stack's scope
		{"hc", "hc_hc"},    // the reverse direction
	} {
		st := baseSpec()
		st.StackName = "hc"
		st.Network = []*pb.NetworkAttachment{{Name: tc.stored}}
		d := baseSpec()
		d.StackName = "hc"
		d.Network = []*pb.NetworkAttachment{{Name: tc.desired}}
		p := Classify(d, st, StoredDisksFromSpec(st))
		if p.Max() != ActionRecreate || len(p.NICRetargets) != 0 {
			t.Errorf("%s→%s: Max()=%v retargets=%+v, want a recreate and no retarget",
				tc.stored, tc.desired, p.Max(), p.NICRetargets)
		}
	}
}
