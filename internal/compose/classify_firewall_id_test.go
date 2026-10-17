package compose

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A deploy's drift check ignores the stored firewall identity (D2a carry):
// the file never carries one (the server mints it, and every insert strips a
// client's), so a stored firewall_id is no change, and a tagged VM is not
// updated or re-created on every deploy.
//
// Mutation: compare firewall_id like any field — red.
func TestClassify_IgnoresTheFirewallID(t *testing.T) {
	desired := &pb.VMSpec{Name: "web", Image: "img", Cpu: 2, MemoryMib: 1024, GuestAgent: true}
	stored := &pb.VMSpec{Name: "web", Image: "img", Cpu: 2, MemoryMib: 1024, GuestAgent: true,
		FirewallId: "0123456789abcdef0123456789abcdef"}
	if p := Classify(desired, stored, nil); p.Max() != ActionNoChange {
		t.Fatalf("a stored firewall identity classifies as %v (%s), want no change", p.Max(), p.Reasons())
	}
}
