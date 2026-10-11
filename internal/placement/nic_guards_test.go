package placement

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestSelectBatch_RequireNICGuards (re-review m8, m2): a guarded VM is placed
// only on a host that enforces NIC guards — its daemon set the label to the
// version it still reports. A host rolled back to an older build keeps the
// label but reports another version, and is not chosen even when the scorer
// would prefer it.
func TestSelectBatch_RequireNICGuards(t *testing.T) {
	hosts, vms := regionHosts() // the scorer prefers the empty w1
	for i := range hosts {
		hosts[i].Version = "v2"
		hosts[i].Labels = map[string]string{corrosion.LabelNICGuards: "v2"}
	}
	hosts[2].Version = "v1" // w1 was rolled back; its label stayed
	got, err := SelectBatch(hosts, vms, nil, nil, nil, time.Time{}, []Request{
		{VMName: "vm", CPUNeeded: 2, MemMiBNeeded: 1024, RequireNICGuards: true},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if h := got["vm"].Host; h != "e1" && h != "e2" {
		t.Fatalf("a guarded VM was placed on %q, which does not enforce guards", h)
	}
	free, err := SelectBatch(hosts, vms, nil, nil, nil, time.Time{}, []Request{
		{VMName: "vm", CPUNeeded: 2, MemMiBNeeded: 1024},
	})
	if err != nil || free["vm"].Host != "w1" {
		t.Fatalf("precondition: an unguarded VM goes to w1 as before: %+v, %v", free["vm"], err)
	}
}
