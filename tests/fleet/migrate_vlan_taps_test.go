package fleet

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A NIC's VLANs live on its host tap, not in the domain XML, so libvirt's live
// migration does not carry them: once the move commits, the TARGET puts them
// on the taps it made (AnnounceMigratedGuest) — the trunk converged to its two
// VLANs, the access port given its VLAN — and the source configures nothing
// for a guest that has left it.
//
// Mutation: drop reapplyVLANTapsOf from AnnounceMigratedGuest — red (the
// target's taps never get the VLANs).
func TestFleet_LiveMigrationPutsTheNICsVLANsOnTheTargetTaps(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetGatewayAnnouncer(func(string, netip.Addr) (bool, error) { return false, nil })
	}
	spec := `{"name":"vmover","cpu":1,"memory_mib":512,"network":[` +
		`{"name":"vt_trk","mac":"52:54:00:47:01:02","trunk":[100,101]},` +
		`{"name":"vt_acc","mac":"52:54:00:47:01:03","trunk":[30]}]}`
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "vmover", HostName: src.Name, State: "running", Spec: spec, CPUActual: 1, MemActual: 512,
	}, []corrosion.InterfaceRecord{
		{VMName: "vmover", NetworkName: "vt_trk", Ordinal: 0, MAC: "52:54:00:47:01:02"},
		{VMName: "vmover", NetworkName: "vt_acc", Ordinal: 1, MAC: "52:54:00:47:01:03"},
	}, nil); err != nil {
		t.Fatalf("seed vmover: %v", err)
	}
	src.Virt.SetState("vmover", "running")
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
		dst.Virt.SetState(name, "running")
		return nil
	}

	taps := func(n *Node) string {
		var out []string
		for _, e := range n.Virt.EventLog() {
			if e.Domain == "vmover" && (e.Op == "trunk-tap" || e.Op == "vlan-tap") {
				out = append(out, e.Op+" "+e.Note)
			}
		}
		return strings.Join(out, "; ")
	}
	before := taps(src)

	if err := migrateAt(t, c, src, "vmover", dst.Name); err != nil {
		t.Fatalf("migrate vmover to %s: %v", dst.Name, err)
	}
	eventually(t, 10*time.Second, dst.Name+" to put vmover's VLANs on its taps", func() bool {
		return strings.Contains(taps(dst), "vlan-tap")
	})
	got := taps(dst)
	for _, want := range []string{
		"trunk-tap bridge=vt_trk mac=52:54:00:47:01:02 vlans=[100 101]",
		"vlan-tap bridge=vt_acc mac=52:54:00:47:01:03 vlan=30",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%s (target) tap VLANs %q, want %q", dst.Name, got, want)
		}
	}
	if after := taps(src); after != before {
		t.Errorf("%s (source) configured taps for a guest that left it: %q", src.Name, after)
	}
}
