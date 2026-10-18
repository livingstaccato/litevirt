// A hand-deleted NetBox address is re-created, and its lease re-pointed, only
// once netbox_ip_repoint_v1 has latched.
//
// The re-point is an UPDATE of ip_allocations.netbox_ip_id that a
// previous-release peer has no ledger entry for: its apply would fail closed and
// its replication watermark would stall. So while the token has not latched —
// for as long as any such peer is listening — the mirror only skips the dead
// address and reports the pass unconverged, and the statement never reaches a
// replication stream. Once latched, the address is re-created at the lease's
// address under the NIC's identity, the lease names the new object on every
// node, and the pass converges.

package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// repointStatementLogged reports whether n's replication log carries the
// lease re-point statement.
func repointStatementLogged(t *testing.T, n *Node) bool {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", n.Name, err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), "SET netbox_ip_id") {
			return true
		}
	}
	return false
}

func leaseAddressOn(t *testing.T, n *Node, mac string) int {
	t.Helper()
	leases, err := corrosion.ListNetBoxLeases(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leases {
		if strings.EqualFold(l.MAC, mac) {
			return l.NetBoxIPID
		}
	}
	t.Fatalf("%s holds no lease for %s", n.Name, mac)
	return 0
}

func TestMirrorRepointsADeadAddressOnlyOnceLatched(t *testing.T) {
	nb, c, gates := boundMirrorClusterGated(t, 2)
	n := c.Nodes[0]
	// The daemon's wiring: the gate reads the DURABLE latch.
	for _, node := range c.Nodes {
		g := gates[node.Name]
		node.DB.SetNetBoxRepointGate(func() bool {
			return g.DurablyLatched(capabilities.NetBoxIPRepointV1)
		})
	}

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	mac := nb.InterfaceMAC("vm-1", "eth0")
	dead := nb.InterfaceAddressID("vm-1", "eth0")
	if dead == 0 || leaseAddressOn(t, n, mac) != dead {
		t.Fatalf("precondition: vm-1's lease must name its mirrored address %d", dead)
	}
	nb.DeleteAddressDirect(dead)

	// Stage 1: not latched — a previous-release peer may be listening.
	m := &mirrorSweepCounter{sweepMetrics: newSweepMetrics()}
	n.Server.SetNetBoxMetrics(m)
	posts := nb.AddressPOSTs()
	mustSyncAllNodes(t, c)
	if got := nb.AddressPOSTs(); got != posts {
		t.Fatalf("%d address create(s) before netbox_ip_repoint_v1 latched", got-posts)
	}
	for _, node := range c.Nodes {
		if repointStatementLogged(t, node) {
			t.Fatalf("%s put the lease re-point on its replication stream before the latch; a "+
				"previous-release peer has no ledger entry for it", node.Name)
		}
		if got := leaseAddressOn(t, node, mac); got != dead {
			t.Fatalf("%s: lease re-pointed to %d before the latch", node.Name, got)
		}
	}
	if p := m.passes(); len(p) == 0 || p[len(p)-1] != "error" {
		t.Fatalf("passes %v: an unrepaired dead address must leave the pass unconverged", p)
	}

	// Stage 2: every node runs this build, and the token latches.
	ctx := context.Background()
	for _, node := range c.Nodes {
		if !gates[node.Name].Enforced(ctx, capabilities.NetBoxIPRepointV1) ||
			!gates[node.Name].DurablyLatched(capabilities.NetBoxIPRepointV1) {
			t.Fatalf("%s: netbox_ip_repoint_v1 did not latch with every node advertising it", node.Name)
		}
	}
	mustSyncAllNodes(t, c)

	repaired := nb.InterfaceAddressID("vm-1", "eth0")
	if repaired == 0 || repaired == dead {
		t.Fatalf("vm-1 eth0 carries address %d after the latch, want a re-created one", repaired)
	}
	for _, node := range c.Nodes {
		if got := leaseAddressOn(t, node, mac); got != repaired {
			t.Fatalf("%s: the lease names %d, want the re-created %d", node.Name, got, repaired)
		}
	}
	if !repointStatementLogged(t, n) {
		t.Fatal("the re-point was applied without reaching the replication log")
	}
	if got := nb.VMPrimaryIP4("vm-1"); got != repaired {
		t.Fatalf("primary_ip4 = %d, want the re-created %d", got, repaired)
	}
	if p := m.passes(); p[len(p)-1] != "ok" {
		t.Fatalf("passes %v: the repaired pass must converge", p)
	}
}
