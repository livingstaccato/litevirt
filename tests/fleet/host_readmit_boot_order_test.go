// Fleet scenario: a re-added host's boot write reaches a node before its
// admission does.
//
// `lv host add` admits the new machine on the node it runs on, and its daemon
// starts on an empty database moments later: it registers itself and writes
// its boot state. Replication carries those writes by relay, and a node whose
// direct link from the admitting node is slow can receive the new daemon's
// writes, relayed by a peer, before the admission itself. There they reached
// the old machine's TOMBSTONE: the boot write, a name-keyed full-PK UPDATE,
// stamped its newer updated_at onto a row that stayed deleted, and the
// admission, older, then lost the LWW gate. That node held a tombstone newer
// than every live copy, and anti-entropy, where a tombstone already wins a
// tie, carried it to every node: the new host was removed cluster-wide.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pumpRelayed pushes origin's own entries to `to` over relay's link, as relay
// does when it forwards origin's stream ahead of another origin's. (A relay
// pushes the entries as their origin wrote them.)
func pumpRelayed(t *testing.T, c *Cluster, origin, relay, to *Node) {
	t.Helper()
	ctx := context.Background()
	rows, err := origin.DB.Query(ctx,
		`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE origin = ? ORDER BY seq`, origin.Name)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", origin.Name, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s wrote nothing to relay", origin.Name)
	}
	entries := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq: r.Int64("seq"), Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts"),
		})
	}
	if _, err := c.PeerClient(relay, to).PushMutations(ctx, &pb.ReplicateRequest{
		Sender: relay.Name, SenderVersion: "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion), Entries: entries,
	}); err != nil {
		t.Fatalf("relay %s's entries %s→%s: %v", origin.Name, relay.Name, to.Name, err)
	}
}

// hostRowOf is n's copy of host's row: whether it is live, its serial and its
// state.
func hostRowOf(t *testing.T, n *Node, host string) (live bool, serial, state, updated string) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT deleted_at, cert_serial, state, updated_at FROM hosts WHERE name = ?`, host)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%s: read %s's row: %d %v", n.Name, host, len(rows), err)
	}
	r := rows[0]
	return r.String("deleted_at") == "", r.String("cert_serial"), r.String("state"), r.String("updated_at")
}

// TestFleet_BootWriteAheadOfAdmissionDoesNotRemoveTheHost: d is removed, then
// admitted again on a rebuilt machine through a. o receives the admission,
// then d's registration and boot write; b receives d's writes from o before
// a's admission reaches it. Once anti-entropy has run, every node must hold d
// LIVE, under its new certificate, in the state its boot wrote.
func TestFleet_BootWriteAheadOfAdmissionDoesNotRemoveTheHost(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4}) // scenario-steered: every delivery below is explicit
	a, b, o, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}

	// d dies and is removed for good; every survivor applies the removal.
	d.Stop()
	if err := corrosion.DeleteHost(ctx, a.DB, d.Name); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, o)
	for _, n := range []*Node{a, b, o} {
		if live, _, _, _ := hostRowOf(t, n, d.Name); live {
			t.Fatalf("fixture: %s still holds %s live after the removal", n.Name, d.Name)
		}
	}

	// The machine is rebuilt and admitted through a; only o hears of it.
	serial := rebuildWithEmptyDB(t, c, d, a)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: serial,
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	pumpMutations(t, c, a, o)

	// d's daemon starts: it registers itself and writes its boot state. o
	// takes d's writes, and relays them to b ahead of a's admission.
	bootRebuiltNode(t, d, serial)
	pumpMutations(t, c, d, o)
	pumpRelayed(t, c, d, o, b)
	pumpMutations(t, c, a, b)

	convergeByAntiEntropy(t, c, 2*convergeTimeout)

	for _, n := range c.Nodes {
		live, got, state, updated := hostRowOf(t, n, d.Name)
		if !live || got != serial || state != "active" {
			dump, _ := json.Marshal(map[string]any{"live": live, "serial": got, "state": state, "updated_at": updated})
			t.Errorf("%s holds the re-added %s as %s; want it live under serial %s and active — a boot "+
				"write that reached the old machine's tombstone first must not leave a tombstone newer "+
				"than the admission", n.Name, d.Name, dump, serial)
		}
	}
}
