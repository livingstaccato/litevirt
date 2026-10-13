// Re-creating a snapshot under the name of a deleted one, and the general
// rule it broke: one change a peer cannot apply must not stop every later
// change from the same node reaching that peer.
//
// Observed on lab 2, 2026-10-12 (lab2-dnr-7e6e8625, F-2): `lv snapshot rm svm
// s1` and then `lv snapshot create svm s1` on node-3. A delete is a soft
// delete, so every peer kept the tombstoned row (id 88d51eb7, vm_name svm, name
// s1). The re-create minted a fresh id (cc3197e1) and replaced the tombstone
// locally (INSERT OR REPLACE resolves the UNIQUE(vm_name, name) conflict by
// deleting it), but on every peer the replicated INSERT met the tombstone's
// natural key and failed the UNIQUE. The receiver back-pressures any failed
// entry, so node-3's push stream stopped at that entry for good: every later
// write from node-3 reached its peers only through anti-entropy, and
// `snapshots` stayed divergent.
//
// The scenarios run the real spine: separate per-node databases, the real
// PushMutations RPC over mTLS, the real WAL apply, and a real anti-entropy
// pass for the convergence checks.
package fleet

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/google/uuid"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pushAll carries every mutation_log entry of `from` to `to` over the real
// PushMutations RPC and returns what the receiver answered. pumpMutations
// fails the test on an error; these scenarios need to SEE the refusal, since a
// refused push is the wedge.
func pushAll(t *testing.T, c *Cluster, from, to *Node) (int64, error) {
	t.Helper()
	ctx := context.Background()
	rows, err := from.DB.Query(ctx, `SELECT seq, hlc, origin, stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", from.Name, err)
	}
	entries := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq: r.Int64("seq"), Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts"),
		})
	}
	if len(entries) == 0 {
		return 0, nil
	}
	resp, err := c.PeerClient(from, to).PushMutations(ctx, &pb.ReplicateRequest{
		Sender:              from.Name,
		SenderVersion:       "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
		Entries:             entries,
	})
	if err != nil {
		return 0, err
	}
	return resp.AppliedUpTo, nil
}

// lastSeq is the newest mutation_log sequence on n.
func lastSeq(t *testing.T, n *Node) int64 {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT MAX(seq) AS s FROM mutation_log`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s mutation_log tail: %v", n.Name, err)
	}
	return rows[0].Int64("s")
}

// snapRow is every row n holds for (vm, name), live or not.
type snapRow struct{ id, deletedAt string }

func snapRows(t *testing.T, n *Node, vm, name string) []snapRow {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT id, COALESCE(deleted_at, '') AS deleted_at FROM snapshots WHERE vm_name = ? AND name = ?`, vm, name)
	if err != nil {
		t.Fatalf("read %s snapshots: %v", n.Name, err)
	}
	out := make([]snapRow, len(rows))
	for i, r := range rows {
		out[i] = snapRow{id: r.String("id"), deletedAt: r.String("deleted_at")}
	}
	return out
}

func createSnap(t *testing.T, n *Node, vm, name string) {
	t.Helper()
	if err := corrosion.InsertSnapshot(context.Background(), n.DB, corrosion.SnapshotRecord{
		VMName: vm, HostName: n.Name, Name: name, State: "ok", SizeBytes: 1,
	}); err != nil {
		t.Fatalf("InsertSnapshot %s/%s on %s: %v", vm, name, n.Name, err)
	}
}

func liveSnapID(t *testing.T, n *Node, vm, name string) string {
	t.Helper()
	s, err := corrosion.GetSnapshot(context.Background(), n.DB, vm, name)
	if err != nil {
		t.Fatalf("GetSnapshot %s/%s on %s: %v", vm, name, n.Name, err)
	}
	if s == nil {
		return ""
	}
	return s.ID
}

// The lab sequence, through the production builders: create, delete, create
// again under the same name, then an unrelated later write. The peer must
// accept the whole stream, hold the re-created snapshot LIVE (not hidden by
// the old tombstone), and agree with the origin about which row it is.
func TestFleet_SnapshotNameReuse_RecreateReplicatesAndDoesNotWedge(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	createSnap(t, a, "svm", "s1")
	firstID := liveSnapID(t, a, "svm", "s1")
	if _, err := pushAll(t, c, a, b); err != nil {
		t.Fatalf("first create did not replicate: %v", err)
	}
	if err := corrosion.DeleteSnapshot(ctx, a.DB, "svm", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := pushAll(t, c, a, b); err != nil {
		t.Fatalf("delete did not replicate: %v", err)
	}
	if id := liveSnapID(t, b, "svm", "s1"); id != "" {
		t.Fatalf("b still shows the deleted snapshot live: %s", id)
	}

	createSnap(t, a, "svm", "s1") // the re-create
	createSnap(t, a, "svm", "s2") // a later, unrelated write from the same node

	applied, err := pushAll(t, c, a, b)
	if err != nil {
		t.Fatalf("a's stream to b is wedged by the re-created snapshot: %v", err)
	}
	if want := lastSeq(t, a); applied != want {
		t.Fatalf("b acknowledged up to %d, want a's tail %d", applied, want)
	}
	if liveSnapID(t, b, "svm", "s2") == "" {
		t.Fatal("the write after the re-create never reached b")
	}
	aID, bID := liveSnapID(t, a, "svm", "s1"), liveSnapID(t, b, "svm", "s1")
	if aID == "" {
		t.Fatal("the re-created snapshot is not live on its origin")
	}
	// The origin takes the deleted row's id back. A fresh id is what an
	// older peer (one without the receiver-side tombstone yield) refuses for
	// ever, so this is what keeps a rolling upgrade from wedging.
	if aID != firstID {
		t.Fatalf("the re-create minted id %q instead of re-using the deleted row's %q", aID, firstID)
	}
	if bID != aID {
		t.Fatalf("b holds re-created s1 as %q, origin holds %q", bID, aID)
	}
	if rows := snapRows(t, b, "svm", "s1"); len(rows) != 1 || rows[0].deletedAt != "" {
		t.Fatalf("b's s1 rows after the re-create: %+v, want one live row", rows)
	}

	// Anti-entropy agrees: a pass in each direction changes nothing and the
	// origin keeps its snapshot live (the lab's image twin, F-1, was
	// re-tombstoned on its origin by exactly this pass).
	for _, pair := range [][2]*Node{{b, a}, {a, b}} {
		pair[0].DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: pair[1].Name}} })
		if !corrosion.NewAntiEntropy(pair[0].DB, pair[0].PKIDir, 0).RunOnce(ctx) {
			t.Fatalf("anti-entropy pass on %s did not run", pair[0].Name)
		}
	}
	for _, n := range []*Node{a, b} {
		if rows := snapRows(t, n, "svm", "s1"); len(rows) != 1 || rows[0].id != aID || rows[0].deletedAt != "" {
			t.Fatalf("%s's s1 rows after anti-entropy: %+v, want one live row %s", n.Name, rows, aID)
		}
	}
}

// The wedge that is already in a stream: an origin on a build before the fix
// minted a FRESH id for the re-create (lab 2 node-3's seq 197117 is one). Its
// entry is already logged and will be pushed as it is, so an upgraded peer
// must apply it — the tombstone it collides with is strictly older and is
// dead — rather than refuse it forever. A peer that holds the old tombstone
// converges by anti-entropy too.
func TestFleet_SnapshotNameReuse_FreshIDFromAnOlderOriginApplies(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	a, b, z := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	createSnap(t, a, "svm", "s1")
	oldID := liveSnapID(t, a, "svm", "s1")
	if err := corrosion.DeleteSnapshot(ctx, a.DB, "svm", "s1"); err != nil {
		t.Fatal(err)
	}
	for _, to := range []*Node{b, z} {
		if _, err := pushAll(t, c, a, to); err != nil {
			t.Fatalf("create+delete did not replicate to %s: %v", to.Name, err)
		}
	}

	// What the pre-fix builder emitted: the same registered INSERT shape with a
	// newly minted id. Locally it replaces the tombstone.
	freshID := uuid.New().String()
	if err := a.DB.Execute(ctx,
		`INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		freshID, "svm", a.Name, "s1", "ok", 1, "disk", "", 0, "2026-10-12T11:57:15Z", a.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
	createSnap(t, a, "svm", "s2")

	if _, err := pushAll(t, c, a, b); err != nil {
		t.Fatalf("the already-logged fresh-id re-create still wedges a's stream: %v", err)
	}
	if liveSnapID(t, b, "svm", "s2") == "" {
		t.Fatal("the write after the re-create never reached b")
	}
	if rows := snapRows(t, b, "svm", "s1"); len(rows) != 1 || rows[0].id != freshID || rows[0].deletedAt != "" {
		t.Fatalf("b's s1 rows: %+v, want only the live re-created row %s (old tombstone %s yields)", rows, freshID, oldID)
	}

	// z never got the push and still holds only the old tombstone. A pass on
	// b against z is offered that tombstone: it must not come back over the
	// live row.
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: z.Name}} })
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("anti-entropy pass on b did not run")
	}
	if rows := snapRows(t, b, "svm", "s1"); len(rows) != 1 || rows[0].id != freshID || rows[0].deletedAt != "" {
		t.Fatalf("b's s1 rows after a pass against z: %+v, want only %s live", rows, freshID)
	}
	// A pass on z against b brings z the live row, and z's tombstone yields.
	z.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: b.Name}} })
	if !corrosion.NewAntiEntropy(z.DB, z.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("anti-entropy pass on z did not run")
	}
	if rows := snapRows(t, z, "svm", "s1"); len(rows) != 1 || rows[0].id != freshID || rows[0].deletedAt != "" {
		t.Fatalf("z's s1 rows after anti-entropy: %+v, want only %s live", rows, freshID)
	}
}

// The general rule. b holds a LIVE snapshot svm/s1 under an id of its own (a
// genuine natural-key conflict between two live rows, which only
// canonical_identity resolves and which is off by default). a's insert of its
// own s1 cannot apply on b. That one change must not stop a's later writes
// from reaching b; it must be held, visibly, and applied once b can take it.
// Nothing may be overwritten or lost while it waits.
func TestFleet_UnapplyableChangeDoesNotBlockLaterChanges(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	localID := uuid.New().String()
	if err := localExec(ctx, b.DB,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, created_at, updated_at)
		 VALUES (?, 'svm', ?, 's1', 'ok', 1, 'disk', '2026-10-12T00:00:00Z', '0000000000001-0000-b')`,
		localID, b.Name); err != nil {
		t.Fatal(err)
	}

	createSnap(t, a, "svm", "s1") // cannot apply on b: UNIQUE(vm_name, name)
	aID := liveSnapID(t, a, "svm", "s1")
	createSnap(t, a, "svm", "s2") // must still reach b

	applied, err := pushAll(t, c, a, b)
	if err != nil {
		t.Fatalf("one unapplyable change wedged a's whole stream to b: %v", err)
	}
	if want := lastSeq(t, a); applied != want {
		t.Fatalf("b acknowledged up to %d, want a's tail %d", applied, want)
	}
	if liveSnapID(t, b, "svm", "s2") == "" {
		t.Fatal("the write after the unapplyable change never reached b")
	}
	if got := liveSnapID(t, b, "svm", "s1"); got != localID {
		t.Fatalf("b's own s1 was replaced while the conflict is unresolved: got %q, want %q", got, localID)
	}

	parked := b.repl.ParkedEntries()
	if len(parked) != 1 || parked[0].Origin != a.Name || parked[0].Table != "snapshots" || parked[0].Error == "" {
		t.Fatalf("the refused change is not held visibly: %+v", parked)
	}

	// A retry while the conflict stands changes nothing and keeps it held.
	b.repl.RetryParked(ctx)
	if len(b.repl.ParkedEntries()) != 1 || liveSnapID(t, b, "svm", "s1") != localID {
		t.Fatal("a retry against a standing conflict dropped or applied the held change")
	}

	// The conflict goes away (here: b's row is removed out of band). The held
	// change now applies, and is no longer held.
	if err := localExec(ctx, b.DB, `DELETE FROM snapshots WHERE id = ?`, localID); err != nil {
		t.Fatal(err)
	}
	b.repl.RetryParked(ctx)
	if got := liveSnapID(t, b, "svm", "s1"); got != aID {
		t.Fatalf("the held change did not apply once it could: s1 on b is %q, want %q", got, aID)
	}
	if p := b.repl.ParkedEntries(); len(p) != 0 {
		t.Fatalf("the applied change is still reported held: %+v", p)
	}
}

// The container analogue, keyed by (host_name, ct_name, name).
func TestFleet_ContainerSnapshotNameReuse_RecreateReplicates(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	create := func() {
		t.Helper()
		if err := corrosion.InsertContainerSnapshot(ctx, a.DB, corrosion.ContainerSnapshotRecord{
			CtName: "ct1", HostName: a.Name, Name: "s1", State: "ok", SizeBytes: 1, Path: "/x",
		}); err != nil {
			t.Fatal(err)
		}
	}
	live := func(n *Node) string {
		t.Helper()
		s, err := corrosion.GetContainerSnapshot(ctx, n.DB, a.Name, "ct1", "s1")
		if err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return s.ID
	}
	create()
	firstID := live(a)
	if err := corrosion.DeleteContainerSnapshot(ctx, a.DB, a.Name, "ct1", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := pushAll(t, c, a, b); err != nil {
		t.Fatalf("create+delete did not replicate: %v", err)
	}
	create()
	if _, err := pushAll(t, c, a, b); err != nil {
		t.Fatalf("the re-created container snapshot wedged a's stream: %v", err)
	}
	if got := live(a); got != firstID {
		t.Fatalf("the re-create minted id %q instead of re-using %q", got, firstID)
	}
	if got := live(b); got != firstID {
		t.Fatalf("b holds the re-created container snapshot as %q (\"\" = hidden by the tombstone), want %q", got, firstID)
	}
}

// The held signal survives a restart. A held WAL entry lives in memory, so a
// restart (or a crash between the batch's commit and the hold being recorded)
// forgets it; the signal must come back from state — anti-entropy's own
// refusal of the row — and stay until the conflict is resolved, so a restart
// never turns the alert green over a row that is still divergent.
func TestFleet_HeldChangeSignalSurvivesARestart(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	localID := uuid.New().String()
	if err := localExec(ctx, b.DB,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, created_at, updated_at)
		 VALUES (?, 'svm', ?, 's1', 'ok', 1, 'disk', '2026-10-12T00:00:00Z', '0000000000001-0000-b')`,
		localID, b.Name); err != nil {
		t.Fatal(err)
	}
	createSnap(t, a, "svm", "s1")
	aID := liveSnapID(t, a, "svm", "s1")
	if _, err := pushAll(t, c, a, b); err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(b.repl.ParkedEntries()) != 1 {
		t.Fatalf("the refused change is not held: %+v", b.repl.ParkedEntries())
	}

	// The restart: a new server and replicator over the same database; the
	// harness keeps the Client, so drop what the new process would not have.
	restartForSignal(t, c, b)
	if p := b.repl.ParkedEntries(); len(p) != 0 {
		t.Fatalf("the restarted node still remembers the held entry, so this proves nothing: %+v", p)
	}

	aePass := func() {
		t.Helper()
		b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
		if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
			t.Fatal("anti-entropy pass on b did not run")
		}
	}
	aePass()
	p := b.repl.ParkedEntries()
	if len(p) != 1 || p[0].Table != "snapshots" || p[0].RowID != aID || p[0].Origin != a.Name {
		t.Fatalf("after a restart and one anti-entropy pass the held signal is %+v, want %s's row %s", p, a.Name, aID)
	}
	if got := liveSnapID(t, b, "svm", "s1"); got != localID {
		t.Fatalf("b's own row changed: %q", got)
	}

	// Resolve the conflict: the next pass applies a's row and the signal clears.
	if err := localExec(ctx, b.DB, `DELETE FROM snapshots WHERE id = ?`, localID); err != nil {
		t.Fatal(err)
	}
	aePass()
	if got := liveSnapID(t, b, "svm", "s1"); got != aID {
		t.Fatalf("after the conflict was resolved b holds %q, want %q", got, aID)
	}
	if p := b.repl.ParkedEntries(); len(p) != 0 {
		t.Fatalf("the signal did not clear once the row applied: %+v", p)
	}
}

// restartForSignal restarts n's server and replicator over its database, as
// restartNode does, and forgets the Client's in-memory refusal record, which a
// real process restart would also lose.
func restartForSignal(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	if n.replStarted {
		n.repl.Stop()
		n.replStarted = false
	}
	if n.stopServerLoops != nil {
		n.stopServerLoops()
	}
	n.Stop()
	l, err := net.Listen("tcp", net.JoinHostPort(n.Address, strconv.Itoa(n.Port)))
	if err != nil {
		t.Fatalf("rebind %s: %v", n.Name, err)
	}
	n.Listener = l
	c.buildServer(n)
	n.DB.ForgetHeldRefusalsForTest()
}
