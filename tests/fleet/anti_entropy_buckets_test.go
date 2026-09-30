package fleet

// Bucketed anti-entropy repair (colonelpanik/litevirt#262,
// docs/design/ae-incremental.md): when a table's digest disagrees, the pass
// asks the peer for the table's bucket digests and pulls only the buckets that
// differ. These scenarios pin that the narrowing is only ever a narrowing —
// every row class still converges when one bucket differs, a peer on an older
// build still repairs, and the bytes a pass moves actually fall.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const aeFixedTS = "2026-01-01T00:00:00Z"

// execBeneath runs one statement on n beneath the replicator (no
// mutation_log entry), so only anti-entropy can carry its effect anywhere.
func execBeneath(t *testing.T, n *Node, q string, args ...interface{}) {
	t.Helper()
	n.DB.Mu().Lock()
	_, err := n.DB.DB().Exec(q, args...)
	n.DB.Mu().Unlock()
	if err != nil {
		t.Fatalf("%s on %s: %v", q, n.Name, err)
	}
}

// seedEqualStacks writes count byte-identical stacks rows on every node.
func seedEqualStacks(t *testing.T, count int, nodes ...*Node) {
	t.Helper()
	for _, n := range nodes {
		n.DB.Mu().Lock()
		tx, err := n.DB.DB().Begin()
		if err != nil {
			n.DB.Mu().Unlock()
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			// A distinct, poorly compressible body per row, as real compose
			// files are, so gzip does not flatter the whole-table pull.
			sum := sha256.Sum256([]byte(fmt.Sprintf("row-%d", i)))
			body := fmt.Sprintf("services: {web: {image: %x, env: {TOKEN: %x}}}", sum[:16], sum[16:])
			if _, err := tx.Exec(`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
				VALUES (?, ?, ?, 'active', ?, ?)`,
				fmt.Sprintf("bulk-%05d", i), fmt.Sprintf("%x", sum[:8]), body, aeFixedTS, aeFixedTS); err != nil {
				t.Fatal(err)
			}
		}
		err = tx.Commit()
		n.DB.Mu().Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
}

// pullRowMetrics records, per scope, the rows repair pulls received.
type pullRowMetrics struct {
	recordingSyncMetrics
	mu   sync.Mutex
	rows map[string]int
}

func (m *pullRowMetrics) ObservePullRows(scope string, rows int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]int{}
	}
	m.rows[scope] += rows
}

func (m *pullRowMetrics) take() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.rows
	m.rows = nil
	if out == nil {
		out = map[string]int{}
	}
	return out
}

func twoNodes(t *testing.T) (*Cluster, *Node, *Node, *pullRowMetrics) {
	t.Helper()
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	a.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: b.Name}} })
	m := &pullRowMetrics{}
	b.DB.SetSyncMetrics(m)
	return c, a, b, m
}

func runFullPass(t *testing.T, n *Node, legacy bool) {
	t.Helper()
	ae := corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0)
	ae.SetLegacyRepair(legacy)
	if !ae.RunOnce(context.Background()) {
		t.Fatalf("%s: the pass did not run", n.Name)
	}
}

func aeStackState(t *testing.T, n *Node, name string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT state || '/' || COALESCE(deleted_at, '') AS s FROM stacks WHERE name = ?`, name)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0].String("s")
}

// One drifted row in a 4,000-row table: the pull carries one bucket, and moves
// a small fraction of the bytes the whole-table pull of the same drift does.
func TestFleet_AntiEntropy_Buckets_OneDriftedRowPullsOneBucket(t *testing.T) {
	c, a, b, m := twoNodes(t)
	const rows = 4000
	seedEqualStacks(t, rows, a, b)

	execBeneath(t, a, `UPDATE stacks SET state = 'failed', updated_at = '2026-02-01T00:00:00Z' WHERE name = 'bulk-00042'`)
	c.ResetAEStats()
	runFullPass(t, b, false)
	if got := aeStackState(t, b, "bulk-00042"); got != "failed/" {
		t.Fatalf("b holds bulk-00042 as %q after the bucketed pass, want failed/", got)
	}
	bucketed := c.AEStats()
	pulled := m.take()
	if pulled["table"] != 0 || pulled["bucket"] == 0 || pulled["bucket"] > 3*rows/corrosion.BucketCount {
		t.Errorf("rows pulled by scope %v: want only bucket rows, about %d (one bucket)", pulled, rows/corrosion.BucketCount)
	}
	if bucketed["GetTableBucketDigests"].Calls == 0 {
		t.Errorf("no bucket exchange: %+v", bucketed)
	}

	// The same drift, repaired the way a pass did before buckets.
	execBeneath(t, a, `UPDATE stacks SET state = 'failed', updated_at = '2026-02-01T00:00:00Z' WHERE name = 'bulk-01042'`)
	c.ResetAEStats()
	runFullPass(t, b, true)
	if got := aeStackState(t, b, "bulk-01042"); got != "failed/" {
		t.Fatalf("b holds bulk-01042 as %q after the whole-table pass, want failed/", got)
	}
	whole := c.AEStats()
	legacyPulled := m.take()
	if legacyPulled["table"] < rows || legacyPulled["bucket"] != 0 {
		t.Errorf("legacy pass rows pulled by scope %v, want the whole table (>= %d)", legacyPulled, rows)
	}
	if whole["GetTableBucketDigests"].Calls != 0 {
		t.Errorf("the stand-down still asked for bucket digests: %+v", whole)
	}

	bb := bucketed["StreamTableDump"].Bytes + bucketed["GetTableBucketDigests"].Bytes
	wb := whole["StreamTableDump"].Bytes
	t.Logf("one drifted row in %d: bucketed pass moved %d bytes (dump %d + bucket digests %d), rows %d; whole-table pass %d bytes, rows %d",
		rows, bb, bucketed["StreamTableDump"].Bytes, bucketed["GetTableBucketDigests"].Bytes, pulled["bucket"], wb, legacyPulled["table"])
	if bb*10 > wb {
		t.Errorf("bucketed pass moved %d bytes, the whole-table pass %d: want at least a 10x drop", bb, wb)
	}
}

// Every row class converges when only one bucket differs: an update, a new
// row, a tombstone, a VM child whose authority parent must travel in its
// bucket, and a sensitive-lane row.
func TestFleet_AntiEntropy_Buckets_EveryRowClassConverges(t *testing.T) {
	c, a, b, m := twoNodes(t)
	seedEqualStacks(t, 1000, a, b)
	for _, n := range []*Node{a, b} {
		for i := 0; i < 300; i++ {
			vm := fmt.Sprintf("vm-%03d", i)
			execBeneath(t, n, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, ?, '{}', 'running', ?, ?)`,
				vm, a.Name, aeFixedTS, aeFixedTS)
			execBeneath(t, n, `INSERT INTO vm_disks (vm_name, disk_name, host_name, path, size_bytes, updated_at) VALUES (?, 'root', ?, '/var/lib/x', 10, ?)`,
				vm, a.Name, aeFixedTS)
		}
		for i := 0; i < 300; i++ {
			execBeneath(t, n, `INSERT INTO registry_credentials (id, registry, username, secret, created_at, updated_at) VALUES (?, ?, 'u', 's', ?, ?)`,
				fmt.Sprintf("rc-%03d", i), fmt.Sprintf("reg-%03d.example", i), aeFixedTS, aeFixedTS)
		}
	}
	const later = "2026-02-01T00:00:00Z"
	// The drift, all on a.
	execBeneath(t, a, `UPDATE stacks SET deleted_at = ?, updated_at = ? WHERE name = 'bulk-00007'`, later, later)
	execBeneath(t, a, `INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at) VALUES ('fresh', 'h', 'y', 'active', ?, ?)`, later, later)
	execBeneath(t, a, `UPDATE vm_disks SET size_bytes = 20, updated_at = ? WHERE vm_name = 'vm-123'`, later)
	execBeneath(t, a, `UPDATE registry_credentials SET secret = 'rotated', updated_at = ? WHERE id = 'rc-045'`, later)

	c.ResetAEStats()
	runFullPass(t, b, false)

	if got := aeStackState(t, b, "bulk-00007"); got != "active/"+later {
		t.Errorf("tombstone: b holds bulk-00007 as %q, want the soft delete", got)
	}
	if !hasStack(t, b, "fresh") {
		t.Error("new row: b did not receive stacks 'fresh'")
	}
	if n := rowCount(t, b, `SELECT COUNT(*) AS n FROM vm_disks WHERE vm_name = 'vm-123' AND size_bytes = 20`); n != 1 {
		t.Error("VM child: b did not take vm-123's newer disk row — its vms parent did not travel in its bucket")
	}
	if n := rowCount(t, b, `SELECT COUNT(*) AS n FROM registry_credentials WHERE id = 'rc-045' AND secret = 'rotated'`); n != 1 {
		t.Error("sensitive lane: b did not take the rotated registry credential")
	}
	assertTablesAgree(t, a, b, "stacks", "vms", "vm_disks", "registry_credentials")
	pulled := m.take()
	if pulled["bucket"] == 0 || pulled["bucket"] > 200 {
		t.Errorf("rows pulled by scope %v: want a handful of buckets' worth", pulled)
	}
}

// A settled tie in a large table still settles when the pull is narrowed to
// its bucket: the proof reads the other buckets from their digests.
func TestFleet_AntiEntropy_Buckets_SettledTieInALargeTable(t *testing.T) {
	c, a, b, _ := twoNodes(t)
	ctx := context.Background()
	for _, n := range []*Node{a, b} {
		for i := 0; i < 600; i++ {
			execBeneath(t, n, `INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at) VALUES ('bulk', ?, 'h', ?, ?, ?)`,
				i, aeFixedTS, aeFixedTS, aeFixedTS)
		}
	}
	seedUnreplicatedLeaseTerm(t, a, "dual_run_detector", 2, a.Name)
	seedUnreplicatedLeaseTerm(t, b, "dual_run_detector", 2, b.Name)
	runFullPass(t, b, false)
	if got := b.DB.UnresolvedTieCount(); got != 1 {
		t.Fatalf("precondition: b tracks %d ties, want 1", got)
	}
	c.ResetAEStats()
	for i := 0; i < 4; i++ {
		ae := corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0)
		if !ae.RunSampledOnce(ctx) {
			t.Fatalf("pass %d did not run", i)
		}
	}
	if got := tableDumpsServed(c); got > 1 {
		t.Errorf("4 scheduled passes pulled leader_lease_terms %d times for a settled tie; want at most 1", got)
	}
	// A new row elsewhere in the table is still pulled at once.
	seedUnreplicatedLeaseTerm(t, a, "bulk", 1000, "new")
	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if h, ok := leaseTermHolder(t, b, "bulk", 1000); !ok || h != "new" {
		t.Errorf("a new row in the settled table was not pulled: holder %q present=%v", h, ok)
	}
	if got := b.DB.UnresolvedTieCount(); got != 1 {
		t.Errorf("the tie is no longer tracked (count %d)", got)
	}
}

// A mixed pair converges both ways: a new node pulling from a peer that has
// no bucket RPC (an older build), and a node on the whole-table protocol
// pulling from a new one.
func TestFleet_AntiEntropy_Buckets_MixedVersionPair(t *testing.T) {
	c, a, b, m := twoNodes(t)
	seedEqualStacks(t, 500, a, b)

	t.Run("new pulls from old", func(t *testing.T) {
		defer a.DoNotImplement("GetTableBucketDigests")()
		execBeneath(t, a, `UPDATE stacks SET state = 'old-peer', updated_at = '2026-02-01T00:00:00Z' WHERE name = 'bulk-00011'`)
		c.ResetAEStats()
		runFullPass(t, b, false)
		if got := aeStackState(t, b, "bulk-00011"); got != "old-peer/" {
			t.Fatalf("b did not repair from a peer without bucket digests: %q", got)
		}
		if pulled := m.take(); pulled["table"] == 0 || pulled["bucket"] != 0 {
			t.Errorf("rows pulled by scope %v: want a whole-table pull from an older peer", pulled)
		}
	})
	t.Run("old pulls from new", func(t *testing.T) {
		execBeneath(t, b, `UPDATE stacks SET state = 'new-peer', updated_at = '2026-03-01T00:00:00Z' WHERE name = 'bulk-00012'`)
		c.ResetAEStats()
		runFullPass(t, a, true)
		if got := aeStackState(t, a, "bulk-00012"); got != "new-peer/" {
			t.Fatalf("a node on the whole-table protocol did not repair from a new peer: %q", got)
		}
		if st := c.AEStats(); st["GetTableBucketDigests"].Calls != 0 {
			t.Errorf("the whole-table node asked for bucket digests: %+v", st)
		}
	})
	assertTablesAgree(t, a, b, "stacks")
}

// assertTablesAgree fails unless a and b digest tables identically. The whole
// replica is not compared: without the push loop, the hosts rows each node
// keeps reporting about itself drift apart between passes by design.
func assertTablesAgree(t *testing.T, a, b *Node, tables ...string) {
	t.Helper()
	ctx := context.Background()
	digests := func(n *Node) map[string]corrosion.TableDigest {
		out := map[string]corrosion.TableDigest{}
		pub, _ := n.DB.StateDigest(ctx)
		sens, _ := n.DB.SensitiveStateDigest(ctx)
		for _, d := range append(pub, sens...) {
			out[d.Name] = d
		}
		return out
	}
	da, db := digests(a), digests(b)
	for _, tbl := range tables {
		if da[tbl] != db[tbl] {
			t.Errorf("%s still apart: %s=%+v %s=%+v", tbl, a.Name, da[tbl], b.Name, db[tbl])
		}
	}
}
