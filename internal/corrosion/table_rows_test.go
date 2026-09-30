package corrosion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// collectPages runs a paged pull of tables from src and returns every message.
func collectPages(t *testing.T, src *Client, tables []string, buckets map[string][]int) []*pb.TableRowsPage {
	t.Helper()
	var pages []*pb.TableRowsPage
	if err := src.StreamTableRowsScoped(context.Background(), tables, buckets, func(p *pb.TableRowsPage) error {
		pages = append(pages, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(pages) == 0 || !pages[len(pages)-1].GetFinal() {
		t.Fatal("the stream did not end with the final marker")
	}
	return pages
}

func replay(pages []*pb.TableRowsPage) func() (*pb.TableRowsPage, error) {
	i := 0
	return func() (*pb.TableRowsPage, error) {
		if i >= len(pages) {
			return nil, io.EOF
		}
		i++
		return pages[i-1], nil
	}
}

func withPageBounds(t *testing.T, rows, bytes int) {
	t.Helper()
	oldR, oldB := antiEntropyPageRows, antiEntropyPageBytes
	antiEntropyPageRows, antiEntropyPageBytes = rows, bytes
	t.Cleanup(func() { antiEntropyPageRows, antiEntropyPageBytes = oldR, oldB })
}

func pagedDigest(t *testing.T, c *Client, table string) TableDigest {
	t.Helper()
	ds, _ := c.stateDigestForTables(context.Background(), []string{table})
	if len(ds) != 1 {
		t.Fatalf("no digest for %s", table)
	}
	return ds[0]
}

// Every page carries at most antiEntropyPageRows rows, and a peer merging the
// pages one at a time ends with the whole table.
func TestStreamTableRows_BoundedPagesConverge(t *testing.T) {
	withPageBounds(t, 100, 1<<20)
	a, b := testClient(t), testClient(t)
	seedStacks(t, a, 2500)
	pages := collectPages(t, a, []string{"stacks"}, nil)
	total := 0
	for _, p := range pages {
		if p.GetRowCount() > 100 {
			t.Fatalf("a page carried %d rows, bound is 100", p.GetRowCount())
		}
		total += int(p.GetRowCount())
	}
	if total != 2500 || len(pages) < 25 {
		t.Fatalf("%d rows in %d pages, want 2500 in at least 25", total, len(pages))
	}
	if _, rows, perr, merr := b.mergeTableRowsStream(replay(pages), replicatedTableSet, nil); perr != nil || merr != nil || rows["stacks"] != 2500 {
		t.Fatalf("merge: pull=%v merge=%v rows=%v", perr, merr, rows)
	}
	if pagedDigest(t, a, "stacks") != pagedDigest(t, b, "stacks") {
		t.Fatal("the paged pull did not converge the table")
	}
}

// The byte bound cuts a page before the row bound does.
func TestStreamTableRows_ByteBound(t *testing.T) {
	withPageBounds(t, 1000, 2048)
	a := testClient(t)
	seedStacks(t, a, 300)
	for _, p := range collectPages(t, a, []string{"stacks"}, nil) {
		if p.GetFinal() {
			continue
		}
		rows, err := decodePageRows(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= 300 || p.GetRowCount() != int32(len(rows)) {
			t.Fatalf("page of %d rows (declared %d): the byte bound did not cut it", len(rows), p.GetRowCount())
		}
	}
}

// Keyset paging over a composite key reaches every row, and a key cell that
// is NULL does not stop the walk.
func TestStreamTableRows_CompositeKeyAndNullKey(t *testing.T) {
	withPageBounds(t, 50, 1<<20)
	const ts = "2026-01-01T00:00:00Z"
	a, b := newTestDB(t), newTestDB(t)
	for i := 0; i < 230; i++ {
		putLeaseTerm(t, a, fmt.Sprintf("k-%02d", i%7), int64(i), "h", ts, ts)
	}
	pages := collectPages(t, a, []string{"leader_lease_terms"}, nil)
	if _, rows, perr, merr := b.mergeTableRowsStream(replay(pages), replicatedTableSet, nil); perr != nil || merr != nil || rows["leader_lease_terms"] != 230 {
		t.Fatalf("merge: pull=%v merge=%v rows=%v", perr, merr, rows)
	}
	if pagedDigest(t, a, "leader_lease_terms") != pagedDigest(t, b, "leader_lease_terms") {
		t.Fatal("composite-key paging missed rows")
	}

	// stacks.name is a TEXT PRIMARY KEY, which SQLite lets hold NULL.
	c := testClient(t)
	for i := 0; i < 120; i++ {
		mustExec(t, c, `INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at) VALUES (NULL, 'h', ?, 'active', 'x', 'x')`, fmt.Sprintf("y%d", i))
	}
	seedStacks(t, c, 80)
	n := 0
	for _, p := range collectPages(t, c, []string{"stacks"}, nil) {
		n += int(p.GetRowCount())
	}
	if n != 200 {
		t.Fatalf("paged %d of 200 rows with NULL keys present", n)
	}
}

// A VM child is merged only after every parent row of the pull: pages of the
// parent tier are held, the manifest built, the parents merged, and only then
// the children.
func TestStreamTableRows_ChildrenAfterTheirParents(t *testing.T) {
	withPageBounds(t, 10, 1<<20)
	a, b := testClient(t), testClient(t)
	const ts = "2026-01-01T00:00:00Z"
	for i := 0; i < 40; i++ {
		vm := fmt.Sprintf("vm-%02d", i)
		mustExec(t, a, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, 'h1', '{}', 'running', ?, ?)`, vm, ts, ts)
		mustExec(t, a, `INSERT INTO vm_disks (vm_name, disk_name, host_name, path, size_bytes, updated_at) VALUES (?, 'root', 'h1', '/p', 10, ?)`, vm, ts)
	}
	pages := collectPages(t, a, []string{"vm_disks"}, nil)
	if pages[0].GetTable() != "vms" {
		t.Fatalf("first page is %q: parents must stream first", pages[0].GetTable())
	}
	if _, _, perr, merr := b.mergeTableRowsStream(replay(pages), replicatedTableSet, nil); perr != nil || merr != nil {
		t.Fatalf("merge: pull=%v merge=%v", perr, merr)
	}
	for _, tbl := range []string{"vms", "vm_disks"} {
		if pagedDigest(t, a, tbl) != pagedDigest(t, b, tbl) {
			t.Fatalf("%s did not converge over the paged pull", tbl)
		}
	}

	// tableNames lists snapshots (an ordinary table) after the VM children;
	// the server must still send it before them, or the receiver's order
	// check refuses a pull it asked for.
	mustExec(t, a, `INSERT INTO snapshots (id, vm_name, name, host_name, state, created_at, updated_at) VALUES ('s1', 'vm-01', 'snap', 'h1', 'ready', ?, ?)`, ts, ts)
	mixed := collectPages(t, a, []string{"vm_disks", "snapshots"}, nil)
	if _, _, perr, merr := testClient(t).mergeTableRowsStream(replay(mixed), replicatedTableSet, nil); perr != nil || merr != nil {
		t.Fatalf("a pull of a child and an ordinary table: pull=%v merge=%v", perr, merr)
	}

	// A child page ahead of its parents is refused, not judged without them.
	var reordered []*pb.TableRowsPage
	for _, p := range pages {
		if p.GetTable() == "vm_disks" {
			reordered = append(reordered, p)
		}
	}
	for _, p := range pages {
		if p.GetTable() != "vm_disks" {
			reordered = append(reordered, p)
		}
	}
	c := testClient(t)
	if _, _, perr, _ := c.mergeTableRowsStream(replay(reordered), replicatedTableSet, nil); !errors.Is(perr, ErrPageOutOfOrder) {
		t.Fatalf("an out-of-order stream was accepted: %v", perr)
	}
}

// The paged pull narrows to buckets exactly as the blob dump does, and hands
// back the rows of the tables it was asked to keep.
func TestStreamTableRows_BucketsAndKeptTables(t *testing.T) {
	a, b := testClient(t), testClient(t)
	seedStacks(t, a, 500)
	bk, _ := bucketIndexOf([]interface{}{"stack-0123"})
	pages := collectPages(t, a, []string{"stacks"}, map[string][]int{"stacks": {bk}})
	kept, rows, perr, merr := b.mergeTableRowsStream(replay(pages), replicatedTableSet, map[string]bool{"stacks": true})
	if perr != nil || merr != nil {
		t.Fatalf("merge: pull=%v merge=%v", perr, merr)
	}
	blob, _ := a.DumpTablesScopedBytes([]string{"stacks"}, map[string][]int{"stacks": {bk}})
	want := len(payloadRows(t, blob)["stacks"])
	if rows["stacks"] != want || want == 0 {
		t.Fatalf("paged pull of bucket %d carried %d rows, the blob dump %d", bk, rows["stacks"], want)
	}
	if len(kept.Tables) != 1 || len(kept.Tables[0].Rows) != want {
		t.Fatalf("kept %+v, want the %d stacks rows", kept.Tables, want)
	}
}
