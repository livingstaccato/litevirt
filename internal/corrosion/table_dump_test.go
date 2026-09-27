package corrosion

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func dumpedTableNames(t *testing.T, data []byte) []string {
	t.Helper()
	payload, err := decompressPayload(data)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	var out []string
	for _, st := range payload.Tables {
		out = append(out, st.Name)
	}
	return out
}

func seedStack(t *testing.T, c *Client, name string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := c.Execute(context.Background(),
		`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		 VALUES (?, 'h', 'services: {}', 'active', ?, ?)`, name, now, now); err != nil {
		t.Fatalf("seed stack %s: %v", name, err)
	}
}

// A table-scoped dump carries the tables it was asked for and no others.
func TestDumpTablesBytes_CarriesOnlyTheRequestedTables(t *testing.T) {
	c := newPruneTestClient(t)
	ctx := context.Background()
	seedStack(t, c, "s1")
	if err := InsertVM(ctx, c, VMRecord{Name: "vm-1", HostName: "h1", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	data, err := c.DumpTablesBytes([]string{"stacks"})
	if err != nil {
		t.Fatalf("DumpTablesBytes: %v", err)
	}
	if got := dumpedTableNames(t, data); !slices.Equal(got, []string{"stacks"}) {
		t.Fatalf("dump of [stacks] carried %v, want exactly [stacks]", got)
	}
}

// A child table travels with the parent its merge checks authority against.
// Without the parent in the same payload the merge keeps every local child row
// (antiEntropyAuthorityDecision: a child with no manifest entry is keep-local),
// so a dump of the mismatched child alone would repair nothing.
func TestResolveTableDump_AddsTheMergeAuthorityParents(t *testing.T) {
	cases := map[string][]string{
		"vm_disks":             {"vms", "vm_disks"},
		"vm_interfaces":        {"vms", "vm_interfaces"},
		"vm_nics":              {"vms", "vm_nics"},
		"vm_pci_intent":        {"vms", "vm_pci_intent"},
		"vm_pci_realizations":  {"vms", "vm_pci_realizations"},
		"container_interfaces": {"containers", "container_interfaces"},
		"operation_steps":      {"vms", "containers", "operations", "operation_steps"},
		"stacks":               {"stacks"},
	}
	for table, want := range cases {
		got, err := ResolveTableDump([]string{table})
		if err != nil {
			t.Fatalf("ResolveTableDump(%s): %v", table, err)
		}
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("ResolveTableDump([%s]) = %v, want %v", table, got, w)
		}
	}
}

// The resolved tables are the dump's own allowlist and order: a name the public
// lane does not carry is dropped, and a sensitive-lane table is refused — this
// RPC must not become a side door into the peer-only sensitive dump.
func TestResolveTableDump_RefusesSensitiveAndDropsUnknown(t *testing.T) {
	for _, s := range sensitiveTableNames {
		if _, err := ResolveTableDump([]string{"stacks", s}); !errors.Is(err, ErrTableDumpSensitive) {
			t.Errorf("ResolveTableDump with sensitive %q: err = %v, want ErrTableDumpSensitive", s, err)
		}
	}
	if _, err := ResolveTableDump(nil); !errors.Is(err, ErrTableDumpEmpty) {
		t.Errorf("ResolveTableDump(nil): err = %v, want ErrTableDumpEmpty", err)
	}
	got, err := ResolveTableDump([]string{"no_such_table", "stacks", "mutation_log"})
	if err != nil {
		t.Fatalf("ResolveTableDump: %v", err)
	}
	if !slices.Equal(got, []string{"stacks"}) {
		t.Fatalf("ResolveTableDump dropped nothing: %v, want [stacks]", got)
	}
	// Only unknown names: nothing to dump, which is not "everything".
	if _, err := ResolveTableDump([]string{"no_such_table"}); !errors.Is(err, ErrTableDumpEmpty) {
		t.Errorf("ResolveTableDump of only unknown names: err = %v, want ErrTableDumpEmpty", err)
	}
}

// End to end through the real merge: a replica missing one vm_disks row gets it
// back from a dump of vm_disks alone.
func TestDumpTablesBytes_ChildTableRepairMerges(t *testing.T) {
	ctx := context.Background()
	src := newPruneTestClient(t)
	dst := newPruneTestClient(t)
	if err := InsertVM(ctx, src, VMRecord{Name: "vm-1", HostName: "h1", Spec: "{}", State: "running"}, nil,
		[]DiskRecord{{VMName: "vm-1", DiskName: "root", HostName: "h1", Path: "/d/root.qcow2", StorageType: "local"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed dst: %v", err)
	}
	// dst loses the disk row beneath the replicator; only vm_disks now differs.
	dst.mu.Lock()
	_, err := dst.db.Exec(`DELETE FROM vm_disks WHERE vm_name = 'vm-1'`)
	dst.mu.Unlock()
	if err != nil {
		t.Fatalf("drop disk: %v", err)
	}

	data, err := src.DumpTablesBytes([]string{"vm_disks"})
	if err != nil {
		t.Fatalf("DumpTablesBytes: %v", err)
	}
	if err := dst.MergeStateBytesLWW(data); err != nil {
		t.Fatalf("merge: %v", err)
	}
	rows, err := dst.Query(ctx, `SELECT COUNT(*) AS n FROM vm_disks WHERE vm_name = 'vm-1'`)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n := rows[0].Int("n"); n != 1 {
		t.Fatalf("vm_disks rows for vm-1 after a vm_disks-scoped repair = %d, want 1", n)
	}
}
