package corrosion

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type hostSeen struct {
	mu   sync.Mutex
	seen []string
}

func (h *hostSeen) watch(c *Client, vm string) {
	c.SetVMHostWatch(func() []string { return []string{vm} }, func(v, host string, epoch int64, known bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.seen = append(h.seen, fmt.Sprintf("%s@%s#%d/%v", v, host, epoch, known))
	})
}

func (h *hostSeen) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.seen...)
}

// A move out and back that reaches this node in one push is seen leg by
// leg: the watch is told each owner the VM's row had after each entry, not
// only where it ended (round-13 review I1: a target must see its incoming
// move's commit even when the move back arrives with it).
//
// Mutation: report only once the whole push has applied — the first leg is
// not seen, red.
func TestVMHostWatch_SeesEachLegOfAMoveOutAndBack(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})
	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	applyWAL(t, rb, walEntries(t, a, "node-a"))
	var h hostSeen
	h.watch(b, "vm1")

	before := len(walEntries(t, a, "node-a"))
	if err := UpdateVMHost(ctx, a, "vm1", "host-b", "running"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateVMHost(ctx, a, "vm1", "host-a", "running"); err != nil {
		t.Fatal(err)
	}
	applyWAL(t, rb, walEntries(t, a, "node-a")[before:])
	got := h.got()
	want := []string{"vm1@host-b#0/true", "vm1@host-a#0/true"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("seen %v, want %v", got, want)
	}
}

// A state sync that merges vms rows is reported as unknown for every watched
// VM: what the rows were between is not seen.
//
// Mutation: drop the sync report — nothing is seen, red.
func TestVMHostWatch_AStateSyncIsUnknown(t *testing.T) {
	c := testClient(t)
	var h hostSeen
	h.watch(c, "vm1")
	merged, _, err := c.mergeChunk(
		syncTable{Name: "vms", Columns: []string{"name", "host_name", "spec", "state", "created_at", "updated_at"}},
		[][]interface{}{{"vm1", "host-a", "{}", "running", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"}},
		"INSERT OR REPLACE INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		[]string{"name"}, []int{0}, 5,
	)
	if err != nil || merged != 1 {
		t.Fatalf("mergeChunk = %d, %v; want one row merged", merged, err)
	}
	if got := h.got(); fmt.Sprint(got) != fmt.Sprint([]string{"vm1@#0/false"}) {
		t.Fatalf("seen %v, want vm1 unknown", got)
	}
}

// With nothing watched, an applied entry costs the watch nothing: no
// statement of it is parsed (round-13c review m1).
//
// Mutation: parse the entry's statements before asking what is watched — red.
func TestVMHostWatch_NothingWatchedParsesNothing(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})
	b.SetVMHostWatch(func() []string { return nil }, func(string, string, int64, bool) {
		t.Error("seen called with nothing watched")
	})
	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	before := vmHostWatchParses.Load()
	applyWAL(t, rb, walEntries(t, a, "node-a"))
	if n := vmHostWatchParses.Load() - before; n != 0 {
		t.Fatalf("the idle watch parsed %d statements", n)
	}
}
