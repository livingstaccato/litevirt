package corrosion

import (
	"context"
	"database/sql"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// These pin the apply-layer half of parked_updates.go: an LWW full-PK UPDATE
// that met no row because the row had not arrived is replayed, under LWW, by
// the WAL batch that creates the row. The fleet tests
// (tests/fleet/update_before_row_test.go) pin the multi-node consequence.

func mustVM(t *testing.T, c *Client, name string) *VMRecord {
	t.Helper()
	vm, err := GetVM(context.Background(), c, name)
	if err != nil {
		t.Fatalf("GetVM %s: %v", name, err)
	}
	if vm == nil {
		t.Fatalf("GetVM %s: no row", name)
	}
	return vm
}

func applyWAL(t *testing.T, r *Replicator, entries []*pb.MutationEntry) {
	t.Helper()
	if _, err := r.ApplyRemoteMutations(context.Background(), entries); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
}

// The origin: b moves a VM whose row is still on its way from a. The move is
// relayed exactly as before, and b itself applies it when a's insert lands.
func TestParkedUpdate_OriginAppliesItsUpdateWhenTheRowArrives(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})

	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	logged := mutationLogCount(t, b)
	if err := UpdateVMHost(ctx, b, "vm1", "host-c", "stopped"); err != nil {
		t.Fatalf("UpdateVMHost on b: %v", err)
	}
	if mutationLogCount(t, b) == logged {
		t.Fatal("the zero-row update was not relayed; parking must not change what is sent")
	}
	if got := b.ParkedUpdates(); got != 1 {
		t.Fatalf("parked = %d, want 1 (the update met no row)", got)
	}

	applyWAL(t, rb, walEntries(t, a, "node-a"))

	vm := mustVM(t, b, "vm1")
	if vm.HostName != "host-c" || vm.State != "stopped" {
		t.Fatalf("b: vm1 = host %q state %q after its row arrived; want b's own move (host-c, stopped)",
			vm.HostName, vm.State)
	}
	if got := b.ParkedUpdates(); got != 0 {
		t.Errorf("parked = %d after replay, want 0", got)
	}
}

// A receiver handed an update ahead of its row applies it once the row lands.
func TestParkedUpdate_ReceiverAppliesAnUpdateThatArrivedFirst(t *testing.T) {
	ctx := context.Background()
	a, b, c := testClient(t), testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})
	rc := NewReplicator(c, "", RelayConfig{})

	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	applyWAL(t, rb, walEntries(t, a, "node-a"))
	if err := UpdateVMHost(ctx, b, "vm1", "host-c", "stopped"); err != nil {
		t.Fatalf("UpdateVMHost on b: %v", err)
	}
	// b is not a relay, so its log holds its own move and not a's insert: c
	// gets the move ahead of the row, as from a leaf.
	applyWAL(t, rc, walEntries(t, b, "node-b"))
	if got := c.ParkedUpdates(); got != 1 {
		t.Fatalf("c parked = %d, want 1", got)
	}

	applyWAL(t, rc, walEntries(t, a, "node-a"))
	vm := mustVM(t, c, "vm1")
	if vm.HostName != "host-c" || vm.State != "stopped" {
		t.Fatalf("c: vm1 = host %q state %q; want b's move", vm.HostName, vm.State)
	}
}

// LWW still decides. An update OLDER than the row that arrives is dropped, not
// applied over it.
func TestParkedUpdate_AnOlderUpdateDoesNotRegressTheRow(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})

	if err := UpdateVMHost(ctx, b, "vm1", "host-c", "stopped"); err != nil {
		t.Fatalf("UpdateVMHost on b: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	applyWAL(t, rb, walEntries(t, a, "node-a"))

	vm := mustVM(t, b, "vm1")
	if vm.HostName != "host-a" || vm.State != "running" {
		t.Fatalf("b: vm1 = host %q state %q; an update older than the row must lose", vm.HostName, vm.State)
	}
	if got := b.ParkedUpdates(); got != 0 {
		t.Errorf("parked = %d, want 0: a replayed update is consumed whether or not it won", got)
	}
}

// An update whose extra predicate rejected a row that IS here is a decision,
// not a gap, and is never parked.
func TestParkedUpdate_APresentRowIsNeverParked(t *testing.T) {
	ctx := context.Background()
	b := testClient(t)
	if err := InsertVM(ctx, b, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The row is at epoch 0; a write at epoch 7 matches nothing.
	if err := UpdateVMStateAtEpoch(ctx, b, "vm1", "stopped", "", 7); err != nil {
		t.Fatalf("UpdateVMStateAtEpoch: %v", err)
	}
	if got := b.ParkedUpdates(); got != 0 {
		t.Fatalf("parked = %d, want 0: the row is present", got)
	}
	// Nor is a shape that is not a plain LWW full-PK update: a custom-merge
	// guarded UPDATE on a row that is absent.
	if err := b.Execute(ctx, `UPDATE runtime_action_proofs
		    SET step_state = TRIM(COALESCE(step_state,'') || ' ' || ?), updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL
		    AND status NOT IN ('completed','failed')
		    AND instr(' ' || COALESCE(step_state,'') || ' ', ' ' || ? || ' ') = 0`,
		"s1", b.NowTS(), "no-such-proof", "s1"); err != nil {
		t.Fatalf("custom-merge update: %v", err)
	}
	if got := b.ParkedUpdates(); got != 0 {
		t.Fatalf("parked = %d, want 0: only DispFullPKUpdate is parked", got)
	}
}

// A batch that rolls back keeps the park, so the redelivered batch still finds
// it.
func TestParkedUpdate_ARolledBackBatchKeepsThePark(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})

	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	if err := UpdateVMHost(ctx, b, "vm1", "host-c", "stopped"); err != nil {
		t.Fatalf("UpdateVMHost on b: %v", err)
	}
	good := walEntries(t, a, "node-a")
	bad := append(append([]*pb.MutationEntry{}, good...),
		replayEntry(t, "node-a", "9999999999999-0000-node-a", Statement{SQL: `NOT SQL AT ALL`})...)
	bad[len(bad)-1].Seq = good[len(good)-1].Seq + 1
	if _, err := rb.ApplyRemoteMutations(ctx, bad); err == nil {
		t.Fatal("premise: the poisoned batch applied")
	}
	if got := b.ParkedUpdates(); got != 1 {
		t.Fatalf("parked = %d after a rolled-back batch, want 1", got)
	}

	applyWAL(t, rb, good)
	if vm := mustVM(t, b, "vm1"); vm.HostName != "host-c" {
		t.Fatalf("b: vm1 host %q after redelivery; want b's move", vm.HostName)
	}
}

// The park is bounded in time and size; what falls out is left to anti-entropy.
func TestParkedUpdate_AgesOutAndIsBounded(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})
	now := time.Now()
	b.parked.now = func() time.Time { return now }

	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	if err := UpdateVMHost(ctx, b, "vm1", "host-c", "stopped"); err != nil {
		t.Fatalf("UpdateVMHost on b: %v", err)
	}
	now = now.Add(parkedUpdateTTL + time.Second)
	applyWAL(t, rb, walEntries(t, a, "node-a"))
	if vm := mustVM(t, b, "vm1"); vm.HostName != "host-a" {
		t.Fatalf("b: vm1 host %q; an expired park must not replay", vm.HostName)
	}

	defer func(old int) { parkedUpdatesMax = old }(parkedUpdatesMax)
	parkedUpdatesMax = 2
	for _, name := range []string{"x1", "x2", "x3"} {
		if err := UpdateVMHost(ctx, b, name, "host-c", "stopped"); err != nil {
			t.Fatalf("UpdateVMHost %s: %v", name, err)
		}
	}
	if got := b.ParkedUpdates(); got != 2 {
		t.Fatalf("parked = %d, want the bound of 2", got)
	}
	if len(b.parked.pending(parkedRowKey("vms", []interface{}{"x1"}))) != 0 {
		t.Error("the oldest park should be the one evicted")
	}
}

// ExecuteBatchGuarded relays a zero-row statement the same way Execute does, so
// it parks the same way.
func TestParkedUpdate_AGuardedBatchParksToo(t *testing.T) {
	ctx := context.Background()
	b := testClient(t)
	applied, err := b.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) { return true, nil },
		[]Statement{{
			SQL:    `UPDATE vms SET host_name = ?, state = ?, state_detail = '', updated_at = ? WHERE name = ?`,
			Params: []interface{}{"host-c", "stopped", b.NowTS(), "vm1"},
		}})
	if err != nil || !applied {
		t.Fatalf("ExecuteBatchGuarded = %v, %v", applied, err)
	}
	if got := b.ParkedUpdates(); got != 1 {
		t.Fatalf("parked = %d, want 1", got)
	}
}

// The production writer that reaches this: BindSecurityGroups runs on whichever
// node took the request, with no forward to the owner and no local read of the
// VM, so `lv sg bind` straight after a create placed elsewhere updates an
// interface this node may not hold yet. It must land here too, not only on the
// peers the statement is relayed to.
func TestParkedUpdate_SecurityGroupBindAheadOfTheInterface(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	rb := NewReplicator(b, "", RelayConfig{})

	if err := InsertVM(ctx, a, VMRecord{Name: "vm1", HostName: "host-a", Spec: "{}", State: "running"},
		[]InterfaceRecord{{VMName: "vm1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"}}, nil); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	if err := SetInterfaceSecurityGroups(ctx, b, "vm1", "default", []string{"web"}); err != nil {
		t.Fatalf("SetInterfaceSecurityGroups on b: %v", err)
	}
	if got := b.ParkedUpdates(); got != 1 {
		t.Fatalf("parked = %d, want 1", got)
	}
	applyWAL(t, rb, walEntries(t, a, "node-a"))

	ifaces, err := GetVMInterfaces(ctx, b, "vm1")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 || len(ifaces[0].SecurityGroups) != 1 || ifaces[0].SecurityGroups[0] != "web" {
		t.Fatalf("b: interfaces = %+v; want the bind b made", ifaces)
	}
}
