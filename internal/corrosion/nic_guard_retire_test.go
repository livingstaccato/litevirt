package corrosion

import (
	"context"
	"reflect"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

const (
	retireVM   = "web"
	retireUUID = "u-1"
	liveMAC    = "52:54:00:00:00:01"
	goneMAC    = "52:54:00:00:00:02"
)

func retireFixture(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	c := nicGuardDB(t, true)
	if err := InsertVM(ctx, c, VMRecord{Name: retireVM, HostName: "h", State: "running",
		Spec: `{"name":"web","uuid":"u-1"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for i, mac := range []string{liveMAC, goneMAC} {
		if err := UpsertNIC(ctx, c, NICRecord{VMName: retireVM, ID: DeterministicNICID(retireVM, mac),
			NetworkName: "lan", MAC: mac, Ordinal: i}); err != nil {
			t.Fatal(err)
		}
		if err := PutNICGuard(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
			NICGuardRecord{VMName: retireVM, MAC: mac, Mode: NICGuardOn, VMUUID: retireUUID, Ordinal: i}, "t"); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// TestRetireNICGuard_TombstonesOneRecord: retiring one NIC's record leaves it
// out of every reader, keeps what it held for a re-create, and touches no
// other record.
func TestRetireNICGuard_TombstonesOneRecord(t *testing.T) {
	ctx := context.Background()
	c := retireFixture(t)
	if err := RetireNICGuard(ctx, c, retireVM, "52:54:00:00:00:02", "t"); err != nil {
		t.Fatal(err)
	}
	if r, err := GetNICGuard(ctx, c, retireVM, goneMAC); err != nil || r != nil {
		t.Errorf("the retired record is still read: %+v, %v", r, err)
	}
	if r, _ := GetNICGuard(ctx, c, retireVM, liveMAC); r == nil {
		t.Error("retiring one NIC's record retired another's")
	}
	all, err := ListNICGuardsWithDeleted(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if r := all[NICGuardKey(retireVM, goneMAC)]; !r.Deleted || r.VMUUID != retireUUID || r.Mode != NICGuardOn {
		t.Errorf("the retired record does not keep what it held: %+v", r)
	}
	// Retiring nothing is not an error.
	if err := RetireNICGuard(ctx, c, retireVM, "52:54:00:00:00:77", "t"); err != nil {
		t.Errorf("retiring an absent record: %v", err)
	}
}

// TestGuardedMACsOf_LeavesOutARemovedNIC: a guard record whose NIC row was
// tombstoned after the record was written guards a NIC that no longer
// exists — no host can render it, so it is not demanded (lab 2, C3).
func TestGuardedMACsOf_LeavesOutARemovedNIC(t *testing.T) {
	ctx := context.Background()
	c := retireFixture(t)
	got, err := GuardedMACsOf(ctx, c, retireVM)
	if err != nil || !reflect.DeepEqual(got, []string{liveMAC, goneMAC}) {
		t.Fatalf("fixture: %v, %v", got, err)
	}
	if err := TombstoneNIC(ctx, c, retireVM, DeterministicNICID(retireVM, goneMAC)); err != nil {
		t.Fatal(err)
	}
	if got, _ := GuardedMACsOf(ctx, c, retireVM); !reflect.DeepEqual(got, []string{liveMAC}) {
		t.Errorf("a detached NIC's record is still demanded: %v", got)
	}
}

// TestGuardedMACsOf_KeepsARecordNewerThanTheTombstone: a record written
// after the NIC's row was tombstoned is a re-attach of that MAC whose row has
// not landed (here) yet; it is demanded, so a replica behind refuses rather
// than runs the NIC unguarded.
func TestGuardedMACsOf_KeepsARecordNewerThanTheTombstone(t *testing.T) {
	ctx := context.Background()
	c := retireFixture(t)
	if err := TombstoneNIC(ctx, c, retireVM, DeterministicNICID(retireVM, goneMAC)); err != nil {
		t.Fatal(err)
	}
	if err := PutNICGuard(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		NICGuardRecord{VMName: retireVM, MAC: goneMAC, Mode: NICGuardOn, VMUUID: retireUUID, Ordinal: 1}, "t"); err != nil {
		t.Fatal(err)
	}
	if got, _ := GuardedMACsOf(ctx, c, retireVM); !reflect.DeepEqual(got, []string{liveMAC, goneMAC}) {
		t.Errorf("a re-attach's record is not demanded: %v", got)
	}
}

// TestGuardedMACsOf_KeepsARecordWithNoRow: a record with no NIC row at all
// (a create or attach whose row has not landed here) is still demanded.
func TestGuardedMACsOf_KeepsARecordWithNoRow(t *testing.T) {
	ctx := context.Background()
	c := retireFixture(t)
	const pending = "52:54:00:00:00:03"
	if err := PutNICGuard(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		NICGuardRecord{VMName: retireVM, MAC: pending, Mode: NICGuardOn, VMUUID: retireUUID, Ordinal: 2}, "t"); err != nil {
		t.Fatal(err)
	}
	if got, _ := GuardedMACsOf(ctx, c, retireVM); !reflect.DeepEqual(got, []string{liveMAC, goneMAC, pending}) {
		t.Errorf("a record whose row has not landed is not demanded: %v", got)
	}
}

// TestGuardedMACsOf_DemandedWhileAnOperationHoldsTheVM (review m1): a detach
// that tombstoned the row and then failed leaves its operation in flight and
// may leave the NIC in the domain; its record is still demanded.
func TestGuardedMACsOf_DemandedWhileAnOperationHoldsTheVM(t *testing.T) {
	ctx := context.Background()
	c := retireFixture(t)
	vm, err := GetVM(ctx, c, retireVM)
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	if ok, err := c.BeginVMOperation(ctx, OperationRecord{ID: "op-1", Method: "DetachDevice", ResourceKind: "vm",
		ResourceID: retireVM, OperationKind: string(OpDeviceDetach), RequestHash: "h"}, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration); err != nil || !ok {
		t.Fatalf("begin: %v %v", ok, err)
	}
	if err := TombstoneNIC(ctx, c, retireVM, DeterministicNICID(retireVM, goneMAC)); err != nil {
		t.Fatal(err)
	}
	if got, _ := GuardedMACsOf(ctx, c, retireVM); !reflect.DeepEqual(got, []string{liveMAC, goneMAC}) {
		t.Errorf("a record whose detach is still in flight is not demanded: %v", got)
	}
}

// TestGuardedMACsOf_ARetiredRecordOverALiveRowGuards: a retired record of
// the incarnation that runs, over a NIC whose row is live, is a write order
// seen out of order; the NIC is demanded (and rendered guarded), never left
// unguarded.
func TestGuardedMACsOf_ARetiredRecordOverALiveRowGuards(t *testing.T) {
	ctx := context.Background()
	c := retireFixture(t)
	if err := RetireNICGuard(ctx, c, retireVM, goneMAC, "t"); err != nil {
		t.Fatal(err)
	}
	if got, _ := GuardedMACsOf(ctx, c, retireVM); !reflect.DeepEqual(got, []string{liveMAC, goneMAC}) {
		t.Errorf("a NIC with a live row lost its guard to a retired record: %v", got)
	}
	if _, ok := RetiredGuardOver(NICGuardRecord{Deleted: true, VMUUID: "other"}, retireUUID); ok {
		t.Error("another incarnation's retired record guards this one")
	}
	if _, ok := RetiredGuardOver(NICGuardRecord{Deleted: true}, retireUUID); ok {
		t.Error("a retired record of an unknown incarnation guards this one")
	}
}

// shipWALRange applies src's entries with after < seq <= upto to dst.
func shipWALRange(t *testing.T, src, dst *Client, after, upto int64) {
	t.Helper()
	var tail []*pb.MutationEntry
	for _, e := range walEntries(t, src, "src") {
		if e.Seq > after && e.Seq <= upto {
			tail = append(tail, e)
		}
	}
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), tail); err != nil {
		t.Fatalf("ship: %v", err)
	}
}

// TestNICGuard_FastClockReattachStaysGuarded (review I1): host A's clock runs
// a minute ahead. A detaches NIC M (row tombstone and retired record stamped
// in A's future); the VM moves to B, which re-attaches M at once. On a third
// replica C — with only B's record, and then with all of it — M is demanded,
// and B's record is live, not shadowed by A's retire.
func TestNICGuard_FastClockReattachStaysGuarded(t *testing.T) {
	ctx := context.Background()
	open := func() *Client {
		c := newTestDB(t)
		c.SetClusterPolicyGate(func() bool { return true })
		return c
	}
	a, b, c := open(), open(), open()
	a.nowFn = func() time.Time { return time.Now().Add(time.Minute) }
	grant := capabilities.GrantForTest(t, capabilities.FeatureNICGuards)
	const m = "52:54:00:00:00:0c"
	id := DeterministicNICID(retireVM, m)

	if err := InsertVM(ctx, a, VMRecord{Name: retireVM, HostName: "a", State: "running",
		Spec: `{"name":"web","uuid":"u-1"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := UpsertNIC(ctx, a, NICRecord{VMName: retireVM, ID: id, NetworkName: "lan", MAC: m}); err != nil {
		t.Fatal(err)
	}
	if err := PutNICGuard(ctx, a, grant, NICGuardRecord{VMName: retireVM, MAC: m, Mode: NICGuardOn, VMUUID: retireUUID}, "t"); err != nil {
		t.Fatal(err)
	}
	// A detaches M.
	if err := TombstoneNIC(ctx, a, retireVM, id); err != nil {
		t.Fatal(err)
	}
	if err := RetireNICGuard(ctx, a, retireVM, m, "t"); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []*Client{b, c} {
		if _, err := shipWAL(t, a, dst, 0); err != nil {
			t.Fatalf("ship A: %v", err)
		}
	}

	// B re-attaches M within A's lead: record first, then the row.
	before := lastWALSeq(t, b)
	if err := PutNICGuard(ctx, b, grant, NICGuardRecord{VMName: retireVM, MAC: m, Mode: NICGuardOn, VMUUID: retireUUID}, "t"); err != nil {
		t.Fatal(err)
	}
	recSeq := lastWALSeq(t, b)
	if err := UpsertNIC(ctx, b, NICRecord{VMName: retireVM, ID: id, NetworkName: "lan", MAC: m}); err != nil {
		t.Fatal(err)
	}

	// C holds B's record, its row not yet.
	shipWALRange(t, b, c, before, recSeq)
	if got, err := GuardedMACsOf(ctx, c, retireVM); err != nil || !reflect.DeepEqual(got, []string{m}) {
		t.Errorf("with the re-attach's record only, C demands %v (%v); want %s", got, err, m)
	}
	// C holds all of it.
	shipWALRange(t, b, c, recSeq, lastWALSeq(t, b))
	if got, err := GuardedMACsOf(ctx, c, retireVM); err != nil || !reflect.DeepEqual(got, []string{m}) {
		t.Errorf("with the re-attach applied, C demands %v (%v); want %s", got, err, m)
	}
	if r, _ := GetNICGuard(ctx, c, retireVM, m); r == nil {
		t.Error("A's earlier retire shadows B's later record on C")
	}
	if nics, _ := MergedVMNICs(ctx, c, retireVM); len(nics) != 1 {
		t.Errorf("A's earlier row tombstone shadows B's later row on C: %+v", nics)
	}
}
