package corrosion

import (
	"context"
	"reflect"
	"testing"

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
