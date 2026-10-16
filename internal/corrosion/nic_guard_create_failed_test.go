package corrosion

import (
	"context"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// failedCreateFixture is a name with no VM row whose guard records two
// incarnations wrote: "old" (a create that failed, on a build that left its
// records live) and "new" (a create in flight now).
func failedCreateFixture(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	c := nicGuardDB(t, true)
	for _, r := range []NICGuardRecord{
		{VMName: "fc", MAC: "52:54:00:00:01:01", Mode: NICGuardOn, VMUUID: "old"},
		{VMName: "fc", MAC: "52:54:00:00:01:02", Mode: NICGuardOn, VMUUID: "old", Ordinal: 1},
		{VMName: "fc", MAC: "52:54:00:00:02:01", Mode: NICGuardOn, VMUUID: "new"},
	} {
		if err := PutNICGuard(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), r, "t"); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// TestGuardedMACsOfIncarnation_DemandsOnlyTheCreatingIncarnation (lab 2,
// F-B): a create of a name another incarnation's create left guard records
// under demands its own records only; with no incarnation named, every record
// of a row-less name is demanded, as before.
func TestGuardedMACsOfIncarnation_DemandsOnlyTheCreatingIncarnation(t *testing.T) {
	ctx := context.Background()
	c := failedCreateFixture(t)
	got, err := GuardedMACsOfIncarnation(ctx, c, "fc", "new")
	if err != nil || !reflect.DeepEqual(got, []string{"52:54:00:00:02:01"}) {
		t.Errorf("creating incarnation new demands %v, %v; want its own record only", got, err)
	}
	all, err := GuardedMACsOf(ctx, c, "fc")
	if err != nil || len(all) != 3 {
		t.Errorf("no incarnation named: %v, %v; want all three records", all, err)
	}
}

// TestGuardedMACsOfIncarnation_CreatingWinsOverTheRowItReplaces: a re-create
// on a replica that still holds the row it replaces demands the new
// incarnation's records, not the old row's.
func TestGuardedMACsOfIncarnation_CreatingWinsOverTheRowItReplaces(t *testing.T) {
	ctx := context.Background()
	c := failedCreateFixture(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "fc", HostName: "h", State: "running",
		Spec: `{"name":"fc","uuid":"old"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	got, err := GuardedMACsOfIncarnation(ctx, c, "fc", "new")
	if err != nil || !reflect.DeepEqual(got, []string{"52:54:00:00:02:01"}) {
		t.Errorf("creating incarnation new over row old demands %v, %v", got, err)
	}
}

// TestRetireNICGuardsOfIncarnation_RetiresOnlyItsOwn: a failed create
// retires the records its incarnation wrote and no other — not another
// incarnation's record of the same MAC, not another MAC.
func TestRetireNICGuardsOfIncarnation_RetiresOnlyItsOwn(t *testing.T) {
	ctx := context.Background()
	c := failedCreateFixture(t)
	macs := []string{"52:54:00:00:01:01", "52:54:00:00:01:02", "52:54:00:00:02:01", "52:54:00:00:09:09"}
	if err := RetireNICGuardsOfIncarnation(ctx, c, "fc", "old", macs, "litevirt"); err != nil {
		t.Fatal(err)
	}
	for mac, live := range map[string]bool{
		"52:54:00:00:01:01": false, "52:54:00:00:01:02": false, "52:54:00:00:02:01": true,
	} {
		r, err := GetNICGuard(ctx, c, "fc", mac)
		if err != nil || (r != nil) != live {
			t.Errorf("record %s: %+v, %v; want live=%v", mac, r, err, live)
		}
	}
	// An empty incarnation retires nothing.
	if err := RetireNICGuardsOfIncarnation(ctx, c, "fc", "", macs, "litevirt"); err != nil {
		t.Fatal(err)
	}
	if r, _ := GetNICGuard(ctx, c, "fc", "52:54:00:00:02:01"); r == nil {
		t.Error("an empty incarnation retired a record")
	}
}
