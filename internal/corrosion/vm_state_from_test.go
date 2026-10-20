package corrosion

import (
	"context"
	"testing"
)

// UpdateVMStateFrom writes a VM's state only while the row is still the
// given host's and in the given state, read inside the write's transaction;
// a row another writer changed meanwhile, or that is absent, is left as it
// is.
//
// Mutation: make the guard return true — the migrating row is overwritten.
func TestUpdateVMStateFrom(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "web", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	row := func() VMRecord {
		r, err := GetVM(ctx, c, "web")
		if err != nil || r == nil {
			t.Fatalf("GetVM: %+v %v", r, err)
		}
		return *r
	}
	if ok, err := UpdateVMStateFrom(ctx, c, "web", "h1", "running", "error", "restart failed"); err != nil || !ok {
		t.Fatalf("running→error on h1: applied=%v err=%v", ok, err)
	}
	if r := row(); r.State != "error" || r.StateDetail != "restart failed" {
		t.Fatalf("after the write: %+v", r)
	}
	if err := UpdateVMState(ctx, c, "web", "migrating", "→ h2"); err != nil {
		t.Fatal(err)
	}
	if ok, err := UpdateVMStateFrom(ctx, c, "web", "h1", "running", "error", "late"); err != nil || ok {
		t.Fatalf("a migrating row: applied=%v err=%v", ok, err)
	}
	if r := row(); r.State != "migrating" || r.StateDetail != "→ h2" {
		t.Fatalf("the migrating row was changed: %+v", r)
	}
	if err := UpdateVMHost(ctx, c, "web", "h2", "running"); err != nil {
		t.Fatal(err)
	}
	if ok, err := UpdateVMStateFrom(ctx, c, "web", "h1", "running", "error", "late"); err != nil || ok {
		t.Fatalf("another host's row: applied=%v err=%v", ok, err)
	}
	if r := row(); r.State != "running" || r.HostName != "h2" {
		t.Fatalf("h2's row was changed: %+v", r)
	}
	if ok, err := UpdateVMStateFrom(ctx, c, "nobody", "h1", "running", "error", ""); err != nil || ok {
		t.Fatalf("an absent VM: applied=%v err=%v", ok, err)
	}
}
