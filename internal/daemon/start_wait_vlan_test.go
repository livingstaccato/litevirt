package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// A start of a VM with a trunk NIC waits for the start guard, NIC guard or
// not: the guard is what puts its VLANs on its taps before the guest runs,
// and an access NIC started without it runs on VLAN 1 (after a host boot, an
// onboot start can come before the guard is wired). A VM with neither a guard
// nor a trunk starts as before. The daemon's wiring of the predicate is the
// server's HasTapVLANs, or grpcapi.VMHasTapVLANs before the server is up;
// this is the latter, over the rows.
//
// Mutation: drop the vlans term from startWaitNeeded — red.
func TestStartWaitPredicate_TapVLANsWait(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	for name, spec := range map[string]string{
		"plain":  `{"name":"plain","network":[{"name":"net0"}]}`,
		"access": `{"name":"access","network":[{"name":"net0","trunk":[30]}]}`,
		"trunk":  `{"name":"trunk","network":[{"name":"net0","trunk":[100,101]}]}`,
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: name, HostName: "h1", State: "stopped", Spec: spec}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	wait := startWaitNeeded(db, func(string) string { return "" }, func(ctx context.Context, name string) bool {
		return grpcapi.VMHasTapVLANs(ctx, db, name)
	})
	if wait("plain") {
		t.Error("a VM with no NIC guard and no trunk waits for the start guard")
	}
	for _, vm := range []string{"access", "trunk"} {
		if !wait(vm) {
			t.Errorf("%s: a VM with a trunk NIC starts without the start guard, so its VLANs are never put on its tap", vm)
		}
	}
	if wait("absent") {
		t.Error("a domain with no VM row waits")
	}
}
