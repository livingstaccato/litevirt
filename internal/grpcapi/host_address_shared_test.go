package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Codex cand30 I1: no replica's guard sees an admission another replica has
// not yet sent it, so two admitters can still admit two names at one address.
// The lease holder names every such pair once it holds both rows, with the
// command that removes one, and resolves the condition when one is gone.
//
// Mutation: skip the evaluation — no condition is raised.
func TestHostAddressShared_NamesTwoHostsAtOneAddress(t *testing.T) {
	ctx := context.Background()
	s := admissionServer(t)
	for _, h := range []corrosion.HostRecord{
		{Name: "node-a", Address: "10.0.0.9", GRPCPort: admitGRPCPort, State: corrosion.HostStateJoining, CertSerial: "0a"},
		{Name: "node-b", Address: "10.0.0.9", GRPCPort: admitGRPCPort, State: "active", CertSerial: "0b"},
		// Not shared: another port, and the zero port of a pre-port row
		// at another address.
		{Name: "node-c", Address: "10.0.0.9", GRPCPort: 7500, State: "active", CertSerial: "0c"},
		{Name: "node-d", Address: "10.0.0.4", State: "active", CertSerial: "0d"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatal(err)
		}
	}
	s.applyHostAddressShared(ctx)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, hostAddressEvaluator, condHostAddressShared, "cluster", hostAddressSubject)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition = %+v, found %v, err %v; want it raised", row, found, err)
	}
	for _, want := range []string{"node-a", "node-b", "10.0.0.9", "lv host rm"} {
		if !strings.Contains(row.Evidence, want) {
			t.Errorf("detail %q does not name %q", row.Evidence, want)
		}
	}
	for _, not := range []string{"node-c", "node-d"} {
		if strings.Contains(row.Evidence, not) {
			t.Errorf("detail %q names %s, which shares nothing", row.Evidence, not)
		}
	}
	if err := corrosion.DeleteHost(ctx, s.db, "node-a"); err != nil {
		t.Fatal(err)
	}
	s.applyHostAddressShared(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, s.db, hostAddressEvaluator, condHostAddressShared, "cluster", hostAddressSubject)
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("condition %s after node-a's removal, want resolved", row.Lifecycle)
	}
}
