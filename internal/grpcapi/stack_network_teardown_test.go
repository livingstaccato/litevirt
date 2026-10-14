package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// deprovRecorder is a NetworkProvisioner that records each Deprovision.
type deprovRecorder struct {
	bridgeRemovalProv
	deprovisioned []string
}

func (p *deprovRecorder) Deprovision(_ context.Context, _ *corrosion.Client, name string, _ compose.NetworkDef, _ string) error {
	p.deprovisioned = append(p.deprovisioned, name)
	return nil
}

// A stack delete tore its networks down on this host without asking whether
// anything here still used them, which `lv network rm` does (networkUseHere):
// a stopped VM on the network lost the bridge litevirt had created for it, and
// a VM start does not re-create it. The record is still deleted; the network
// reconciler tears the network down here once nothing uses it.
func TestDeprovisionNetworkByName_WaitsWhileAWorkloadHereUsesIt(t *testing.T) {
	ctx := adminCtx()
	for _, tc := range []struct {
		name, vmHost string
		wantTeardown bool
	}{
		{"a stopped VM on this host: teardown waits", "test-host", false},
		{"a VM on another host only: torn down here", "other-host", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerR2(t)
			prov := &deprovRecorder{}
			s.SetNetworkProvisioner(prov)
			if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
				Name: "st_net", StackName: "st", Type: "bridge", Config: `{"interface":"lvtstnet0"}`,
			}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "kept", HostName: tc.vmHost, State: "stopped", Spec: "{}"},
				[]corrosion.InterfaceRecord{{VMName: "kept", NetworkName: "st_net", Ordinal: 0, MAC: "52:54:00:00:00:09"}}, nil); err != nil {
				t.Fatal(err)
			}
			if err := s.deprovisionNetworkByName(ctx, "st_net"); err != nil {
				t.Fatalf("deprovisionNetworkByName: %v", err)
			}
			if got := len(prov.deprovisioned) == 1; got != tc.wantTeardown {
				t.Fatalf("Deprovision calls = %v, want teardown %v", prov.deprovisioned, tc.wantTeardown)
			}
			if nr, err := corrosion.GetNetwork(ctx, s.db, "st_net"); err != nil || nr != nil {
				t.Fatalf("network record after the delete = %+v, %v; want it deleted", nr, err)
			}
		})
	}
}
