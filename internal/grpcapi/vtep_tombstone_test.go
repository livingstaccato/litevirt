package grpcapi

import (
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

func liveVTEPs(t *testing.T, s *Server, name string) int {
	t.Helper()
	v, err := network.GetVTEPs(adminCtx(), s.db, name)
	if err != nil {
		t.Fatal(err)
	}
	return len(v)
}

// Deleting a network tombstones its network_vteps rows once the release token
// has latched — and not before, when a host on the previous build could not
// apply the statement and would back-pressure this host's stream.
func TestDeleteNetwork_TombstonesItsVTEPsOnceLatched(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gate    fakeFeatureGate
		wantVTE int
	}{
		{"latched: rows tombstoned", fakeFeatureGate{t: t}, 0},
		{"not latched: rows left as before", fakeFeatureGate{err: errors.New("upgrade in progress")}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := adminCtx()
			s := testServerR2(t)
			s.SetNetworkProvisioner(&vtepRecorder{})
			s.SetReleaseFeatureGate(tc.gate)
			if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
				Name: "vxd_vxdnet", Type: "vxlan", Config: `{"interface":"vxdnet","vni":5177}`,
			}); err != nil {
				t.Fatal(err)
			}
			for _, h := range []string{"node-1", "node-4"} {
				if err := network.UpsertVTEP(ctx, s.db, "vxd_vxdnet", h, "10.77.0.1"+h[5:], 5177); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.deleteNetworkRecord(ctx, "vxd_vxdnet"); err != nil {
				t.Fatalf("deleteNetworkRecord: %v", err)
			}
			if nr, err := corrosion.GetNetwork(ctx, s.db, "vxd_vxdnet"); err != nil || nr != nil {
				t.Fatalf("network after the delete = %+v, %v; want it deleted", nr, err)
			}
			if got := liveVTEPs(t, s, "vxd_vxdnet"); got != tc.wantVTE {
				t.Fatalf("live VTEP rows after the delete = %d, want %d", got, tc.wantVTE)
			}
		})
	}
}
