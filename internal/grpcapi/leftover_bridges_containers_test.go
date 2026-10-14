package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// The leftover-stack-bridge sweep proved a flat stack bridge unused from the
// VM NIC tables only. A container on this host on the bridge — by an
// interface row on its name, or by a raw `bridge=` NIC that only its create
// spec records — was invisible, and a stopped container lost its bridge. The
// sweep now asks the same question the network teardown does
// (network.BridgeNamedByWorkload): is the bridge still named by a workload on
// this host.
//
// Mutation: skip the workload check in removeBridgeIfUnusedHere — both
// containers' bridges are removed.
func TestRemoveLeftoverStackBridges_KeepsABridgeAContainerHereNames(t *testing.T) {
	for name, seed := range map[string]func(t *testing.T, s *Server){
		"an interface row on the bridge's name": func(t *testing.T, s *Server) {
			if err := corrosion.UpsertContainerInterface(adminCtx(), s.db, corrosion.ContainerInterfaceRecord{
				HostName: s.hostName, CtName: "ct1", NetworkName: "hc_a", Ordinal: 0, MAC: "52:54:00:00:00:03",
			}); err != nil {
				t.Fatal(err)
			}
		},
		"a raw bridge NIC in its create spec": func(t *testing.T, s *Server) {
			if err := s.db.Execute(adminCtx(), `UPDATE containers SET create_spec = ? WHERE name = 'ct1'`,
				`{"networks":[{"name":"eth0","bridge":"`+network.FlatBridgeName("hc_a")+`"}]}`); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := testServerCov(t)
			ctx := adminCtx()
			if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "hc", ComposeYAML: "vms: {}\n", State: "running"}); err != nil {
				t.Fatal(err)
			}
			// A VM once used hc_a; its row is gone, so the VM tables call
			// the bridge unused.
			if err := s.db.Execute(ctx,
				`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at, deleted_at)
				 VALUES ('old', 'hc_a', 0, '52:54:00:00:00:01', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
				HostName: s.hostName, Name: "ct1", State: "stopped",
			}); err != nil {
				t.Fatal(err)
			}
			seed(t, s)
			prov := &bridgeRemovalProv{}
			s.SetNetworkProvisioner(prov)

			s.removeLeftoverStackBridges(ctx, nil)

			if len(prov.removed) != 0 {
				t.Errorf("removed %v although a container on this host attaches to it", prov.removed)
			}
		})
	}
}
