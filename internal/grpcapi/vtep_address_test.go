package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// vtepRecorder is a NetworkProvisioner that records the VTEP address each
// Provision is handed.
type vtepRecorder struct {
	bridgeRemovalProv
	localIPs []string
}

func (p *vtepRecorder) Provision(_ context.Context, _ *corrosion.Client, _ string, _ compose.NetworkDef, localIP, _ string) (string, error) {
	p.localIPs = append(p.localIPs, localIP)
	return "br-vni5177", nil
}

// Every path that provisions a network on this host hands the provisioner the
// host's cluster address (advertise_address), not the default-route source
// address: on the lab the latter was 10.0.2.15 on every node, so each host's
// VTEP — and its flood entry for every peer — was itself.
func TestVXLANProvisioning_UsesTheHostAddress(t *testing.T) {
	ctx := adminCtx()
	s := testServerR2(t)
	prov := &vtepRecorder{}
	s.SetNetworkProvisioner(prov)
	s.SetHostAddress("10.77.0.11")
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "vxd_vxdnet", Type: "vxlan", Config: `{"interface":"vxdnet","vni":5177}`,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.ReconcileNetworksOnce(ctx); err != nil { // the network reconciler
		t.Fatalf("ReconcileNetworksOnce: %v", err)
	}
	if _, err := s.provisionForVM(ctx, "vxd_vxdnet"); err != nil { // a VM create
		t.Fatalf("provisionForVM: %v", err)
	}
	if _, err := s.ensureNICNetworkProvisioned(ctx, "vxd_vxdnet"); err != nil { // a NIC hotplug
		t.Fatalf("ensureNICNetworkProvisioned: %v", err)
	}
	if len(prov.localIPs) != 3 {
		t.Fatalf("Provision calls = %v, want 3", prov.localIPs)
	}
	for i, ip := range prov.localIPs {
		if ip != "10.77.0.11" {
			t.Errorf("Provision call %d was handed VTEP %q, want the host address 10.77.0.11", i, ip)
		}
	}

	// The failover start path (health.Reconciler) goes through the same lookup
	// with the address it is handed.
	prov.localIPs = nil
	if _, err := network.ProvisionForVMWith(ctx, s.db, "vxd_vxdnet", s.hostName, s.VTEPAddress(), s.ProvisionNetworkHere); err != nil {
		t.Fatalf("ProvisionForVMWith: %v", err)
	}
	if len(prov.localIPs) != 1 || prov.localIPs[0] != "10.77.0.11" {
		t.Errorf("failover-start Provision was handed %v, want [10.77.0.11]", prov.localIPs)
	}
}
