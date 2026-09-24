package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A vxlan network's host bridge is br-vni<VNI>: that is the device Provision
// creates and returns. `lv network create` stores interface=<name> on every
// network, so resolveBridge used to hand the NIC paths that trust it (hot
// attach, restart, containers) a bridge named after the network, which
// provisioning never creates.
func TestResolveBridge_VXLANNamesTheProvisionedBridge(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "ov",
		Type:   "vxlan",
		Config: `{"interface":"ov","vni":500}`,
	}); err != nil {
		t.Fatalf("seed network: %v", err)
	}

	if got := resolveBridge(ctx, s.db, "ov"); got != "br-vni500" {
		t.Errorf("resolveBridge = %q, want br-vni500 (the bridge Provision creates)", got)
	}
}
