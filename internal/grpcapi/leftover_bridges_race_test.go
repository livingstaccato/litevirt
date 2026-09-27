package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// bridgeRemovalProv is a NetworkProvisioner that records RemoveUnusedBridge
// calls and runs onRemove first, so a test can change the database between the
// leftover scan and a later removal.
type bridgeRemovalProv struct {
	removed  []string
	onRemove func(name string)
}

func (p *bridgeRemovalProv) Provision(context.Context, *corrosion.Client, string, compose.NetworkDef, string, string) (string, error) {
	return "", nil
}
func (p *bridgeRemovalProv) Deprovision(context.Context, *corrosion.Client, string, compose.NetworkDef, string) error {
	return nil
}
func (p *bridgeRemovalProv) Provisioned(string, compose.NetworkDef) bool { return true }
func (p *bridgeRemovalProv) RemoveUnusedBridge(name string) (bool, error) {
	if p.onRemove != nil {
		p.onRemove(name)
	}
	p.removed = append(p.removed, name)
	return true, nil
}

// The leftover scan reads which networks exist once, then removes bridges one
// by one. A network created under one of those names after the read — its
// bridge now fresh and wanted — must not lose that bridge.
func TestRemoveLeftoverStackBridges_RechecksEachNameBeforeRemoving(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "hc", ComposeYAML: "vms: {}\n", State: "running"}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"hc_a", "hc_b"} {
		if err := s.db.Execute(ctx,
			`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at, deleted_at)
			 VALUES ('old', ?, 0, '52:54:00:00:00:01', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')`, n); err != nil {
			t.Fatal(err)
		}
	}
	prov := &bridgeRemovalProv{}
	prov.onRemove = func(name string) {
		if name == "hc_a" {
			// While hc_a is being removed, an operator creates network hc_b.
			if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "hc_b", Type: "bridge", Config: "{}"}); err != nil {
				t.Error(err)
			}
		}
	}
	s.SetNetworkProvisioner(prov)

	s.removeLeftoverStackBridges(ctx, nil)

	for _, n := range prov.removed {
		if n == "hc_b" {
			t.Fatalf("removed bridge hc_b after network hc_b was created (removed %v)", prov.removed)
		}
	}
	if len(prov.removed) != 1 || prov.removed[0] != "hc_a" {
		t.Errorf("removed %v, want only hc_a", prov.removed)
	}
}
