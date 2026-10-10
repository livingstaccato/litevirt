package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
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
func (p *bridgeRemovalProv) GuestPorts(string) ([]string, error)         { return nil, nil }
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

// A stack network whose "<stack>_<name>" exceeds IFNAMSIZ can never have been
// a flat bridge by that name, so the cleanup must ask about the hashed
// flat-bridge name — an impossible interface name would fail every 30s forever.
func TestRemoveLeftoverStackBridges_LongNameUsesFlatBridgeName(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "hc", ComposeYAML: "vms: {}\n", State: "running"}); err != nil {
		t.Fatal(err)
	}
	long := "hc_averyverylongnetworkname"
	if err := s.db.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at, deleted_at)
		 VALUES ('old', ?, 0, '52:54:00:00:00:01', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')`, long); err != nil {
		t.Fatal(err)
	}
	prov := &bridgeRemovalProv{}
	s.SetNetworkProvisioner(prov)

	s.removeLeftoverStackBridges(ctx, nil)

	if len(prov.removed) != 1 || prov.removed[0] != network.FlatBridgeName(long) || len(prov.removed[0]) > 15 {
		t.Errorf("asked to remove %v, want [%s] (<=15 bytes)", prov.removed, network.FlatBridgeName(long))
	}
}

type failingRemoveProv struct {
	bridgeRemovalProv
	calls int
}

func (p *failingRemoveProv) RemoveUnusedBridge(name string) (bool, error) {
	p.calls++
	return false, errors.New("interface name is not valid")
}

// A removal that keeps failing is attempted every pass but logged once.
func TestRemoveBridgeIfUnusedHere_FailureLoggedOnce(t *testing.T) {
	s := testServerCov(t)
	prov := &failingRemoveProv{}
	s.SetNetworkProvisioner(prov)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	for i := 0; i < 5; i++ {
		s.removeBridgeIfUnusedHere("hc_bad")
	}
	if prov.calls != 5 {
		t.Errorf("removal attempted %d times, want 5 (the pass still retries)", prov.calls)
	}
	if n := strings.Count(buf.String(), "remove leftover stack bridge failed"); n != 1 {
		t.Errorf("failure logged %d times, want 1:\n%s", n, buf.String())
	}
}
