package grpcapi

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

type sweepRecordingProv struct {
	hostNetworkProvisioner
	created []string
	removed *[]string
}

func (p sweepRecordingProv) CreatedBridges() ([]string, error) { return p.created, nil }

func (p sweepRecordingProv) RemoveOrphanedBridge(name string) (bool, error) {
	*p.removed = append(*p.removed, name)
	return true, nil
}

// The sweep keeps a bridge a VM is plugged into, and says a bridge "no network
// names is kept" only of one no live network names. A live network's bridge
// with a VM on it is kept without that line (lab 3, 2026-10-18: it was logged
// for the bridge of the drill's own network after every boot).
//
// Mutation: check the users before the network names (the old order) — red.
func TestSweepOrphanedBridges_InUseBridgeOfALiveNetworkIsNotCalledUnnamed(t *testing.T) {
	s := reconfigServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	var removed []string
	s.SetNetworkProvisioner(sweepRecordingProv{created: []string{"brnamed", "brorphan"}, removed: &removed})
	seedStackNetworkRow(t, s, "st", "net", compose.NetworkDef{Type: "bridge", Interface: "brnamed"})
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "vm1", CPU: 1, MemoryMiB: 256,
		Networks: []lv.NetworkConfig{{Bridge: "brnamed"}, {Bridge: "brorphan"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	logs := &lockedLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	st := &netReconcileState{applied: map[string]appliedNetwork{}, torn: map[string]string{}, lastErr: map[string]string{}}
	s.sweepOrphanedBridges(context.Background(), st, nil)

	if len(removed) != 0 {
		t.Fatalf("the sweep removed %v, both bridges are in use", removed)
	}
	out := logs.String()
	const unnamed = "a bridge litevirt made that no network names is kept"
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, unnamed) && strings.Contains(line, "bridge=brnamed") {
			t.Errorf("the bridge of a live network is logged as one no network names:\n%s", line)
		}
	}
	if !strings.Contains(out, unnamed) || !strings.Contains(out, "bridge=brorphan") {
		t.Errorf("the in-use bridge no network names is not logged:\n%s", out)
	}
}
