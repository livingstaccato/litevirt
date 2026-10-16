package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// applySNATLB applies a two-host stack LB on a host-isolated network's bridge
// and returns the config handed to the LB manager.
func applySNATLB(t *testing.T, snat bool, hosts []string) lb.Config {
	t.Helper()
	s := testServer(t)
	isolateLBEffects(t, s)
	s.SetBridgeExists(func(string) bool { return true })
	ctx := context.Background()
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	for name, addr := range map[string]string{s.hostName: "192.0.2.11", "peer-host": "192.0.2.12"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: name, Address: addr, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	var applied []lb.Config
	s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }
	if err := s.applyLBForStack(ctx, "lbr-lb", "10.202.0.250/24",
		lb.Settings{Algorithm: "roundrobin", Ports: []lb.Port{{Listen: 80, Target: 8080, Protocol: "tcp"}}},
		[]lb.Backend{{Name: "lbr1", IP: "10.202.0.72", Port: 8080}}, hosts, snat); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied %d configs, want 1", len(applied))
	}
	return applied[0]
}

// TestApplyLBForStack_SNATRunsConntrackd: a stack LB with snat on two hosts
// hands the LB manager a config that runs conntrackd, syncing with the other
// LB host over the hosts' own addresses for the network's subnet. Before,
// SNATEnabled was set nowhere and conntrackd never ran.
//
// Mutation: drop the lbSNATSync call in applyLBForStack — red.
func TestApplyLBForStack_SNATRunsConntrackd(t *testing.T) {
	c := applySNATLB(t, true, []string{"test-host", "peer-host"})
	if !c.SNATEnabled || c.LocalIP != "192.0.2.11" || c.PeerIP != "192.0.2.12" || c.Subnet != "10.202.0.0/24" {
		t.Errorf("SNAT sync enabled=%v local=%q peer=%q subnet=%q, want true 192.0.2.11 192.0.2.12 10.202.0.0/24",
			c.SNATEnabled, c.LocalIP, c.PeerIP, c.Subnet)
	}
	// The backup syncs with the master, the first host.
	c = applySNATLB(t, true, []string{"peer-host", "test-host"})
	if !c.SNATEnabled || c.PeerIP != "192.0.2.12" {
		t.Errorf("backup: SNAT sync enabled=%v peer=%q, want true 192.0.2.12", c.SNATEnabled, c.PeerIP)
	}
}

// TestApplyLBForStack_NoSNATNoConntrackd: without snat, or with no other LB
// host to sync with, no conntrackd.
func TestApplyLBForStack_NoSNATNoConntrackd(t *testing.T) {
	if c := applySNATLB(t, false, []string{"test-host", "peer-host"}); c.SNATEnabled || c.PeerIP != "" {
		t.Errorf("snat off: SNAT sync enabled=%v peer=%q, want off", c.SNATEnabled, c.PeerIP)
	}
	if c := applySNATLB(t, true, []string{"test-host"}); c.SNATEnabled {
		t.Errorf("one LB host: SNAT sync enabled, want off (no peer)")
	}
}
