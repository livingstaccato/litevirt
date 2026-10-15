package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

func putNetwork(t *testing.T, s *Server, name, typ string, def compose.NetworkDef) {
	t.Helper()
	def.Type = typ
	cfg, _ := json.Marshal(def)
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{Name: name, Type: typ, Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
}

// TestLBVIPInterface_OnTheNetworksBridge: a VIP inside a network's subnet goes
// on that network's bridge here, even when the bridge carries no address in
// the subnet (a host-isolated bridge network: lab 1 LBAndSNAT, where the
// address lookup fell back to the default-route device and the VIP's /24 took
// the backends' route off the bridge). The most specific subnet wins.
//
// Mutation: return lb.DetectInterfaceForIP first — red (no device on the test
// host holds 10.202.0.0/24, so it answers the default-route device).
func TestLBVIPInterface_OnTheNetworksBridge(t *testing.T) {
	s := testServer(t)
	s.SetBridgeExists(func(string) bool { return true })
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	putNetwork(t, s, "wide", "bridge", compose.NetworkDef{Interface: "brwide", Subnet: "10.202.0.0/16"})
	putNetwork(t, s, "ovl", "vxlan", compose.NetworkDef{VNI: 1000, Subnet: "10.100.0.0/24", HostIsolation: true})
	putNetwork(t, s, "iso", "isolated", compose.NetworkDef{Subnet: "10.150.0.0/24"})
	ctx := context.Background()
	for vip, want := range map[string]string{
		"10.202.0.250": "hinet",
		"10.202.9.1":   "brwide",
		"10.100.0.50":  "br-vni1000",
		"10.150.0.9":   compose.IsolatedBridgeName("iso"),
	} {
		got, err := s.lbVIPInterface(ctx, "", vip)
		if err != nil || got != want {
			t.Errorf("VIP %s: interface %q, %v; want %q", vip, got, err, want)
		}
	}
}

// TestLBVIPInterface_RefusesWhenTheBridgeIsNotHere: a VIP in a network's
// subnet whose bridge is not on this host is refused, naming the network and
// the bridge, rather than placed on an unrelated uplink.
//
// Mutation: fall back to lb.DetectInterfaceForIP instead of refusing — red.
func TestLBVIPInterface_RefusesWhenTheBridgeIsNotHere(t *testing.T) {
	s := testServer(t)
	s.SetBridgeExists(func(string) bool { return false })
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	got, err := s.lbVIPInterface(context.Background(), "", "10.202.0.250")
	if err == nil {
		t.Fatalf("VIP placed on %q with the network's bridge absent, want refused", got)
	}
	for _, want := range []string{"10.202.0.250", "lbr_hinet", "hinet"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}

// TestLBVIPInterface_OutsideEveryNetwork: a VIP in no network's subnet (an
// address on the host's own LAN) keeps the address lookup it always had.
func TestLBVIPInterface_OutsideEveryNetwork(t *testing.T) {
	s := testServer(t)
	s.SetBridgeExists(func(string) bool { return true })
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24"})
	got, err := s.lbVIPInterface(context.Background(), "", "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if want := lb.DetectInterfaceForIP("192.0.2.50"); got != want {
		t.Errorf("interface %q, want the address lookup's %q", got, want)
	}
}

// TestApplyLBForStack_VIPOnTheNetworksBridge: the stack apply path hands
// keepalived the network's bridge, and records the LB's isolation intent on
// it — the lab's `snat=false` came from that intent looking up the uplink.
//
// Mutation: give applyLBForStack's config lb.DetectInterfaceForIP — red.
func TestApplyLBForStack_VIPOnTheNetworksBridge(t *testing.T) {
	s := testServer(t)
	s.SetBridgeExists(func(string) bool { return true })
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	var applied []lb.Config
	s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }
	ctx := context.Background()
	if err := s.applyLBForStack(ctx, "lbr-lb", "10.202.0.250/24", lbSettings{Ports: []lb.Port{{Listen: 80, Target: 8080, Protocol: "tcp"}}},
		[]lb.Backend{{Name: "lbr1", IP: "10.202.0.72", Port: 8080}}, []string{s.hostName}, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(applied) != 1 || applied[0].Interface != "hinet" {
		t.Fatalf("applied %+v, want one config on hinet", applied)
	}
	intents, err := corrosion.ListHostFWIntent(ctx, s.db, s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	var lbIntent *corrosion.HostFWIntent
	for i := range intents {
		if intents[i].ScopeKey == "lb:lbr-lb" {
			lbIntent = &intents[i]
		}
	}
	if lbIntent == nil || lbIntent.Bridge != "hinet" || len(lbIntent.Exceptions) != 1 || lbIntent.Exceptions[0].VIP != "10.202.0.250" {
		t.Errorf("LB isolation intent %+v, want VIP holes on hinet", lbIntent)
	}
}

// TestLBVIPInterface_PrefersTheLBsOwnStack: two stacks may each have a
// network on the same subnet; a stack LB's VIP goes on its own stack's
// network's bridge, not on whichever network sorts first.
//
// Mutation: drop the own-stack preference — red (a_lan sorts first).
func TestLBVIPInterface_PrefersTheLBsOwnStack(t *testing.T) {
	s := testServer(t)
	s.SetBridgeExists(func(string) bool { return true })
	ctx := context.Background()
	for _, n := range []struct {
		name, stack string
		vni         int
	}{{"a_lan", "a", 10}, {"b_lan", "b", 11}} {
		cfg, _ := json.Marshal(compose.NetworkDef{Type: "vxlan", VNI: n.vni, Subnet: "10.10.0.0/24"})
		if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: n.name, StackName: n.stack, Type: "vxlan", Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.PersistLBFull(ctx, s.db, corrosion.LBConfigRecord{
		Name: "b-lb", StackName: "b", VIP: "10.10.0.50/24", Hosts: `["test-host"]`, Ports: "[]", Enabled: true,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.lbVIPInterface(ctx, "b-lb", "10.10.0.50"); err != nil || got != "br-vni11" {
		t.Errorf("stack b's LB: %q, %v; want stack b's bridge br-vni11", got, err)
	}
	if got, err := s.lbVIPInterface(ctx, "", "10.10.0.50"); err != nil || got != "br-vni10" {
		t.Errorf("no LB row: %q, %v; want the first by name, br-vni10", got, err)
	}
}
