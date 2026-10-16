package grpcapi

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// vrrpServer is a peer-auth server whose hosts are recorded at addresses
// (self 192.0.2.11, peer-1 127.0.0.1, peer-2 192.0.2.12), with
// enforcement.vrrp_unicast at flag and vrrp_unicast_v1 latched in memory at
// latched and durably at durable.
func vrrpServer(t *testing.T, flag, latched, durable bool) *Server {
	t.Helper()
	s := newPeerAuthServer(t)
	s.SetBridgeExists(func(string) bool { return true })
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: s.hostName, Address: "192.0.2.11", State: "active"},
		{Name: "peer-2", Address: "192.0.2.12", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatal(err)
		}
	}
	s.SetVRRPUnicast(flag)
	s.SetGate(fakeServerGate{
		enforcedTok:       map[string]bool{capabilities.VRRPUnicastV1: latched},
		durablyLatchedTok: map[string]bool{capabilities.VRRPUnicastV1: durable},
	})
	s.lbIfaceForIPOverride = func(ip string) string {
		if ip == "192.0.2.11" {
			return "eth-host"
		}
		return "wrong-device"
	}
	return s
}

// peerApply runs a forwarded ApplyLB of a three-host LB on a host-isolated
// network's bridge (hinet) and returns what reached the LB manager.
func peerApply(t *testing.T, s *Server, hosts []string) ([]lb.Config, error) {
	t.Helper()
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	var applied []lb.Config
	s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }
	_, err := s.ApplyLB(mtlsCtx("peer-1"), &pb.ApplyLBRequest{
		LbName: "lbr-lb", Vip: "10.202.0.250/24", Hosts: hosts,
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackend{{VmName: "lbr1", Address: "10.202.0.72"}},
	})
	return applied, err
}

// TestApplyLB_VRRPUnicastOnceDurablyLatched: an LB host sends its VRRP as
// unicast between the LB hosts' recorded addresses, over the device holding
// its own, only with enforcement.vrrp_unicast on AND vrrp_unicast_v1 durably
// latched. Before that every host renders the multicast transport, which is
// what a peer on an earlier build renders, so the two still hear each other.
//
// Mutations (each red): render unicast on the flag alone; on Latched rather
// than DurablyLatched; leave a peer out; send from the VIP's bridge.
func TestApplyLB_VRRPUnicastOnceDurablyLatched(t *testing.T) {
	hosts := []string{"peer-1", "self", "peer-2"}
	for _, tc := range []struct {
		name                   string
		flag, latched, durable bool
		unicast                bool
	}{
		{"flag on, durably latched", true, true, true, true},
		{"flag on, latched in memory only", true, true, false, false},
		{"flag on, not latched", true, false, false, false},
		{"flag off, durably latched", false, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applied, err := peerApply(t, vrrpServer(t, tc.flag, tc.latched, tc.durable), hosts)
			if err != nil || len(applied) != 1 {
				t.Fatalf("ApplyLB: %v (applied %d)", err, len(applied))
			}
			c := applied[0]
			if c.VRRPUnicast != tc.unicast {
				t.Fatalf("VRRPUnicast = %v, want %v", c.VRRPUnicast, tc.unicast)
			}
			if c.Interface != "hinet" {
				t.Errorf("VIP device = %q, want the network's bridge hinet", c.Interface)
			}
			if !tc.unicast {
				if c.UnicastSrc != "" || len(c.UnicastPeers) != 0 || c.VRRPInterface != "" {
					t.Errorf("multicast config carries unicast fields: %+v", c)
				}
				return
			}
			if c.UnicastSrc != "192.0.2.11" || c.VRRPInterface != "eth-host" {
				t.Errorf("source %q on %q, want 192.0.2.11 on eth-host", c.UnicastSrc, c.VRRPInterface)
			}
			peers := slices.Clone(c.UnicastPeers)
			slices.Sort(peers)
			if !slices.Equal(peers, []string{"127.0.0.1", "192.0.2.12"}) {
				t.Errorf("peers = %v, want peer-1 and peer-2's addresses", c.UnicastPeers)
			}
		})
	}
}

// TestApplyLB_VRRPUnicastRefusesAnUnnamedPeer: a host that cannot name one of
// its LB peers does not apply, rather than render a peer set short of it (and
// hold the VIP beside it).
//
// Mutation: skip a host with no recorded address — red.
func TestApplyLB_VRRPUnicastRefusesAnUnnamedPeer(t *testing.T) {
	applied, err := peerApply(t, vrrpServer(t, true, true, true), []string{"self", "ghost"})
	if err == nil || len(applied) != 0 {
		t.Fatalf("applied %d configs (err %v), want the apply refused", len(applied), err)
	}
}

// TestReconcileDeadLBs_SwitchesTransport: once this host renders the other
// VRRP transport from the one an LB's keepalived config on disk has — the
// latch formed, or the flag was turned off — the reconciler re-applies the
// LB even though its keepalived is running; an LB already on the transport is
// left alone.
//
// Mutation: keep reconcileDeadLBs on dead LBs only — red.
func TestReconcileDeadLBs_SwitchesTransport(t *testing.T) {
	for _, tc := range []struct {
		name            string
		flag            bool
		renderedUnicast bool
		reapply, want   bool
	}{
		{"latched, still multicast", true, false, true, true},
		{"latched, already unicast", true, true, false, false},
		{"flag turned off, still unicast", false, true, true, false},
		{"flag off, multicast", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := vrrpServer(t, tc.flag, true, true)
			ctx := context.Background()
			hosts, _ := json.Marshal([]string{"self", "peer-1"})
			if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
				Name: "web", VIP: "192.0.2.250/24", Algorithm: "roundrobin", Hosts: string(hosts),
				Ports: `[{"listen":80,"target":8080,"protocol":"tcp"}]`, Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}
			s.lbKeepalivedOverride = func(string) bool { return true }
			s.lbRenderedUnicastOverride = func(string) (bool, bool) { return tc.renderedUnicast, true }
			var applied []lb.Config
			s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }

			s.reconcileDeadLBs(ctx)

			if got := len(applied) == 1; got != tc.reapply {
				t.Fatalf("re-applied %d times, want re-apply=%v", len(applied), tc.reapply)
			}
			if tc.reapply && applied[0].VRRPUnicast != tc.want {
				t.Errorf("re-applied with VRRPUnicast=%v, want %v", applied[0].VRRPUnicast, tc.want)
			}
		})
	}
}

// TestAdvertise_VRRPUnicastWithheldWhileOff: an LB host's peers rely on it
// rendering their VRRP transport, so a flag-off host withholds the token and
// the latch means every host has the flag on.
//
// Mutation: advertise it whatever the flag says — red.
func TestAdvertise_VRRPUnicastWithheldWhileOff(t *testing.T) {
	off := testServer(t)
	off.SetVRRPUnicast(false)
	if slices.Contains(off.advertisedCapabilities(), capabilities.VRRPUnicastV1) || off.tokenEnabled(capabilities.VRRPUnicastV1) {
		t.Fatalf("%s advertised or enabled with enforcement.vrrp_unicast off", capabilities.VRRPUnicastV1)
	}
	on := testServer(t)
	on.SetVRRPUnicast(true)
	if !slices.Contains(on.advertisedCapabilities(), capabilities.VRRPUnicastV1) || !on.tokenEnabled(capabilities.VRRPUnicastV1) {
		t.Fatalf("a flag-on host does not advertise or enable %s", capabilities.VRRPUnicastV1)
	}
}
