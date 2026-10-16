package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
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
// latched and durably at durable. cluster_policies is writable.
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
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetVRRPUnicast(flag)
	s.SetGate(fakeServerGate{
		enforcedTok:       map[string]bool{capabilities.VRRPUnicastV1: latched},
		durablyLatchedTok: map[string]bool{capabilities.VRRPUnicastV1: durable},
	})
	s.lbIfaceForIPOverride = func(ip string) string {
		if ip == "192.0.2.11" {
			return "eth-host"
		}
		return ""
	}
	return s
}

// peerApply runs a forwarded ApplyLB of an LB on a host-isolated network's
// bridge (hinet) over hosts and returns what reached the LB manager.
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

// TestApplyLB_VRRPTransportIsClusterWide: the transport an LB host renders is
// the cluster's, never its own flag's. Unicast once vrrp_unicast_v1 is
// durably latched here OR any host's latch row has reached this replica; the
// operator's policy overrides both; enforcement.vrrp_unicast plays no part.
// Unicast goes from this host's recorded address, over the device holding it,
// to every other LB host's.
//
// Mutations (each red): decide on the flag; on Latched rather than
// DurablyLatched; ignore the latch row; ignore the operator's multicast; leave
// a peer out; send from the VIP's bridge.
func TestApplyLB_VRRPTransportIsClusterWide(t *testing.T) {
	hosts := []string{"peer-1", "self", "peer-2"}
	for _, tc := range []struct {
		name                   string
		flag, latched, durable bool
		row                    bool   // another host's latch row has replicated here
		policy                 string // the operator's choice
		unicast                bool
	}{
		{"durably latched", true, true, true, false, "", true},
		{"durably latched, flag off", false, true, true, false, "", true},
		{"latched in memory only", true, true, false, false, "", false},
		{"not latched", true, false, false, false, "", false},
		{"not latched here, latch row replicated", false, false, false, true, "", true},
		{"durably latched, operator chose multicast", true, true, true, false, "multicast", false},
		{"latch row, operator chose unicast", false, false, false, true, "unicast", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := vrrpServer(t, tc.flag, tc.latched, tc.durable)
			ctx := context.Background()
			if tc.row {
				if err := corrosion.MarkVRRPUnicastLatched(ctx, s.db, "peer-2"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.policy != "" {
				if err := corrosion.SetVRRPTransport(ctx, s.db, tc.policy, "test"); err != nil {
					t.Fatal(err)
				}
			}
			applied, err := peerApply(t, s, hosts)
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

// TestVRRPUnicastActive_FirstLatchTellsEveryHost: the host whose latch becomes
// durable records it, so a host that has not latched yet renders unicast as
// soon as the row reaches it.
//
// Mutation: do not write the latch row — red.
func TestVRRPUnicastActive_FirstLatchTellsEveryHost(t *testing.T) {
	s := vrrpServer(t, true, true, true)
	ctx := context.Background()
	if on, err := s.vrrpUnicastActive(ctx); err != nil || !on {
		t.Fatalf("vrrpUnicastActive = %v, %v", on, err)
	}
	p, err := corrosion.GetVRRPTransport(ctx, s.db)
	if err != nil || !p.Latched || p.LatchedBy != s.hostName {
		t.Fatalf("latch row = %+v (%v), want written by %s", p, err, s.hostName)
	}
}

// TestApplyLB_VRRPUnicastDropsAPeerWithNoAddress: a host in the LB's hosts with
// no recorded address — removed from the cluster, or never known — is not a
// VRRP peer, and never stops the hosts still serving from applying. With no
// peer left the LB renders the sole-host form (it names itself), which makes
// it master on its own, as a sole multicast host was.
//
// Mutation: refuse the apply on such a host — red; keep it as a peer — red.
func TestApplyLB_VRRPUnicastDropsAPeerWithNoAddress(t *testing.T) {
	ctx := context.Background()
	s := vrrpServer(t, true, true, true)
	if err := corrosion.DeleteHost(ctx, s.db, "peer-2"); err != nil { // lv host rm
		t.Fatal(err)
	}
	applied, err := peerApply(t, s, []string{"self", "peer-2", "ghost"})
	if err != nil || len(applied) != 1 {
		t.Fatalf("ApplyLB: %v (applied %d), want applied without the removed and unknown hosts", err, len(applied))
	}
	if c := applied[0]; !c.VRRPUnicast || len(c.UnicastPeers) != 0 {
		t.Fatalf("unicast=%v peers=%v, want the sole-host form", c.VRRPUnicast, c.UnicastPeers)
	}
	conf, err := lb.RenderKeepalived(applied[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := "        192.0.2.11 min_ttl 0 max_ttl 0\n"; !strings.Contains(conf, want) {
		t.Fatalf("not the sole-host form:\n%s", conf)
	}
}

// TestApplyLB_VRRPUnicastRefusesAnAddressNoDeviceHolds: VRRP sent from an
// address this host does not own is never answered, so the apply is refused
// rather than guessing the default-route device.
//
// Mutation: fall back to some device — red.
func TestApplyLB_VRRPUnicastRefusesAnAddressNoDeviceHolds(t *testing.T) {
	s := vrrpServer(t, true, true, true)
	s.lbIfaceForIPOverride = func(string) string { return "" }
	if applied, err := peerApply(t, s, []string{"self", "peer-1"}); err == nil || len(applied) != 0 {
		t.Fatalf("applied %d configs (err %v), want the apply refused", len(applied), err)
	}
}

// TestReconcileDeadLBs_ReappliesOnAnyTransportChange: the reconciler compares
// the whole transport on disk with what this host would render — mode, device,
// source and peers — and re-applies a running LB on any difference: the latch
// formed, the operator stood down, a peer's address changed, a peer was
// removed. An LB already on it is left alone.
//
// Mutation: compare the mode only — the address and removal cases go red;
// keep reconcileDeadLBs on dead LBs only — red.
func TestReconcileDeadLBs_ReappliesOnAnyTransportChange(t *testing.T) {
	cur := lb.Transport{Unicast: true, Iface: "eth-host", Src: "192.0.2.11", Peers: []string{"127.0.0.1"}}
	for _, tc := range []struct {
		name    string
		have    lb.Transport
		prep    func(*testing.T, *Server)
		reapply bool
	}{
		{"latched, still multicast", lb.Transport{}, nil, true},
		{"already on it", cur, nil, false},
		{"operator stood down", cur, func(t *testing.T, s *Server) {
			if err := corrosion.SetVRRPTransport(context.Background(), s.db, "multicast", "test"); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"peer's address changed", lb.Transport{Unicast: true, Iface: "eth-host", Src: "192.0.2.11", Peers: []string{"192.0.2.99"}}, nil, true},
		{"peer removed", cur, func(t *testing.T, s *Server) {
			if err := corrosion.DeleteHost(context.Background(), s.db, "peer-1"); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := vrrpServer(t, true, true, true)
			ctx := context.Background()
			hosts, _ := json.Marshal([]string{"self", "peer-1"})
			if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
				Name: "web", VIP: "192.0.2.250/24", Algorithm: "roundrobin", Hosts: string(hosts),
				Ports: `[{"listen":80,"target":8080,"protocol":"tcp"}]`, Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}
			if tc.prep != nil {
				tc.prep(t, s)
			}
			s.lbKeepalivedOverride = func(string) bool { return true }
			s.lbRenderedTransportOverride = func(string) (lb.Transport, bool) { return tc.have, true }
			s.vrrpPeerCapsOverride = func(context.Context, string) ([]string, error) { return nil, errors.New("down") }
			var applied []lb.Config
			s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }

			s.reconcileDeadLBs(ctx)

			if got := len(applied) == 1; got != tc.reapply {
				t.Fatalf("re-applied %d times, want re-apply=%v", len(applied), tc.reapply)
			}
		})
	}
}

// TestNoteVRRPSplit_AnEarlierBuildPeerIsReported: after the latch, an LB host
// that answers a Ping without vrrp_unicast_v1 is on an earlier build and
// renders multicast while this host renders unicast — both hold the VIP. A
// critical condition names the LB, the host and the remedy, and resolves once
// the host advertises it. An unreachable host is not reported.
//
// Mutation: count an unreachable host — red; never raise — red.
func TestNoteVRRPSplit_AnEarlierBuildPeerIsReported(t *testing.T) {
	s := vrrpServer(t, true, true, true)
	ctx := context.Background()
	hosts, _ := json.Marshal([]string{"self", "peer-1", "peer-2"})
	recs := []corrosion.LBConfigRecord{{Name: "web", Hosts: string(hosts)}}
	caps := map[string][]string{"peer-1": {capabilities.SplitBrainGateV1}}
	s.vrrpPeerCapsOverride = func(_ context.Context, h string) ([]string, error) {
		if c, ok := caps[h]; ok {
			return c, nil
		}
		return nil, errors.New("unreachable")
	}
	active := func() (bool, string) {
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, LBEvaluator, CondLBVRRPSplit, "host", s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return ok && row.Lifecycle != corrosion.ConditionResolved, row.Evidence
	}
	s.noteVRRPSplit(ctx, recs)
	on, detail := active()
	if !on || !strings.Contains(detail, "web (with peer-1)") || strings.Contains(detail, "peer-2") || !strings.Contains(detail, "lv cluster vrrp-transport multicast") {
		t.Fatalf("condition active=%v detail=%q, want web with peer-1 only, and the remedy", on, detail)
	}
	caps["peer-1"] = []string{capabilities.VRRPUnicastV1}
	s.noteVRRPSplit(ctx, recs)
	if on, _ := active(); on {
		t.Fatal("condition still active once every LB host advertises vrrp_unicast_v1")
	}
}

// TestSetVRRPTransport_Preconditions: unicast cannot be chosen before the
// latch; multicast can, and every host then renders it.
func TestSetVRRPTransport_Preconditions(t *testing.T) {
	ctx := adminCtx()
	s := vrrpServer(t, true, false, false)
	s.SetGate(fakeServerGate{
		healthy:           []string{"peer-1", "peer-2"},
		enforcedTok:       map[string]bool{capabilities.FailoverScopeV1: true},
		durablyLatchedTok: map[string]bool{capabilities.FailoverScopeV1: true},
	})
	if _, err := s.SetVRRPTransport(ctx, &pb.SetVRRPTransportRequest{Transport: "unicast"}); err == nil {
		t.Fatal("unicast set before vrrp_unicast_v1 latched")
	}
	st, err := s.SetVRRPTransport(ctx, &pb.SetVRRPTransportRequest{Transport: "multicast"})
	if err != nil || st.GetPolicy() != "multicast" || st.GetTransport() != "multicast" {
		t.Fatalf("set multicast: %+v, %v", st, err)
	}
	if _, err := s.SetVRRPTransport(ctx, &pb.SetVRRPTransportRequest{Transport: "broadcast"}); err == nil {
		t.Fatal("an unknown transport was accepted")
	}
}

// TestAdvertise_VRRPUnicastWithheldWhileOff: before the latch a flag-off host
// withholds the token, so the latch means every host opted in. After it the
// transport is cluster-wide and the host renders unicast whatever its flag,
// so it advertises the token: one that does not is an earlier build.
//
// Mutation: advertise it whatever the flag says — red; keep withholding
// after the latch — red.
func TestAdvertise_VRRPUnicastWithheldWhileOff(t *testing.T) {
	off := testServer(t)
	off.SetVRRPUnicast(false)
	if slices.Contains(off.advertisedCapabilities(), capabilities.VRRPUnicastV1) || off.tokenEnabled(capabilities.VRRPUnicastV1) {
		t.Fatalf("%s advertised or enabled with enforcement.vrrp_unicast off", capabilities.VRRPUnicastV1)
	}
	off.vrrpRowLatched.Store(true)
	if !slices.Contains(off.advertisedCapabilities(), capabilities.VRRPUnicastV1) {
		t.Fatalf("a flag-off host withholds %s after the latch, though it renders unicast", capabilities.VRRPUnicastV1)
	}
	on := testServer(t)
	on.SetVRRPUnicast(true)
	if !slices.Contains(on.advertisedCapabilities(), capabilities.VRRPUnicastV1) || !on.tokenEnabled(capabilities.VRRPUnicastV1) {
		t.Fatalf("a flag-on host does not advertise or enable %s", capabilities.VRRPUnicastV1)
	}
}
