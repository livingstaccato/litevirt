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
// the cluster's rows only. Unicast once a latch row has reached this replica,
// never on this host's own latch alone (another host may not have latched);
// the operator's policy overrides; enforcement.vrrp_unicast plays no part.
// Unicast goes from this host's recorded address, over the device holding it,
// to every other LB host's.
//
// Mutations (each red): decide on the flag; render on the own latch; ignore
// the latch row; ignore the operator's multicast; leave a peer out; send from
// the VIP's bridge.
func TestApplyLB_VRRPTransportIsClusterWide(t *testing.T) {
	hosts := []string{"peer-1", "self", "peer-2"}
	for _, tc := range []struct {
		name                   string
		flag, latched, durable bool
		row                    bool   // another host's latch row has replicated here
		policy                 string // the operator's choice
		unicast                bool
	}{
		{"durably latched, no row yet", true, true, true, false, "", false},
		{"latch row", true, true, true, true, "", true},
		{"latch row, flag off", false, true, true, true, "", true},
		{"not latched", true, false, false, false, "", false},
		{"not latched here, latch row replicated", false, false, false, true, "", true},
		{"latch row, operator chose multicast", true, true, true, true, "multicast", false},
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

// TestNoteVRRPLatch_TheRowSwitchesEveryHost: a host's durable latch switches
// nothing by itself; the watch writes the latch row, and the row switches
// every host. A host whose cluster_policies is not writable yet
// (failover_scope_v1 not latched) writes nothing, so every host stays
// multicast: uniform rather than early. Read paths never write it.
//
// Mutations: write the row from vrrpUnicastActive — the read-only case goes
// red; write it with the gate closed — red; render on the own latch — red.
func TestNoteVRRPLatch_TheRowSwitchesEveryHost(t *testing.T) {
	ctx := context.Background()
	s := vrrpServer(t, true, true, true)
	s.db.SetClusterPolicyGate(func() bool { return false })
	if on, err := s.vrrpUnicastActive(ctx); err != nil || on {
		t.Fatalf("own latch alone: unicast=%v err=%v, want multicast", on, err)
	}
	if _, err := s.GetVRRPTransport(adminCtx(), nil); err != nil {
		t.Fatal(err)
	}
	s.noteVRRPLatch(ctx)
	if p, _ := corrosion.GetVRRPTransport(ctx, s.db); p.Latched {
		t.Fatal("the latch row was written with cluster_policies not writable")
	}
	if applied, err := peerApply(t, s, []string{"self", "peer-1"}); err != nil || applied[0].VRRPUnicast {
		t.Fatalf("gate closed: applied %+v (%v), want multicast", applied, err)
	}
	s.db.SetClusterPolicyGate(func() bool { return true })
	if on, _ := s.vrrpUnicastActive(ctx); on {
		t.Fatal("a read path wrote the latch row")
	}
	s.noteVRRPLatch(ctx)
	p, err := corrosion.GetVRRPTransport(ctx, s.db)
	if err != nil || !p.Latched || p.LatchedBy != s.hostName {
		t.Fatalf("latch row = %+v (%v), want written by %s", p, err, s.hostName)
	}
	if on, _ := s.vrrpUnicastActive(ctx); !on {
		t.Fatal("the latch row does not switch this host")
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
	markLatched(t, s)
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

// markLatched writes the latch row, as the first latching host does.
func markLatched(t *testing.T, s *Server) {
	t.Helper()
	if err := corrosion.MarkVRRPUnicastLatched(context.Background(), s.db, "peer-2"); err != nil {
		t.Fatal(err)
	}
}

// TestApplyLB_VRRPRefusalStopsThisHostAndIsCritical: a host whose recorded
// address no up, non-loopback device holds cannot render unicast. Its
// keepalived, still on multicast, would hold the VIP beside the LB hosts that
// switched, so when another LB host answers as one that renders the
// transport it is stopped, and a critical condition names the LB, the reason
// and the remedy (lv cluster vrrp-transport multicast). With no other host
// rendering it, nothing is stopped (the LB keeps a holder). A successful apply
// resolves the condition. The refusal event is published once per reason.
//
// Mutations (each red): never stop keepalived; stop it with no other host
// rendering; no condition; no resolve; publish on every refusal.
func TestApplyLB_VRRPRefusalStopsThisHostAndIsCritical(t *testing.T) {
	ctx := context.Background()
	s := vrrpServer(t, true, true, true)
	markLatched(t, s)
	held := true
	s.lbIfaceForIPOverride = func(ip string) string {
		if !held && ip == "192.0.2.11" {
			return "eth-host"
		}
		return ""
	}
	renders := false
	s.vrrpPeerCapsOverride = func(context.Context, string) ([]string, bool, error) {
		if renders {
			return []string{capabilities.VRRPUnicastV1}, false, nil
		}
		return nil, false, errors.New("unreachable")
	}
	var stopped []string
	s.lbDemoteOverride = func(name string) error { stopped = append(stopped, name); return nil }
	cond := func() (bool, string) {
		row, ok, err := corrosion.GetHealthCondition(ctx, s.db, LBEvaluator, CondLBVRRPRefused, "host", s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return ok && row.Lifecycle != corrosion.ConditionResolved && row.Severity == corrosion.SeverityCritical, row.Evidence
	}
	ch, unsub := s.events.Subscribe()
	defer unsub()

	if applied, err := peerApply(t, s, []string{"self", "peer-1"}); err == nil || len(applied) != 0 {
		t.Fatalf("applied %d configs (err %v), want the apply refused", len(applied), err)
	}
	if len(stopped) != 0 {
		t.Fatalf("stopped %v with no other LB host rendering the transport", stopped)
	}
	if on, detail := cond(); !on || !strings.Contains(detail, "lbr-lb") || !strings.Contains(detail, "lv cluster vrrp-transport multicast") {
		t.Fatalf("condition active=%v detail=%q, want critical, naming the LB and the remedy", on, detail)
	}
	renders = true
	if _, err := peerApply(t, s, []string{"self", "peer-1"}); err == nil {
		t.Fatal("applied")
	}
	if len(stopped) != 1 || stopped[0] != "lbr-lb" {
		t.Fatalf("stopped %v, want lbr-lb once another LB host renders the transport", stopped)
	}
	refusals := 0
	for done := false; !done; {
		select {
		case e := <-ch:
			if e.Action == "lb.vrrp_transport_refused" {
				refusals++
			}
		default:
			done = true
		}
	}
	if refusals != 1 {
		t.Errorf("published %d refusal events for one reason, want 1", refusals)
	}
	held = false
	if applied, err := peerApply(t, s, []string{"self", "peer-1"}); err != nil || len(applied) != 1 || !applied[0].VRRPUnicast {
		t.Fatalf("apply once the address is held: %v (%d)", err, len(applied))
	}
	if on, _ := cond(); on {
		t.Fatal("the condition is still active after a successful apply")
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
			markLatched(t, s)
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
			s.vrrpPeerCapsOverride = func(context.Context, string) ([]string, bool, error) { return nil, false, errors.New("down") }
			var applied []lb.Config
			s.lbApplyOverride = func(_ context.Context, c lb.Config) error { applied = append(applied, c); return nil }

			s.reconcileDeadLBs(ctx)

			if got := len(applied) == 1; got != tc.reapply {
				t.Fatalf("re-applied %d times, want re-apply=%v", len(applied), tc.reapply)
			}
		})
	}
}

// TestNoteVRRPSplit_AnEarlierBuildPeerIsReported: after the switch, an LB
// host that answers a Ping without vrrp_unicast_v1, or reports WAL quarantine
// (rolled back), renders multicast while this host renders unicast — both
// hold the VIP. A critical condition names the LB, the host and the remedy,
// and resolves once the host advertises it. An unreachable host, and a
// self-fenced one (it answers with no capabilities), are not reported.
//
// Mutations: count an unreachable or self-fenced host — red; ignore WAL
// quarantine — red; never raise — red.
func TestNoteVRRPSplit_AnEarlierBuildPeerIsReported(t *testing.T) {
	s := vrrpServer(t, true, true, true)
	markLatched(t, s)
	ctx := context.Background()
	hosts, _ := json.Marshal([]string{"self", "peer-1", "peer-2", "fenced", "rolledback"})
	recs := []corrosion.LBConfigRecord{{Name: "web", Hosts: string(hosts)}}
	caps := map[string][]string{"peer-1": {capabilities.SplitBrainGateV1}, "fenced": {}, "rolledback": {capabilities.VRRPUnicastV1}}
	s.vrrpPeerCapsOverride = func(_ context.Context, h string) ([]string, bool, error) {
		if c, ok := caps[h]; ok {
			return c, h == "rolledback", nil
		}
		return nil, false, errors.New("unreachable")
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
	if !on || !strings.Contains(detail, "web (with peer-1)") || !strings.Contains(detail, "web (with rolledback)") ||
		strings.Contains(detail, "peer-2") || strings.Contains(detail, "fenced") || !strings.Contains(detail, "lv cluster vrrp-transport multicast") {
		t.Fatalf("condition active=%v detail=%q, want peer-1 and rolledback only, and the remedy", on, detail)
	}
	caps["peer-1"] = []string{capabilities.VRRPUnicastV1}
	delete(caps, "rolledback")
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
