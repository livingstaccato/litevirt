package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"google.golang.org/protobuf/proto"
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
		got, err := lbIfaceOf(s, ctx, "", "", vip)
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
	got, err := lbIfaceOf(s, context.Background(), "", "", "10.202.0.250")
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
	got, err := lbIfaceOf(s, context.Background(), "", "", "192.0.2.50")
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
	if err := s.applyLBForStack(ctx, "lbr-lb", "10.202.0.250/24", lb.Settings{Ports: []lb.Port{{Listen: 80, Target: 8080, Protocol: "tcp"}}},
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
	if got, err := lbIfaceOf(s, ctx, "b-lb", "", "10.10.0.50"); err != nil || got != "br-vni11" {
		t.Errorf("stack b's LB: %q, %v; want stack b's bridge br-vni11", got, err)
	}
	if got, err := lbIfaceOf(s, ctx, "", "b", "10.10.0.50"); err != nil || got != "br-vni11" {
		t.Errorf("stack named by a peer apply, no LB row: %q, %v; want br-vni11", got, err)
	}
	if got, err := lbIfaceOf(s, ctx, "", "", "10.10.0.50"); err != nil || got != "br-vni10" {
		t.Errorf("no LB row: %q, %v; want the first by name, br-vni10", got, err)
	}
}

// TestApplyLB_HonoursSNAT: a peer apply records SNAT for the LB's network
// exactly when the request asks for it. A request with no snat field — from a
// caller on an earlier build — gets SNAT, as every ApplyLB did before the
// field; snat false records the VIP holes and no SNAT.
//
// Mutation: ignore req.Snat in ApplyLB — the false case goes red.
func TestApplyLB_HonoursSNAT(t *testing.T) {
	for _, tc := range []struct {
		name string
		snat *bool
		want bool
	}{
		{"absent (an earlier build)", nil, true},
		{"false", proto.Bool(false), false},
		{"true", proto.Bool(true), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.SetBridgeExists(func(string) bool { return true })
			s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
			putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
			ctx := peerCtxFor(t, s, "node-0")
			if _, err := s.ApplyLB(ctx, &pb.ApplyLBRequest{
				LbName: "lbr-lb", Vip: "10.202.0.250/24", Hosts: []string{"node-0", s.hostName},
				Ports: []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}}, Snat: tc.snat, StackName: "lbr",
			}); err != nil {
				t.Fatalf("ApplyLB: %v", err)
			}
			intents, err := corrosion.ListHostFWIntent(context.Background(), s.db, s.hostName)
			if err != nil {
				t.Fatal(err)
			}
			var got *corrosion.HostFWIntent
			for i := range intents {
				if intents[i].ScopeKey == "lb:lbr-lb" {
					got = &intents[i]
				}
			}
			if got == nil || len(got.Exceptions) != 1 {
				t.Fatalf("LB intent %+v, want the VIP's holes", got)
			}
			if (got.SNATVIP != "") != tc.want {
				t.Errorf("SNAT recorded = %v (vip %q), want %v", got.SNATVIP != "", got.SNATVIP, tc.want)
			}
		})
	}
}

// TestLBVIPInterface_StackBridgeOnItsRecordedName: a stack's bridge network
// is on one device on every host, the one its row names (network.BridgeName):
// its scoped name when the row names no interface. A host that has only the
// short name does not have the network's bridge, and the VIP is refused there,
// never put on a device another stack's `hinet` may be on.
//
// Mutation: fall back to the short name when the scoped one is missing — red.
func TestLBVIPInterface_StackBridgeOnItsRecordedName(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		iface, have, want string
	}{
		{"", "lbs_hinet", "lbs_hinet"}, // no interface: the scoped name
		{"", "hinet", ""},              // no interface, only the short name here: refused
		{"hinet", "hinet", "hinet"},    // the row names the device
		{"hinet", "lbs_hinet", ""},     // the row names a device this host lacks: refused
	} {
		s := testServer(t)
		have := tc.have
		s.SetBridgeExists(func(b string) bool { return b == have })
		cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: tc.iface, Subnet: "10.203.0.0/24", HostIsolation: true})
		if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lbs_hinet", StackName: "lbs", Type: "bridge", Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
		got, err := lbIfaceOf(s, ctx, "", "lbs", "10.203.0.250")
		if tc.want == "" {
			if err == nil {
				t.Errorf("row interface %q, host has %s: placed on %q; want refused", tc.iface, tc.have, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("row interface %q, host has %s: %q, %v; want %s", tc.iface, tc.have, got, err, tc.want)
		}
	}
}

// TestLB_TwoStacksSharingAShortNameStayApart: stacks a and b each have a
// host-isolated `backend` network, on different subnets. On this host b's is
// on the short name `backend` (b was deployed here: its row names the
// interface) and a's on the scoped `a_backend` (provisioned as a peer target).
// Each LB's VIP and SNAT intent land on its own stack's network only, and a's
// VIP is never put on b's device.
//
// Mutation: match the intent's network by device name (findIsolatedNetworkForBridge) — red.
func TestLB_TwoStacksSharingAShortNameStayApart(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T, devices map[string]string) *Server {
		t.Helper()
		s := testServer(t)
		s.SetBridgeExists(func(b string) bool { _, ok := devices[b]; return ok })
		s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
		for _, n := range []struct{ name, stack, iface, subnet string }{
			{"a_backend", "a", "", "10.1.0.0/24"},
			{"b_backend", "b", "backend", "10.2.0.0/24"},
		} {
			cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: n.iface, Subnet: n.subnet, HostIsolation: true})
			if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: n.name, StackName: n.stack, Type: "bridge", Config: string(cfg)}); err != nil {
				t.Fatal(err)
			}
		}
		for _, st := range []string{"a", "b"} {
			if err := corrosion.PersistLBFull(ctx, s.db, corrosion.LBConfigRecord{
				Name: st + "-lb", StackName: st, VIP: "x", Hosts: `["test-host"]`, Ports: "[]", Enabled: true,
			}, nil); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	intent := func(t *testing.T, s *Server, lbName string) *corrosion.HostFWIntent {
		t.Helper()
		intents, err := corrosion.ListHostFWIntent(ctx, s.db, s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		for i := range intents {
			if intents[i].ScopeKey == "lb:"+lbName {
				return &intents[i]
			}
		}
		return nil
	}
	ports := []lb.Port{{Listen: 80, Target: 8080, Protocol: "tcp"}}

	t.Run("each on its own", func(t *testing.T) {
		s := setup(t, map[string]string{"backend": "10.2.0.1/24", "a_backend": "10.1.0.1/24"})
		for _, c := range []struct{ lb, vip, dev, subnet string }{
			{"b-lb", "10.2.0.250/24", "backend", "10.2.0.0/24"},
			{"a-lb", "10.1.0.250/24", "a_backend", "10.1.0.0/24"},
		} {
			if err := s.applyLBForStack(ctx, c.lb, c.vip, lb.Settings{Ports: ports}, nil, []string{s.hostName}, true); err != nil {
				t.Fatalf("%s: %v", c.lb, err)
			}
			in := intent(t, s, c.lb)
			if in == nil || in.Bridge != c.dev || in.SNATSubnet != c.subnet {
				t.Errorf("%s: intent %+v, want bridge %s and SNAT for %s", c.lb, in, c.dev, c.subnet)
			}
		}
	})
	t.Run("a's LB on a host that has only b's backend", func(t *testing.T) {
		s := setup(t, map[string]string{"backend": "10.2.0.1/24"})
		if err := s.applyLBForStack(ctx, "a-lb", "10.1.0.250/24", lb.Settings{Ports: ports}, nil, []string{s.hostName}, true); err == nil {
			t.Error("a's VIP was placed on b's bridge")
		}
		if in := intent(t, s, "a-lb"); in != nil {
			t.Errorf("a-lb recorded %+v on b's bridge", in)
		}
	})
}

// TestStackLBSNAT_OneRule: the stack's `snat:` for every re-apply path. The
// stored compose file is the stack-level value (any VM's `snat: true` wins);
// with no file declaring an LB, the VMs' stored specs decide the same way; an
// explicit LB SNATs; a read error is an error, never false.
//
// Mutation: take the first VM's value, prefer the VM specs over the file, or
// return false on a read error — red.
func TestStackLBSNAT_OneRule(t *testing.T) {
	ctx := context.Background()
	lbVM := func(t *testing.T, s *Server, name, stack string, snat bool) {
		t.Helper()
		spec, _ := json.Marshal(&pb.VMSpec{Name: name, StackName: stack, Loadbalancer: &pb.LBSpec{Enabled: true, Vip: "10.2.0.250/24", Snat: snat}})
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, StackName: stack, Spec: string(spec), State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	storeFile := func(t *testing.T, s *Server, name, yaml string) {
		t.Helper()
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: name, ComposeHash: "h", ComposeYAML: yaml}); err != nil {
			t.Fatal(err)
		}
	}
	stackFile := func(t *testing.T, s *Server, name, yaml string) {
		t.Helper()
		if _, err := compose.ParseBytes([]byte(yaml)); err != nil {
			t.Fatalf("precondition: the stored file must parse: %v", err)
		}
		storeFile(t, s, name, yaml)
	}
	// One LB per stack: a file declaring two different ones no longer parses
	// (compose validation); one stored before that falls back to the VMs'
	// specs. Identical copies parse, and the file decides.
	const oneLB = `name: st
images:
  test:
    source: file:///dev/null
vms:
  a:
    image: test
    cpu: 1
    memory: 512
    loadbalancer:
      enabled: true
      vip: 10.2.0.250/24
      ports: [{listen: 80, target: 8080, protocol: tcp}]
      snat: %s
  b:
    image: test
    cpu: 1
    memory: 512
`
	const twoLBs = `name: st
images:
  test:
    source: file:///dev/null
vms:
  a:
    image: test
    cpu: 1
    memory: 512
    loadbalancer:
      enabled: true
      vip: 10.2.0.250/24
      ports: [{listen: 80, target: 8080, protocol: tcp}]
      snat: %s
  b:
    image: test
    cpu: 1
    memory: 512
    loadbalancer:
      enabled: true
      vip: 10.2.0.250/24
      ports: [{listen: 80, target: 8080, protocol: tcp}]
      snat: %s
`
	for _, tc := range []struct {
		name string
		prep func(t *testing.T, s *Server)
		want bool
	}{
		{"explicit LB", func(*testing.T, *Server) {}, true},
		{"file says true", func(t *testing.T, s *Server) {
			stackFile(t, s, "st", fmt.Sprintf(oneLB, "true"))
		}, true},
		{"file says false, a stale VM spec says true: the file wins", func(t *testing.T, s *Server) {
			stackFile(t, s, "st", fmt.Sprintf(oneLB, "false"))
			lbVM(t, s, "st-a", "st", true)
		}, false},
		{"file with two identical LB copies says true", func(t *testing.T, s *Server) {
			stackFile(t, s, "st", fmt.Sprintf(twoLBs, "true", "true"))
		}, true},
		{"file with two identical LB copies says false, a stale VM spec says true: the file wins", func(t *testing.T, s *Server) {
			stackFile(t, s, "st", fmt.Sprintf(twoLBs, "false", "false"))
			lbVM(t, s, "st-a", "st", true)
		}, false},
		{"a stored file with two different LBs (no longer parses): VM specs decide, any true wins", func(t *testing.T, s *Server) {
			storeFile(t, s, "st", fmt.Sprintf(twoLBs, "false", "true"))
			lbVM(t, s, "st-a", "st", false)
			lbVM(t, s, "st-b", "st", true)
		}, true},
		{"no file: VM specs disagree, any true wins", func(t *testing.T, s *Server) {
			lbVM(t, s, "st-a", "st", false)
			lbVM(t, s, "st-b", "st", true)
		}, true},
		{"no file, no VM declares snat", func(t *testing.T, s *Server) {
			lbVM(t, s, "st-a", "st", false)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			tc.prep(t, s)
			stack := "st"
			if tc.name == "explicit LB" {
				stack = ""
			}
			got, err := s.stackLBSNAT(ctx, stack)
			if err != nil || got != tc.want {
				t.Errorf("stackLBSNAT = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	t.Run("read error", func(t *testing.T) {
		s := testServer(t)
		_ = s.db.Close()
		if got, err := s.stackLBSNAT(ctx, "st"); err == nil {
			t.Errorf("stackLBSNAT on an unreadable database = %v, nil; want an error", got)
		}
	})
}

// lbIfaceOf is lbVIPInterface's device.
func lbIfaceOf(s *Server, ctx context.Context, lbName, stack, vip string) (string, error) {
	p, err := s.lbVIPInterface(ctx, lbName, stack, vip)
	return p.iface, err
}
