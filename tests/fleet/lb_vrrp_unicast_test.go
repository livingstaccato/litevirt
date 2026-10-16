package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// unicastPeers is the unicast_src_ip and the unicast_peer block of a
// keepalived config, or ok=false for a multicast one.
func unicastPeers(conf string) (src string, peers []string, ok bool) {
	in := false
	for _, l := range strings.Split(conf, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "unicast_src_ip "):
			src, ok = strings.TrimPrefix(l, "unicast_src_ip "), true
		case l == "unicast_peer {":
			in = true
		case in && l == "}":
			in = false
		case in:
			peers = append(peers, strings.Fields(l)[0])
		}
	}
	return src, peers, ok
}

// TestFleet_VRRPUnicast_LBHostsSwitchTogether: two hosts run an LB, and a
// third — on an older build, which does not advertise vrrp_unicast_v1 — holds
// the latch off, whether it is active or parked in maintenance (it still
// receives replication and may run an LB: ReplicationGated). Until the latch
// forms, both LB hosts render the multicast VRRP transport every earlier
// build renders, so either still pairs with a peer on that build. Once it
// forms, each LB host's reconciler re-renders the running LB — keepalived up,
// nothing else changed — as unicast from its own recorded address to the
// other LB host's, and nothing else: no password, and no non-LB host as a
// peer. Both switch, so neither is left on a transport its peer has left.
//
// Mutations (each red): render unicast on the flag alone (both switch before
// the latch); reconcile dead LBs only (neither switches); drop
// vrrp_unicast_v1 from replicationGated (the maintenance case latches).
func TestFleet_VRRPUnicast_LBHostsSwitchTogether(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		name := "active"
		if maintenance {
			name = "maintenance"
		}
		t.Run(name, func(t *testing.T) {
			bin := lbStandIns(t)
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, SharedCRDT: true})
			a, b, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			confDir := map[string]string{}
			for _, n := range c.Nodes {
				n.Server.SetVRRPUnicast(true)
				n.Server.SetBridgeExists(func(string) bool { return true })
				root := t.TempDir()
				confDir[n.Name] = filepath.Join(root, "config")
				m := lb.NewManagerAt(confDir[n.Name], filepath.Join(root, "run"))
				n.Server.SetLBManager(m)
				n.Server.SetLBApply(m.Apply)
				// The fleet's hosts are all recorded at 127.0.0.1, on loopback.
				n.Server.SetLBIfaceForIPForTests(func(string) string { return "fleet0" })
				// failover_scope_v1 latched: the LB's snat setting can be recorded.
				n.DB.SetClusterPolicyGate(func() bool { return true })
			}
			if maintenance {
				if err := corrosion.UpdateHostState(ctx, a.DB, old.Name, "maintenance"); err != nil {
					t.Fatal(err)
				}
			}
			var held atomic.Bool
			held.Store(true)
			gates := gateAll(t, c)
			for _, n := range c.Nodes {
				node := n
				peers := map[string]bool{}
				for _, o := range c.Nodes {
					if o != node {
						peers[o.Name] = true
					}
				}
				gates[node.Name].SeedPeersForTests(peers)
				gates[node.Name].SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
					caps, wall, err := node.Server.PeerCapabilities(ctx, host)
					if held.Load() && host == old.Name {
						caps = withoutToken(caps, capabilities.VRRPUnicastV1)
					}
					return caps, wall, err
				})
			}
			if !gates[a.Name].Enforced(ctx, capabilities.SplitBrainGateV1) {
				t.Fatal("fixture: split_brain_gate_v1 did not latch")
			}

			if _, err := c.SelfClient(a).CreateLoadBalancer(ctx, &pb.CreateLBRequest{
				Name: "web", Vip: "10.207.0.250/24", Hosts: []string{a.Name, b.Name},
				Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
				Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.207.0.10"}},
			}); err != nil {
				t.Fatalf("create: %v", err)
			}
			conf := func(n *Node) string {
				data, _ := os.ReadFile(filepath.Join(confDir[n.Name], "web-keepalived.conf"))
				return string(data)
			}
			for _, n := range []*Node{a, b} {
				n := n
				eventually(t, 20*time.Second, "the LB's keepalived config on "+n.Name, func() bool { return conf(n) != "" })
			}
			reconcile := func() {
				rctx, cancel := context.WithCancel(ctx)
				t.Cleanup(cancel)
				for _, n := range []*Node{a, b} {
					go n.Server.RunLBReconciler(rctx, 100*time.Millisecond)
				}
			}
			reconcile()

			// The older host holds the latch off: both stay on multicast.
			for _, n := range []*Node{a, b} {
				if gates[n.Name].Enforced(ctx, capabilities.VRRPUnicastV1) {
					t.Fatalf("vrrp_unicast_v1 latched on %s across %s (%s), which does not advertise it", n.Name, old.Name, name)
				}
			}
			time.Sleep(time.Second) // several reconciler ticks
			for _, n := range []*Node{a, b} {
				if _, _, uni := unicastPeers(conf(n)); uni || !strings.Contains(conf(n), "auth_type PASS") {
					t.Fatalf("%s left the multicast transport before the latch:\n%s", n.Name, conf(n))
				}
			}

			// Every host advertises it: the latch forms on each LB host, and
			// its reconciler re-renders the running LB.
			held.Store(false)
			for _, n := range []*Node{a, b} {
				n := n
				eventually(t, 20*time.Second, "vrrp_unicast_v1 latches on "+n.Name, func() bool {
					return gates[n.Name].Enforced(ctx, capabilities.VRRPUnicastV1) && gates[n.Name].DurablyLatched(capabilities.VRRPUnicastV1)
				})
			}
			for _, n := range []*Node{a, b} {
				n := n
				eventually(t, 20*time.Second, n.Name+" re-renders the LB as unicast", func() bool {
					_, _, uni := unicastPeers(conf(n))
					return uni
				})
				other := map[string]*Node{a.Name: b, b.Name: a}[n.Name]
				src, peers, _ := unicastPeers(conf(n))
				if src != n.Address || len(peers) != 1 || peers[0] != other.Address {
					t.Errorf("%s: unicast from %q to %v, want from its own address to the other LB host's only", n.Name, src, peers)
				}
				if strings.Contains(conf(n), "auth_pass") {
					t.Errorf("%s: the unicast config still carries a password:\n%s", n.Name, conf(n))
				}
			}
			if _, err := os.Stat(filepath.Join(confDir[old.Name], "web-keepalived.conf")); err == nil {
				t.Errorf("%s, not an LB host, renders the LB", old.Name)
			}
			// One start, and one restart onto the new transport, per LB host,
			// and no more over further reconciler ticks: the config written
			// is the one keepalived runs (the write precedes the restart).
			calls := filepath.Join(bin, "keepalived.calls")
			eventually(t, 20*time.Second, "keepalived restarted onto the new transport on both LB hosts", func() bool {
				return countLines(calls, "-f ") >= 4
			})
			time.Sleep(time.Second)
			if got := countLines(calls, "-f "); got != 4 {
				data, _ := os.ReadFile(calls)
				t.Errorf("keepalived started %d times on two LB hosts, want 4 (start and switch on each):\n%s", got, data)
			}
		})
	}
}

// TestFleet_VRRPUnicast_StandDownAndRemovedPeer: the transport is the
// cluster's, not a host's. With vrrp_unicast_v1 latched on only one LB host,
// both render unicast (the latch row replicates); `lv cluster vrrp-transport
// multicast` takes both back, and `unicast` forward again, each within the
// watcher's interval and without waiting for the reconcile tick. Then one LB
// host is removed (`lv host rm`): the other stops naming it, renders the
// sole-host form, and comes back up in that form after its keepalived dies.
//
// Mutations (each red): ignore the latch row (only node-0 switches); ignore
// the operator's policy (the stand-down does nothing); refuse the apply over
// the removed peer (node-0 stays on the pair form, and is not restarted).
func TestFleet_VRRPUnicast_StandDownAndRemovedPeer(t *testing.T) {
	bin := lbStandIns(t)
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	a, b := c.Nodes[0], c.Nodes[1]
	confDir, runDir := map[string]string{}, map[string]string{}
	for _, n := range c.Nodes {
		n.Server.SetVRRPUnicast(true)
		n.Server.SetBridgeExists(func(string) bool { return true })
		root := t.TempDir()
		confDir[n.Name], runDir[n.Name] = filepath.Join(root, "config"), filepath.Join(root, "run")
		m := lb.NewManagerAt(confDir[n.Name], runDir[n.Name])
		n.Server.SetLBManager(m)
		n.Server.SetLBApply(m.Apply)
		// The fleet's hosts are all recorded at 127.0.0.1, on loopback.
		n.Server.SetLBIfaceForIPForTests(func(string) string { return "fleet0" })
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		peers := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
	if !gates[a.Name].Enforced(ctx, capabilities.SplitBrainGateV1) {
		t.Fatal("fixture: split_brain_gate_v1 did not latch")
	}
	if !gates[a.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
		t.Fatal("fixture: failover_scope_v1 did not latch")
	}
	if _, err := c.SelfClient(a).CreateLoadBalancer(ctx, &pb.CreateLBRequest{
		Name: "web", Vip: "10.207.0.250/24", Hosts: []string{a.Name, b.Name},
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.207.0.10"}},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	conf := func(n *Node) string {
		data, _ := os.ReadFile(filepath.Join(confDir[n.Name], "web-keepalived.conf"))
		return string(data)
	}
	isUnicast := func(n *Node) bool { _, _, uni := unicastPeers(conf(n)); return uni }
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, "the LB's keepalived config on "+n.Name, func() bool { return conf(n) != "" })
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, n := range c.Nodes {
		// A reconcile tick far longer than the test: every switch below is
		// the transport watcher's.
		go n.Server.RunLBReconciler(rctx, time.Hour)
	}

	// Only node-0 latches; node-1 follows its latch row.
	if !gates[a.Name].Enforced(ctx, capabilities.VRRPUnicastV1) || !gates[a.Name].DurablyLatched(capabilities.VRRPUnicastV1) {
		t.Fatal("vrrp_unicast_v1 did not latch on node-0")
	}
	if gates[b.Name].Latched(capabilities.VRRPUnicastV1) {
		t.Fatal("fixture: node-1 latched too")
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, n.Name+" renders unicast", func() bool { return isUnicast(n) })
	}

	for _, step := range []struct {
		transport string
		unicast   bool
	}{{"multicast", false}, {"unicast", true}} {
		if _, err := c.SelfClient(a).SetVRRPTransport(ctx, &pb.SetVRRPTransportRequest{Transport: step.transport}); err != nil {
			t.Fatalf("lv cluster vrrp-transport %s: %v", step.transport, err)
		}
		for _, n := range c.Nodes {
			n := n
			eventually(t, 15*time.Second, n.Name+" renders "+step.transport, func() bool { return isUnicast(n) == step.unicast })
		}
	}

	// lv host rm node-1: node-0 serves the VIP alone.
	if err := corrosion.DeleteHost(ctx, a.DB, b.Name); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(runDir[a.Name], "web-keepalived.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	calls := filepath.Join(bin, "keepalived.calls")
	before := countLines(calls, "-f ")
	go func() {
		for i := 0; i < 50 && rctx.Err() == nil; i++ {
			a.Server.KickLBReconcileForTests()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	eventually(t, 15*time.Second, "node-0 renders the sole-host form", func() bool {
		src, peers, uni := unicastPeers(conf(a))
		return uni && len(peers) == 1 && peers[0] == src && strings.Contains(conf(a), "max_ttl 0")
	})
	eventually(t, 15*time.Second, "node-0's keepalived started again", func() bool { return countLines(calls, "-f ") > before })
}
