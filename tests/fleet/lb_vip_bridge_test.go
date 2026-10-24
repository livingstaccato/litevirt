package fleet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// The lab 1 LBAndSNAT stack: backends on a host-isolated bridge network, whose
// bridge carries no address in the subnet, and a VIP inside that subnet.
const composeLBOnHostIsolatedBridge = `name: lbr

images:
  test:
    source: file:///dev/null

networks:
  hinet:
    type: bridge
    subnet: 10.202.0.0/24
    dhcp: true
    host-isolation: true

vms:
  lbr1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: hinet
    loadbalancer:
      enabled: true
      vip: 10.202.0.250/24
      ports:
        - listen: 80
          target: 8080
          protocol: tcp
      hosts:
        - node-0
      snat: true
`

// TestFleet_LBVIPGoesOnTheNetworksBridge: deploying that stack puts the VIP
// on the network's own bridge, and the LB's isolation intent (VIP holes, and
// SNAT) on the same bridge. Before, the VIP's address lookup found no device
// holding the subnet and fell back to the default-route device: keepalived put
// the VIP's /24 on the uplink, which took the backends' route off the bridge,
// and the LB logged snat=false.
//
// Mutation: give applyLBForStack lb.DetectInterfaceForIP again — red.
func TestFleet_LBVIPGoesOnTheNetworksBridge(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	node.Server.SetBridgeExists(node.Net.HasDevice)
	var mu sync.Mutex
	var applied []lb.Config
	node.Server.SetLBApply(func(_ context.Context, c lb.Config) error {
		mu.Lock()
		defer mu.Unlock()
		applied = append(applied, c)
		return nil
	})

	msgs := deployCollect(t, ctx, client, composeLBOnHostIsolatedBridge)
	if p := errorPhaseFor(msgs, "lbr1"); p != nil {
		t.Fatalf("deploy of lbr1 failed: %s", p.Error)
	}
	dev, ok := node.Net.Up("lbr_hinet")
	if !ok {
		t.Fatal("network lbr_hinet was not provisioned on node-0")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(applied) == 0 {
		t.Fatal("the load balancer was never applied on node-0")
	}
	for _, c := range applied {
		if c.VIP != "10.202.0.250" || c.Interface != dev {
			t.Errorf("LB applied with VIP %s on %q, want 10.202.0.250 on the network's bridge %q", c.VIP, c.Interface, dev)
		}
	}
	intents, err := corrosion.ListHostFWIntent(ctx, node.DB, node.Name)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, in := range intents {
		if in.ScopeKey != "lb:lbr-lb" {
			continue
		}
		found = true
		if in.Bridge != dev || len(in.Exceptions) != 1 || in.Exceptions[0].VIP != "10.202.0.250" {
			t.Errorf("LB isolation intent %+v, want the VIP's holes on %s", in, dev)
		}
		// snat: true — the guests' egress is rewritten to the VIP.
		if in.SNATVIP != "10.202.0.250" || in.SNATSubnet != "10.202.0.0/24" || in.SNATOutIface == "" {
			t.Errorf("LB SNAT intent vip=%q subnet=%q out=%q, want 10.202.0.250 for 10.202.0.0/24 out the uplink",
				in.SNATVIP, in.SNATSubnet, in.SNATOutIface)
		}
	}
	if !found {
		t.Errorf("no LB isolation intent recorded (the lab's snat=false); intents: %+v", intents)
	}
}

// composeLBTwoHosts is the lbr stack spread over two LB hosts; %s is the
// loadbalancer's snat line ("" leaves it unset).
const composeLBTwoHosts = `name: lbs

images:
  test:
    source: file:///dev/null

networks:
  hinet:
    type: bridge
    subnet: 10.203.0.0/24
    dhcp: true
    host-isolation: true

vms:
  lbs1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: hinet
    loadbalancer:
      enabled: true
      vip: 10.203.0.250/24
      ports:
        - listen: 80
          target: 8080
          protocol: tcp
      hosts:
        - node-0
        - node-1
%s
  lbs2:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-1
    network:
      - name: hinet
`

// TestFleet_LBSNATHoldsOnEveryLBHost: a stack LB's `snat:` holds on every LB
// host, the one that deployed it and the ones it forwards the apply to. With
// `snat:` unset no host records SNAT — host-isolated guests get no implicit
// outbound NAT anywhere — and with `snat: true` every host does. The peer
// apply (ApplyLB) used to force SNAT on, so only the deploying host honoured
// an unset `snat:`, and with the VIP and gateway now on the bridge the other
// hosts' guests were NATed out.
//
// Mutation: drop snat from forwardLBApply's request, or ignore it in ApplyLB
// — the unset case goes red on node-1.
func TestFleet_LBSNATHoldsOnEveryLBHost(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		want       bool
	}{
		{"unset", "", false},
		{"true", "      snat: true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, IndependentReplicas: true})
			ctx := context.Background()
			for _, n := range c.Nodes {
				if err := corrosion.InsertImage(ctx, n.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
					t.Fatal(err)
				}
				if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
					t.Fatal(err)
				}
				n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
				n.Server.SetBridgeExists(n.Net.HasDevice)
				n.Server.SetLBApply(func(context.Context, lb.Config) error { return nil })
			}
			msgs := deployCollect(t, ctx, c.SelfClient(c.Nodes[0]), fmt.Sprintf(composeLBTwoHosts, tc.line))
			for _, p := range msgs {
				if p.Phase == "error" {
					t.Fatalf("deploy: %s: %s", p.VmName, p.Error)
				}
			}
			for _, n := range c.Nodes {
				n := n
				var in corrosion.HostFWIntent
				eventually(t, 20*time.Second, "the LB's isolation intent on "+n.Name, func() bool {
					intents, err := corrosion.ListHostFWIntent(ctx, n.DB, n.Name)
					if err != nil {
						return false
					}
					for _, x := range intents {
						if x.ScopeKey == "lb:lbs-lb" && len(x.Exceptions) == 1 {
							in = x
							return true
						}
					}
					return false
				})
				if got := in.SNATVIP != ""; got != tc.want {
					t.Errorf("%s: SNAT recorded = %v (vip=%q subnet=%q), want %v", n.Name, got, in.SNATVIP, in.SNATSubnet, tc.want)
				}
			}
		})
	}
}

// composeBackendStack is a stack with a host-isolated `backend` network and
// an LB with snat: true; %[1]s the stack, %[2]s its subnet's third octet.
const composeBackendStack = `name: %[1]s

images:
  test:
    source: file:///dev/null

networks:
  backend:
    type: bridge
    subnet: 10.%[2]s.0.0/24
    dhcp: true
    host-isolation: true

vms:
  %[1]s1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: backend
    loadbalancer:
      enabled: true
      vip: 10.%[2]s.0.250/24
      ports:
        - listen: 80
          target: 8080
          protocol: tcp
      hosts:
        - node-0
      snat: true
`

// TestFleet_TwoStacksSharingABackendNameStayApart: stacks sa and sb each have
// a host-isolated `backend` network, on different subnets, with an LB on
// node-0. sa is deployed from node-1, so node-0 provisions its network as a
// peer target; sb is deployed from node-0, which provisions its own. A stack
// network with no interface is on its scoped name on every host, so the two
// are on sa_backend and sb_backend, never one shared `backend` bridge. Each
// LB's VIP and SNAT intent must land on its own stack's network only.
// Matched by device name, sb's intent took sa's row (it claims `backend` too)
// and NATed sa's subnet as sb's VIP.
//
// Mutation: look the intent's network up by device name again — red.
// Mutation: default a stack network's interface to its short name — red (the
// two stacks share one device on node-0).
func TestFleet_TwoStacksSharingABackendNameStayApart(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	var mu sync.Mutex
	applied := map[string]string{} // LB → device, on node-0
	for _, n := range c.Nodes {
		n := n
		if err := corrosion.InsertImage(ctx, n.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
			t.Fatal(err)
		}
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatal(err)
		}
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
		n.Server.SetBridgeExists(n.Net.HasDevice)
		n.Server.SetLBApply(func(_ context.Context, cfg lb.Config) error {
			mu.Lock()
			defer mu.Unlock()
			if n == c.Nodes[0] {
				applied[cfg.Name] = cfg.Interface
			}
			return nil
		})
	}
	for _, d := range []struct {
		from         *Node
		stack, octet string
	}{{c.Nodes[1], "sa", "1"}, {c.Nodes[0], "sb", "2"}} {
		msgs := deployCollect(t, ctx, c.SelfClient(d.from), fmt.Sprintf(composeBackendStack, d.stack, d.octet))
		for _, p := range msgs {
			if p.Phase == "error" {
				t.Fatalf("deploy %s: %s: %s", d.stack, p.VmName, p.Error)
			}
		}
	}
	n0 := c.Nodes[0]
	for _, w := range []struct{ lbName, dev, subnet string }{
		{"sa-lb", "sa_backend", "10.1.0.0/24"},
		{"sb-lb", "sb_backend", "10.2.0.0/24"},
	} {
		w := w
		var in corrosion.HostFWIntent
		eventually(t, 20*time.Second, w.lbName+"'s isolation intent on node-0", func() bool {
			intents, err := corrosion.ListHostFWIntent(ctx, n0.DB, n0.Name)
			if err != nil {
				return false
			}
			for _, x := range intents {
				if x.ScopeKey == "lb:"+w.lbName {
					in = x
					return in.SNATSubnet != ""
				}
			}
			return false
		})
		if in.Bridge != w.dev || in.SNATSubnet != w.subnet {
			t.Errorf("%s: intent on %s NATing %s, want %s NATing only %s", w.lbName, in.Bridge, in.SNATSubnet, w.dev, w.subnet)
		}
		mu.Lock()
		if got := applied[w.lbName]; got != w.dev {
			t.Errorf("%s: VIP placed on %q, want its own stack's %s", w.lbName, got, w.dev)
		}
		mu.Unlock()
	}
	// The two stacks are never on one device, on any node; node-0 has both.
	for _, n := range c.Nodes {
		da, okA := n.Net.Up("sa_backend")
		db, okB := n.Net.Up("sb_backend")
		if n == n0 && (!okA || !okB) {
			t.Errorf("node-0: sa_backend up=%v, sb_backend up=%v, want both", okA, okB)
		}
		if okA && okB && da == db {
			t.Errorf("%s: sa_backend and sb_backend share device %q", n.Name, da)
		}
	}
}
