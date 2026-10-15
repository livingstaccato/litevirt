package fleet

import (
	"context"
	"sync"
	"testing"

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
	}
	if !found {
		t.Errorf("no LB isolation intent recorded (the lab's snat=false); intents: %+v", intents)
	}
}
