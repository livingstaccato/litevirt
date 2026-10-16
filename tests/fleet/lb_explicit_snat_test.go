package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"google.golang.org/protobuf/proto"
)

// composeHostIsolatedNetOnTwoHosts provisions a host-isolated network on
// node-0 and node-1 and nothing else, for an LB made with `lv lb create`.
const composeHostIsolatedNetOnTwoHosts = `name: lbx

images:
  test:
    source: file:///dev/null

networks:
  hinet:
    type: bridge
    subnet: 10.206.0.0/24
    dhcp: true
    host-isolation: true

vms:
  lbx1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: hinet
  lbx2:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-1
    network:
      - name: hinet
`

// TestFleet_ExplicitLBSNATReachesEveryLBHost: an LB made with `lv lb create`
// over two LB hosts has the outbound NAT asked for on both of them, the
// creating host and the one the create forwards the apply to, and an
// `lv lb update --snat` / `--snat=false` changes it on both.
//
// Mutations (each red): the create's ApplyLB to its peers sends snat true;
// the update's ApplyLB to its peers sends snat true.
func TestFleet_ExplicitLBSNATReachesEveryLBHost(t *testing.T) {
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
		// failover_scope_v1 latched: the setting can be recorded.
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	client := c.SelfClient(c.Nodes[0])
	for _, p := range deployCollect(t, ctx, client, composeHostIsolatedNetOnTwoHosts) {
		if p.Phase == "error" {
			t.Fatalf("deploy: %s: %s", p.VmName, p.Error)
		}
	}

	// snatOn reports whether n has the LB's isolation intent, and whether it
	// SNATs.
	snatOn := func(n *Node, name string) (found, snat bool) {
		intents, err := corrosion.ListHostFWIntent(ctx, n.DB, n.Name)
		if err != nil {
			return false, false
		}
		for _, x := range intents {
			if x.ScopeKey == "lb:"+name && len(x.Exceptions) == 1 {
				return true, x.SNATVIP != ""
			}
		}
		return false, false
	}

	for _, tc := range []struct {
		name, vip string
		snat      bool
	}{
		{"plain", "10.206.0.250/24", false},
		{"natted", "10.206.0.251/24", true},
	} {
		if _, err := client.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
			Name: tc.name, Vip: tc.vip, Hosts: []string{"node-0", "node-1"}, Snat: tc.snat,
			Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
			Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.206.0.10"}},
		}); err != nil {
			t.Fatalf("create %s: %v", tc.name, err)
		}
		for _, n := range c.Nodes {
			n := n
			var snat bool
			eventually(t, 20*time.Second, tc.name+"'s isolation intent on "+n.Name, func() bool {
				var found bool
				found, snat = snatOn(n, tc.name)
				return found
			})
			if snat != tc.snat {
				t.Errorf("%s after create on %s: SNAT %v, want %v", tc.name, n.Name, snat, tc.snat)
			}
		}
	}

	// Each update flips the setting; every LB host follows.
	for _, step := range []struct {
		name string
		snat bool
	}{
		{"plain", true},
		{"natted", false},
	} {
		if _, err := client.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: step.name, Snat: proto.Bool(step.snat)}); err != nil {
			t.Fatalf("update %s --snat=%v: %v", step.name, step.snat, err)
		}
		for _, n := range c.Nodes {
			n := n
			eventually(t, 20*time.Second, step.name+" with SNAT "+map[bool]string{true: "on", false: "off"}[step.snat]+" on "+n.Name, func() bool {
				found, snat := snatOn(n, step.name)
				return found && snat == step.snat
			})
		}
	}
}
