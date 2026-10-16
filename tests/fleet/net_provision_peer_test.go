package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedTestImageEverywhere puts image "test" in the catalogue and its file in
// every node's store, so a deploy may place a VM on any node, and lets a VM's
// bridge check pass (the fleet has no host bridges).
func seedTestImageEverywhere(t *testing.T, c *Cluster) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	if err := corrosion.InsertImage(ctx, c.Nodes[0].DB, corrosion.ImageRecord{
		Name: "test", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024,
	}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	for _, n := range c.Nodes {
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatalf("stage image file on %s: %v", n.Name, err)
		}
		if err := corrosion.InsertImageHost(ctx, n.DB, corrosion.ImageHostRecord{
			ImageName: "test", HostName: n.Name, Path: n.Server.ImagePathForTests("test"), Status: "ready",
		}); err != nil {
			t.Fatalf("seed image host %s: %v", n.Name, err)
		}
	}
}

// deployStream runs a deploy and returns its progress and the stream's
// terminal error (nil on a clean end).
func deployStream(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string) ([]*pb.DeployProgress, error) {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err != nil {
		return nil, err
	}
	var out []*pb.DeployProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
}

func rowInterface(t *testing.T, db *corrosion.Client, name string) string {
	t.Helper()
	nr, err := corrosion.GetNetwork(context.Background(), db, name)
	if err != nil || nr == nil {
		t.Fatalf("network %s: row=%v err=%v", name, nr, err)
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(nr.Config), &def); err != nil {
		t.Fatalf("network %s config: %v", name, err)
	}
	return def.Interface
}

const composeBridgeNoInterface = `name: nb

networks:
  lan:
    type: bridge
    subnet: 172.45.0.0/24
    dhcp: true

vms:
  va:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    network:
      - name: lan
  vb:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-1
    network:
      - name: lan
  vc:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-2
    network:
      - name: lan
`

// Lab 2, bug 1: a bridge network with no `interface:` deployed to a stack
// with VMs on peers failed on every peer with "bridge network requires
// interface name": the entry node defaulted the interface for itself only,
// and sent the peers the definition without one — which they also wrote over
// the network row. Every node now gets the same device, the network's
// stack-scoped name, and the row keeps it.
//
// Mutation: drop the interface default in provisionPlannedNetworks — the
// deploy fails on node-1 and node-2.
func TestFleet_ComposeBridgeWithoutInterfaceDeploysOnEveryNode(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)

	msgs, err := deployStream(t, ctx, c.SelfClient(c.Nodes[0]), composeBridgeNoInterface)
	if err != nil {
		t.Fatalf("deploy of a bridge network with no interface onto three nodes: %v", err)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy failed: %s: %s", p.VmName, p.Error)
		}
	}
	for _, n := range c.Nodes {
		if dev, ok := n.Net.Up("nb_lan"); !ok || dev != "nb_lan" {
			t.Errorf("%s: nb_lan provisioned=%v on %q, want on nb_lan", n.Name, ok, dev)
		}
	}
	if got := rowInterface(t, c.Nodes[0].DB, "nb_lan"); got != "nb_lan" {
		t.Errorf("nb_lan's row names interface %q after the deploy, want nb_lan", got)
	}
}

const composeTwoStackBackend = `name: %[1]s

networks:
  backend:
    type: bridge
    subnet: 10.%[2]s.0.0/24
    dhcp: true

vms:
  %[1]sa:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    network:
      - name: backend
  %[1]sb:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-1
    network:
      - name: backend
`

// Two stacks that each name a network `backend` with no interface, both
// deployed from node-2, which runs neither: node-0 and node-1 provision both
// as peer targets. Each stack's network is on its own scoped device, the same
// on every node, so the two never share an L2 segment.
//
// Mutation: default a stack network's interface to its short name — red.
func TestFleet_TwoStacksSameShortNetworkNameGetDifferentDevicesOnPeers(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)

	for _, d := range []struct{ stack, octet string }{{"sa", "1"}, {"sb", "2"}} {
		msgs, err := deployStream(t, ctx, c.SelfClient(c.Nodes[2]), fmt.Sprintf(composeTwoStackBackend, d.stack, d.octet))
		if err != nil {
			t.Fatalf("deploy %s: %v", d.stack, err)
		}
		for _, p := range msgs {
			if p.Phase == "error" {
				t.Fatalf("deploy %s failed: %s: %s", d.stack, p.VmName, p.Error)
			}
		}
	}
	for _, n := range c.Nodes[:2] {
		da, okA := n.Net.Up("sa_backend")
		db, okB := n.Net.Up("sb_backend")
		if !okA || da != "sa_backend" {
			t.Errorf("%s: sa_backend up=%v on %q, want on sa_backend", n.Name, okA, da)
		}
		if !okB || db != "sb_backend" {
			t.Errorf("%s: sb_backend up=%v on %q, want on sb_backend", n.Name, okB, db)
		}
		if okA && okB && da == db {
			t.Errorf("%s: both stacks' backend on one device %q", n.Name, da)
		}
	}
	for _, name := range []string{"sa_backend", "sb_backend"} {
		if got := rowInterface(t, c.Nodes[0].DB, name); got != name {
			t.Errorf("%s's row names interface %q, want %s", name, got, name)
		}
	}
}

// A stack deployed before the scoped default (its row records the short
// `backend`) keeps that device on a redeploy, on every node: the default never
// moves a deployed network. When another stack's network is recorded on the
// same device, the deploy is warned, naming both stacks and the remedy.
//
// Mutation: drop the recorded-device lookup — sa moves to sa_backend, red.
// Mutation: do not send the shared-device warnings — red.
func TestFleet_RedeployKeepsARecordedSharedDeviceAndWarns(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	for _, d := range []struct{ stack, octet string }{{"sa", "1"}, {"sb", "2"}} {
		cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "backend", Subnet: "10." + d.octet + ".0.0/24", DHCP: true})
		if err := corrosion.UpsertNetwork(ctx, c.Nodes[0].DB, corrosion.NetworkRecord{
			Name: d.stack + "_backend", StackName: d.stack, Type: "bridge", Config: string(cfg),
		}); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := deployStream(t, ctx, c.SelfClient(c.Nodes[2]), fmt.Sprintf(composeTwoStackBackend, "sa", "1"))
	if err != nil {
		t.Fatalf("redeploy sa: %v", err)
	}
	warned := false
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("redeploy sa failed: %s: %s", p.VmName, p.Error)
		}
		if p.Phase == "warning" && strings.Contains(p.Detail, `"sb"`) && strings.Contains(p.Detail, "interface: sa_backend") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no deploy warning naming stack sb and the remedy; progress: %v", msgs)
	}
	for _, n := range c.Nodes[:2] {
		if dev, ok := n.Net.Up("sa_backend"); !ok || dev != "backend" {
			t.Errorf("%s: sa_backend up=%v on %q, want kept on its recorded backend", n.Name, ok, dev)
		}
	}
	if got := rowInterface(t, c.Nodes[0].DB, "sa_backend"); got != "backend" {
		t.Errorf("sa_backend's row names %q after the redeploy, want backend", got)
	}
}

const composeDirectNoInterface = `name: dn

networks:
  eth1:
    type: direct

vms:
  da:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    network:
      - name: eth1
  db:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-1
    network:
      - name: eth1
`

// A direct network with no interface attaches macvtap to the host NIC named
// after it, as on main, on the entry host and the peer alike: the scoped
// default is for bridges only.
//
// Mutation: give direct networks the scoped default — red.
func TestFleet_DirectNetworkWithoutInterfaceUsesTheHostNIC(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	msgs, err := deployStream(t, ctx, c.SelfClient(c.Nodes[0]), composeDirectNoInterface)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy failed: %s: %s", p.VmName, p.Error)
		}
	}
	for _, n := range c.Nodes {
		if dev, ok := n.Net.Up("dn_eth1"); !ok || dev != "direct:eth1" {
			t.Errorf("%s: dn_eth1 up=%v on %q, want direct:eth1", n.Name, ok, dev)
		}
	}
	if got := rowInterface(t, c.Nodes[0].DB, "dn_eth1"); got != "eth1" {
		t.Errorf("dn_eth1's row names %q, want eth1", got)
	}
}

const composeHostBridge = `name: hb

networks:
  br0:
    type: bridge

vms:
  ha:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    network:
      - name: br0
  hb:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-1
    network:
      - name: br0
`

// A new stack network named after a bridge the entry host already has (an
// operator's, which no stack network is on) is put on that bridge, as on
// main; the entry host decides once and every peer gets the same device.
//
// Mutation: drop the host-bridge rule — the network goes to hb_br0, red.
// Mutation: no host-bridge warning for the second stack — red.
func TestFleet_StackNetworkNamedAfterAHostBridgeUsesIt(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	entry := c.Nodes[0]
	entry.Net.SetOperatorBridge("br0")
	entry.Server.SetIsBridge(func(dev string) bool { return dev == "br0" })
	msgs, err := deployStream(t, ctx, c.SelfClient(entry), composeHostBridge)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy failed: %s: %s", p.VmName, p.Error)
		}
	}
	for _, n := range c.Nodes {
		if dev, ok := n.Net.Up("hb_br0"); !ok || dev != "br0" {
			t.Errorf("%s: hb_br0 up=%v on %q, want the host bridge br0", n.Name, ok, dev)
		}
	}
	if got := rowInterface(t, c.Nodes[0].DB, "hb_br0"); got != "br0" {
		t.Errorf("hb_br0's row names %q, want br0", got)
	}

	// A second stack naming the same host bridge does not share it silently:
	// it gets its scoped bridge, and the deploy says how to share.
	msgs, err = deployStream(t, ctx, c.SelfClient(entry), strings.NewReplacer("name: hb", "name: hc", "  ha:", "  hca:", "  hb:", "  hcb:").Replace(composeHostBridge))
	if err != nil {
		t.Fatalf("deploy hc: %v", err)
	}
	warned := false
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy hc failed: %s: %s", p.VmName, p.Error)
		}
		if p.Phase == "warning" && strings.Contains(p.Detail, `"hb"`) && strings.Contains(p.Detail, `to share it, set "interface: br0" and redeploy`) {
			warned = true
		}
	}
	if !warned {
		t.Errorf("hc's deploy did not warn that br0 is hb's and how to share it; progress: %v", msgs)
	}
	for _, n := range c.Nodes {
		if dev, ok := n.Net.Up("hc_br0"); !ok || dev != "hc_br0" {
			t.Errorf("%s: hc_br0 up=%v on %q, want its own hc_br0", n.Name, ok, dev)
		}
	}
}
