package fleet

import (
	"context"
	"encoding/json"
	"io"
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
// the network row. Every node now gets the same device, the network's own
// name, and the row keeps it.
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
		if dev, ok := n.Net.Up("nb_lan"); !ok || dev != "lan" {
			t.Errorf("%s: nb_lan provisioned=%v on %q, want on lan", n.Name, ok, dev)
		}
	}
	if got := rowInterface(t, c.Nodes[0].DB, "nb_lan"); got != "lan" {
		t.Errorf("nb_lan's row names interface %q after the deploy, want lan", got)
	}
}
