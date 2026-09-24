package fleet

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// The lab failure, end to end: `lv network create hc --type isolated --subnet
// 172.16.50.0/24 --dhcp`, then a stack "hc" whose VM names network "hc"
// without declaring it. The VM came up on a flat bridge "hc_hc" — no gateway,
// no dnsmasq — and never got a lease, while br-iso-hc (which carries both)
// stood unused. A NIC naming an undeclared network is the cluster network of
// that name; it must be provisioned on the VM's host and the domain must sit
// on its bridge.
const composeOnClusterNetwork = `name: hc

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: hc
`

var domainBridgeRE = regexp.MustCompile(`bridge="([^"]+)"`)

func domainBridges(xml string) []string {
	var out []string
	for _, m := range domainBridgeRE.FindAllStringSubmatch(xml, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestFleet_ComposeVMOnUndeclaredNetworkUsesTheClusterNetwork(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)

	if _, err := client.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	msgs := deployCollect(t, ctx, client, composeOnClusterNetwork)
	if p := errorPhaseFor(msgs, "db"); p != nil {
		t.Fatalf("deploy of db failed: %s", p.Error)
	}
	var vm *corrosion.VMRecord
	deadline := time.Now().Add(5 * time.Second)
	for vm == nil || vm.State != "running" {
		if time.Now().After(deadline) {
			t.Fatalf("db = %+v, want running", vm)
		}
		vm, _ = corrosion.GetVM(ctx, node.DB, "db")
		time.Sleep(20 * time.Millisecond)
	}

	want := network.IsolatedBridgeName("hc")
	if got := domainBridges(node.Virt.DefinedXML("db")); len(got) != 1 || got[0] != want {
		t.Errorf("db's domain attaches to bridges %v, want [%s]", got, want)
	}
	if dev, ok := node.Net.Up("hc"); !ok || dev != want {
		t.Errorf("network hc on the VM's host: provisioned=%v device=%q, want provisioned on %s", ok, dev, want)
	}
	for _, b := range node.Net.FlatBridges() {
		if b != want {
			t.Errorf("a flat bridge %q was created for db's NIC", b)
		}
	}
	ifaces, err := corrosion.GetVMInterfaces(ctx, node.DB, "db")
	if err != nil || len(ifaces) != 1 || ifaces[0].NetworkName != "hc" {
		t.Errorf("db's interface rows = %+v (err %v), want one on network hc", ifaces, err)
	}
}

// With no cluster network of that name, the deploy is refused before any VM
// exists. It used to create a flat bridge named "<stack>_<name>" and report
// success.
func TestFleet_ComposeVMOnUnknownUndeclaredNetworkIsRefused(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: composeOnClusterNetwork})
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), `network "hc" (used by db) is not declared`) {
		t.Fatalf("deploy onto a network that does not exist: err=%v, want a refusal naming network hc and db", err)
	}
	if db, _ := corrosion.GetVM(ctx, node.DB, "db"); db != nil {
		t.Errorf("db was created (state %s) on a network that does not exist", db.State)
	}
	if got := node.Net.FlatBridges(); len(got) != 0 {
		t.Errorf("flat bridges %v were created for a refused deploy", got)
	}
}
