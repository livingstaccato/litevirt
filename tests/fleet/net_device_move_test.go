package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeIfaceChange = `name: ic

networks:
  lan:
    type: bridge
    interface: IFACE
    subnet: 172.46.0.0/24
    dhcp: true

vms:
  ia:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    network:
      - name: lan
  ib:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-1
    network:
      - name: lan
`

// Lab 2, bug 2: changing `interface:` of a deployed network made the next
// deploy fail — the new bridge got the same gateway address as the old one,
// whose dnsmasq still ran, so the new dnsmasq exited 2 — and stranded the old
// bridge and its dnsmasq on every node for good. A changed device is now torn
// down before the new one is set up, on the entry node and on each peer.
//
// While a guest on a node is still on the old device, that node refuses the
// move, naming the guest, and keeps serving the old device; once the guest
// has left, the reconciler finishes the move there.
//
// Mutation: skip retireReplacedDevice in provisionDevice — the second deploy
// fails with dnsmasq's exit status 2. Mutation: drop its guest-port check —
// the deploy with ia's tap still on lanaa succeeds.
func TestFleet_ComposeInterfaceChangeMovesTheNetwork(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	for _, n := range c.Nodes {
		n.Net.SetDHCPConflicts(true)
	}
	cl := c.SelfClient(c.Nodes[0])

	msgs, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lanaa"))
	if err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("first deploy failed: %s: %s", p.VmName, p.Error)
		}
	}
	for _, n := range c.Nodes {
		if dev, ok := n.Net.Up("ic_lan"); !ok || dev != "lanaa" {
			t.Fatalf("%s: ic_lan provisioned=%v on %q after the first deploy, want lanaa", n.Name, ok, dev)
		}
	}

	// A guest on node-1 is still on the old bridge: node-1 refuses the move.
	n1 := c.Nodes[1]
	n1.Net.SetGuestPorts("lanaa", "vnet3")
	_, err = deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lanbb"))
	if err == nil || !strings.Contains(err.Error(), "vnet3") || !strings.Contains(err.Error(), "lanaa") {
		t.Fatalf("redeploy onto lanbb with vnet3 still on lanaa on %s: err=%v, want a refusal naming vnet3 and lanaa", n1.Name, err)
	}
	if got := n1.Net.Serving(); len(got) != 1 || got[0] != "lanaa" {
		t.Errorf("%s serves %v while vnet3 is on lanaa, want [lanaa] untouched", n1.Name, got)
	}
	if got := c.Nodes[0].Net.Serving(); len(got) != 1 || got[0] != "lanbb" {
		t.Errorf("%s serves %v after the redeploy, want [lanbb]", c.Nodes[0].Name, got)
	}

	// The guest leaves; node-1's reconciler finishes the move.
	n1.Net.SetGuestPorts("lanaa")
	reconcileNetworks(t, n1)
	if got := n1.Net.Serving(); len(got) != 1 || got[0] != "lanbb" {
		t.Errorf("%s serves %v once vnet3 left lanaa, want [lanbb]", n1.Name, got)
	}

	// And a clean redeploy of the changed interface works on every node.
	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lancc")); err != nil {
		t.Fatalf("redeploy onto lancc: %v", err)
	}
	for _, n := range c.Nodes {
		if dev, ok := n.Net.Up("ic_lan"); !ok || dev != "lancc" {
			t.Errorf("%s: ic_lan provisioned=%v on %q, want lancc", n.Name, ok, dev)
		}
		if got := n.Net.Serving(); len(got) != 1 || got[0] != "lancc" {
			t.Errorf("%s serves %v after the move to lancc, want [lancc]", n.Name, got)
		}
		if b, _ := n.Net.CreatedBridges(); len(b) != 1 || b[0] != "lancc" {
			t.Errorf("%s keeps the bridges %v litevirt made, want [lancc]", n.Name, b)
		}
	}
}

// A device another live network still names is never torn down when one
// network moves off it: the move leaves it, and what it serves, alone.
//
// Mutation: drop the other-live-network check in retireReplacedDevice — brs is
// torn down under net "keep".
func TestFleet_NetworkMoveLeavesASharedDevice(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	cl := c.SelfClient(n)
	for _, name := range []string{"keep", "mover"} {
		if _, err := cl.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: name, Type: "bridge", Iface: "brs"}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	reconcileNetworks(t, n)
	def, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "brt"})
	if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "mover", Type: "bridge", Config: string(def)}); err != nil {
		t.Fatalf("move mover to brt: %v", err)
	}
	reconcileNetworks(t, n)
	if dev, ok := n.Net.Up("mover"); !ok || dev != "brt" {
		t.Fatalf("mover provisioned=%v on %q, want brt", ok, dev)
	}
	if got := n.Net.Deprovisions("mover"); got != 0 {
		t.Errorf("mover's old device brs, which keep still names, was torn down %d times", got)
	}
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "brs,brt" {
		t.Errorf("bridges after the move = %v, want [brs brt]", b)
	}
}

// After a restart the process no longer knows which device it set a network
// up on. A bridge litevirt made that no live network names any more, with no
// guest on it, is swept before the networks are provisioned, so a network
// that moved while this node was down does not collide with its old device.
// A bridge a network still names, one with a guest on it, and one a VM's NIC
// names, stay.
//
// Mutation: skip the sweep in ReconcileNetworksOnce — lanbb is never
// provisioned (dnsmasq exit 2) and lanaa stays. Mutation: drop the sweep's
// workload check — flatw is swept.
func TestFleet_ReconcileSweepsAnOrphanedBridgeAfterARestart(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	n.Net.SetDHCPConflicts(true)
	put := func(name, iface, subnet string) {
		t.Helper()
		def, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: iface, Subnet: subnet})
		if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: name, Type: "bridge", Config: string(def)}); err != nil {
			t.Fatalf("upsert %s: %v", name, err)
		}
	}
	put("moved", "lanaa", "172.47.0.0/24")
	put("held", "lanhh", "172.48.0.0/24")
	reconcileNetworks(t, n)
	// A flat bridge litevirt made for a VM's NIC: no network names it, the
	// VM's interface row does.
	n.Net.RecordCreatedBridge("flatw")
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{Name: "fw", HostName: n.Name, State: "stopped", Spec: "{}"},
		[]corrosion.InterfaceRecord{{VMName: "fw", NetworkName: "flatw", MAC: "52:54:00:00:00:09"}}, nil); err != nil {
		t.Fatalf("seed fw: %v", err)
	}

	// The node restarts; meanwhile "moved" was moved to lanbb, and "held"
	// to lanii while a guest is still on lanhh.
	n.Server.ForgetNetworkReconcileForTests()
	put("moved", "lanbb", "172.47.0.0/24")
	put("held", "lanii", "172.49.0.0/24")
	n.Net.SetGuestPorts("lanhh", "vnet9")
	reconcileNetworks(t, n)

	if got := n.Net.Sweeps("lanaa"); got != 1 {
		t.Errorf("orphaned lanaa swept %d times, want 1", got)
	}
	if dev, ok := n.Net.Up("moved"); !ok || dev != "lanbb" {
		t.Errorf("moved provisioned=%v on %q after the restart, want lanbb", ok, dev)
	}
	if got := n.Net.Sweeps("lanhh"); got != 0 {
		t.Errorf("lanhh, with vnet9 on it, was swept %d times", got)
	}
	if got := n.Net.Sweeps("flatw"); got != 0 {
		t.Errorf("flatw, which VM fw's NIC names, was swept %d times", got)
	}
	if got := n.Net.Sweeps("lanbb") + n.Net.Sweeps("lanii"); got != 0 {
		t.Errorf("a bridge a live network names was swept %d times", got)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanbb,lanhh,lanii" {
		t.Errorf("serving %v, want [lanbb lanhh lanii]", got)
	}
}
