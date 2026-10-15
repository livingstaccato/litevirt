package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
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

// composeIfaceChangeOneVM is composeIfaceChange with ia alone, on node-0.
const composeIfaceChangeOneVM = `name: ic

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
`

// vmBridges is the bridges vm's domain definition on n names.
func vmBridges(n *Node, vm string) string {
	return strings.Join(domainBridges(n.Virt.DefinedXML(vm)), ",")
}

func hasVMEvent(t *testing.T, n *Node, vm, typ, result string) bool {
	t.Helper()
	evs, _ := corrosion.ListVMEvents(context.Background(), n.DB, vm, 50, "")
	for _, e := range evs {
		if e.Type == typ && e.Result == result {
			return true
		}
	}
	return false
}

// Lab 2, bug 2: changing `interface:` of a deployed network made the next
// deploy fail — the new bridge got the same gateway address as the old one,
// whose dnsmasq still ran, so the new dnsmasq exited 2 — and stranded the old
// bridge and its dnsmasq on every node for good.
//
// The old device is never torn down while a VM's domain on that node still
// names it, stopped or running: its gateway stays, and only a real collision
// is refused — a new device on the same subnet — naming the VM and the
// remedy. `lv restart` (any start) moves the VM's NIC onto the network's
// device, and the old device goes once nothing names it.
//
// Mutations: drop the deviceReference check in retireReplacedDevice — the
// redeploy tears lanaa down under ia and succeeds; drop the collision refusal
// — the redeploy reports dnsmasq's exit 2; skip followNetworkDevices — ia
// restarts on lanaa.
func TestFleet_ComposeInterfaceChangeOnSameSubnetMovesEachVMAtItsRestart(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	for _, n := range c.Nodes {
		n.Net.SetDHCPConflicts(true)
	}
	n0, n1 := c.Nodes[0], c.Nodes[1]
	cl := c.SelfClient(n0)

	msgs, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lanaa"))
	if err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("first deploy failed: %s: %s", p.VmName, p.Error)
		}
	}
	if got := vmBridges(n0, "ia"); got != "lanaa" {
		t.Fatalf("ia is defined on %q, want lanaa", got)
	}

	_, err = deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChange, "IFACE", "lanbb"))
	for _, want := range []string{"VM ia", "lanaa", "lanbb", "lv restart"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("redeploy onto lanbb on the same subnet while ia is on lanaa: err=%v, want a refusal containing %q", err, want)
		}
	}
	for _, n := range c.Nodes {
		if got := n.Net.Serving(); strings.Join(got, ",") != "lanaa" {
			t.Errorf("%s serves %v while its VM is on lanaa, want [lanaa] untouched", n.Name, got)
		}
	}

	if _, err := cl.RestartVM(ctx, &pb.RestartVMRequest{Name: "ia"}); err != nil {
		t.Fatalf("restart ia: %v", err)
	}
	if got := vmBridges(n0, "ia"); got != "lanbb" {
		t.Errorf("ia restarted on %q, want lanbb, the device its network is on now", got)
	}
	if !hasVMEvent(t, n0, "ia", "vm.nic_moved", "ok") {
		t.Errorf("no vm.nic_moved event says ia's NIC moved")
	}
	if got := n0.Net.Serving(); strings.Join(got, ",") != "lanbb" {
		t.Errorf("%s serves %v after ia moved, want [lanbb]", n0.Name, got)
	}
	if got := n1.Net.Serving(); strings.Join(got, ",") != "lanaa" {
		t.Errorf("%s serves %v while ib is still on lanaa, want [lanaa]", n1.Name, got)
	}

	if _, err := c.SelfClient(n1).RestartVM(ctx, &pb.RestartVMRequest{Name: "ib"}); err != nil {
		t.Fatalf("restart ib: %v", err)
	}
	if got := vmBridges(n1, "ib"); got != "lanbb" {
		t.Errorf("ib restarted on %q, want lanbb", got)
	}
	for _, n := range c.Nodes {
		if got := n.Net.Serving(); strings.Join(got, ",") != "lanbb" {
			t.Errorf("%s serves %v once its VM moved, want [lanbb]", n.Name, got)
		}
		if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanbb" {
			t.Errorf("%s keeps the bridges %v, want [lanbb]", n.Name, b)
		}
	}
}

// Review C1: a network moves to another device while a VM on it is stopped.
// The VM's domain still names the old bridge, so the old bridge, its gateway
// and dnsmasq stay — a reconcile pass and its sweep included — until the VM
// starts; `lv start` puts its NIC on the new device and the old one goes.
//
// Mutations: drop the libvirt lookup from deviceReference — lanaa is torn
// down while ia is stopped; skip followNetworkDevices — ia starts on lanaa.
func TestFleet_NetworkMoveWhileAVMIsStoppedKeepsTheOldBridgeUntilItStarts(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	n := c.Nodes[0]
	cl := c.SelfClient(n)
	one := composeIfaceChangeOneVM

	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(one, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "ia", Force: true}); err != nil {
		t.Fatalf("stop ia: %v", err)
	}
	// Another subnet too, so the kept lanaa does not collide with lanbb.
	moved := strings.ReplaceAll(strings.ReplaceAll(one, "IFACE", "lanbb"), "172.46.0.0/24", "172.47.0.0/24")
	if _, err := deployStream(t, ctx, cl, moved); err != nil {
		t.Fatalf("redeploy onto lanbb: %v", err)
	}
	reconcileNetworks(t, n)
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanaa,lanbb" {
		t.Errorf("bridges %v while stopped ia's domain names lanaa, want [lanaa lanbb]", b)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanaa,lanbb" {
		t.Errorf("serving %v while stopped ia's domain names lanaa, want [lanaa lanbb]", got)
	}

	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "ia"}); err != nil {
		t.Fatalf("start ia: %v", err)
	}
	if got := vmBridges(n, "ia"); got != "lanbb" {
		t.Errorf("ia started on %q, want lanbb", got)
	}
	reconcileNetworks(t, n)
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanbb" {
		t.Errorf("bridges %v once ia moved, want [lanbb]", b)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanbb" {
		t.Errorf("serving %v once ia moved, want [lanbb]", got)
	}
}

// A move to a device on another subnet does not collide: it deploys, the
// old device stays for the running VM, and goes once that VM has moved.
func TestFleet_InterfaceAndSubnetChangeDeploysAndKeepsTheOldDeviceForItsVM(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	n := c.Nodes[0]
	n.Net.SetDHCPConflicts(true)
	cl := c.SelfClient(n)
	one := composeIfaceChangeOneVM

	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(one, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	moved := strings.ReplaceAll(strings.ReplaceAll(one, "IFACE", "lanbb"), "172.46.0.0/24", "172.47.0.0/24")
	if _, err := deployStream(t, ctx, cl, moved); err != nil {
		t.Fatalf("redeploy onto lanbb on another subnet: %v", err)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanaa,lanbb" {
		t.Errorf("serving %v while running ia is on lanaa, want [lanaa lanbb]", got)
	}
	if _, err := cl.RestartVM(ctx, &pb.RestartVMRequest{Name: "ia"}); err != nil {
		t.Fatalf("restart ia: %v", err)
	}
	reconcileNetworks(t, n)
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanbb" {
		t.Errorf("serving %v once ia moved, want [lanbb]", got)
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
// A bridge a network still names, one with a guest on it, one a VM's NIC row
// names, one a stopped VM's domain names and one a container's config links
// to, stay.
//
// Mutation: skip the sweep in ReconcileNetworksOnce — lanbb is never
// provisioned (dnsmasq exit 2) and lanaa stays. Mutation: drop the sweep's
// workload check — flatw is swept. Mutation: drop the libvirt lookup from
// deviceReference — lanvv is swept; drop the container lookup — lanct is.
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

	// A bridge only a stopped VM's domain definition names, and one only a
	// container's config links to: no row of any kind names either.
	n.Net.RecordCreatedBridge("lanvv")
	if err := n.Virt.DefineDomain(`<domain type="kvm"><name>vv</name><memory unit="MiB">256</memory><vcpu>1</vcpu><devices>` +
		`<interface type="bridge"><mac address="52:54:00:00:00:0a"/><source bridge="lanvv"/><model type="virtio"/></interface>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define vv: %v", err)
	}
	n.Net.RecordCreatedBridge("lanct")
	if _, err := n.CT.CreateContainer(ctx, grpcapi.CreateContainerOpts{Name: "ct1",
		Networks: []grpcapi.ContainerNICOpt{{Name: "eth0", Bridge: "lanct"}}}); err != nil {
		t.Fatalf("create ct1: %v", err)
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
	if got := n.Net.Sweeps("lanvv"); got != 0 {
		t.Errorf("lanvv, which stopped VM vv's domain names, was swept %d times", got)
	}
	if got := n.Net.Sweeps("lanct"); got != 0 {
		t.Errorf("lanct, which container ct1's config links to, was swept %d times", got)
	}
	if got := n.Net.Sweeps("lanbb") + n.Net.Sweeps("lanii"); got != 0 {
		t.Errorf("a bridge a live network names was swept %d times", got)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanbb,lanhh,lanii" {
		t.Errorf("serving %v, want [lanbb lanhh lanii]", got)
	}
}

// The container side of review C1: a stopped container whose config links a
// NIC to its network's old device keeps that device until it starts, and its
// start relinks the NIC to the network's device now.
//
// Mutation: skip followNetworkDevicesCT in startContainerArmed — ct2 starts
// linked to lancta.
func TestFleet_NetworkMoveWhileAContainerIsStoppedRelinksItAtStart(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	n := c.Nodes[0]
	ctx := context.Background()
	cl := c.SelfClient(n)
	if _, err := cl.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: "cn", Type: "bridge", Iface: "lancta", Subnet: "172.48.0.0/24"}); err != nil {
		t.Fatalf("create cn: %v", err)
	}
	if _, err := cl.CreateContainer(ctx, &pb.CreateContainerRequest{
		HostName: n.Name, Name: "ct2", Template: "download", Distro: "alpine", Release: "3.21", Arch: "amd64", MemoryMib: 256,
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "cn"}},
	}); err != nil {
		t.Fatalf("create ct2: %v", err)
	}
	if links, _ := n.CT.ContainerNICLinks(ctx, "ct2"); links[0] != "lancta" {
		t.Fatalf("ct2 NIC 0 links to %q, want lancta", links[0])
	}
	reconcileNetworks(t, n)
	def, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "lanctb", Subnet: "172.49.0.0/24"})
	if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "cn", Type: "bridge", Config: string(def)}); err != nil {
		t.Fatalf("move cn to lanctb: %v", err)
	}
	reconcileNetworks(t, n)
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lancta,lanctb" {
		t.Errorf("bridges %v while stopped ct2 links to lancta, want [lancta lanctb]", b)
	}
	if _, err := cl.StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "ct2"}); err != nil {
		t.Fatalf("start ct2: %v", err)
	}
	if links, _ := n.CT.ContainerNICLinks(ctx, "ct2"); links[0] != "lanctb" {
		t.Errorf("ct2 started linked to %q, want lanctb", links[0])
	}
	reconcileNetworks(t, n)
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanctb" {
		t.Errorf("bridges %v once ct2 moved, want [lanctb]", b)
	}
}
