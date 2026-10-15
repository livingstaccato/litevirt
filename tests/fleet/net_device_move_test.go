package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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

// composeIfaceTwoVMs puts ia and ic on node-0, on network lan.
const composeIfaceTwoVMs = `name: ic

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
  ic:
    image: test
    cpu: 1
    memory: 256
    placement:
      host: node-0
    network:
      - name: lan
`

// netIntent is network name's host firewall intent on n, or nil.
func netIntent(t *testing.T, n *Node, name string) *corrosion.HostFWIntent {
	t.Helper()
	all, err := corrosion.ListHostFWIntent(context.Background(), n.DB, n.Name)
	if err != nil {
		t.Fatalf("ListHostFWIntent: %v", err)
	}
	for i := range all {
		if all[i].ScopeKey == "net:"+name {
			return &all[i]
		}
	}
	return nil
}

// Lab 2, bug 2, and re-review NI1/NC1: an `interface:` change on the same
// subnet, on a host with two VMs on the network.
//
//   - While a VM RUNS on the old device, which carries the gateway, the move
//     is refused, naming the running VMs only, with the remedy that works:
//     stop or migrate them.
//   - Once only stopped VMs are defined on it, the gateway moves to the new
//     device at once and the old one keeps its L2 for them; each moves at its
//     own start, in any order, and the old one is retired after the last.
//   - Retiring the old device keeps the network's NAT intent, which names
//     the new one.
//
// Mutations: refuse on any user rather than a running one — the move never
// completes with ic stopped on lanaa; drop the gateway release — lanbb's
// dnsmasq exits 2; retire with Deprovision instead of RetireDevice — the NAT
// intent is gone.
func TestFleet_ComposeSameSubnetMoveWithTwoVMsOnAHost(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	n := c.Nodes[0]
	n.Net.SetDHCPConflicts(true)
	n.Net.SetIntents(true)
	cl := c.SelfClient(n)

	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceTwoVMs, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "ic", Force: true}); err != nil {
		t.Fatalf("stop ic: %v", err)
	}

	_, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceTwoVMs, "IFACE", "lanbb"))
	for _, want := range []string{"VM ia", "lanaa", "lanbb", "Stop or migrate"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("redeploy onto lanbb while ia runs on lanaa: err=%v, want a refusal containing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "VM ic") {
		t.Errorf("the refusal names stopped ic, which does not hold the move up: %v", err)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanaa" {
		t.Errorf("serving %v while ia runs on lanaa, want [lanaa]", got)
	}

	// The remedy: stop the running VM. The next pass moves the gateway.
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "ia", Force: true}); err != nil {
		t.Fatalf("stop ia: %v", err)
	}
	reconcileNetworks(t, n)
	if got := n.Net.Serving(); strings.Join(got, ",") != "lanbb" {
		t.Errorf("serving %v with only stopped VMs on lanaa, want the gateway on [lanbb]", got)
	}
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanaa,lanbb" {
		t.Errorf("bridges %v while ia and ic are defined on lanaa, want [lanaa lanbb]", b)
	}

	// ic starts first, then ia: each moves; lanaa goes after the last.
	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "ic"}); err != nil {
		t.Fatalf("start ic: %v", err)
	}
	if got := vmBridges(n, "ic"); got != "lanbb" {
		t.Errorf("ic started on %q, want lanbb", got)
	}
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanaa,lanbb" {
		t.Errorf("bridges %v while stopped ia is still defined on lanaa, want [lanaa lanbb]", b)
	}
	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "ia"}); err != nil {
		t.Fatalf("start ia: %v", err)
	}
	if got := vmBridges(n, "ia"); got != "lanbb" {
		t.Errorf("ia started on %q, want lanbb", got)
	}
	if !hasVMEvent(t, n, "ia", "vm.nic_moved", "ok") {
		t.Errorf("no vm.nic_moved event says ia's NIC moved")
	}
	// ia's start retired lanaa. The network's intent names lanbb and must
	// still be there: nothing re-provisions the network to put it back.
	if b, _ := n.Net.CreatedBridges(); strings.Join(b, ",") != "lanbb" {
		t.Errorf("bridges %v once both VMs moved, want [lanbb]", b)
	}
	in := netIntent(t, n, "ic_lan")
	if in == nil || in.Bridge != "lanbb" || in.MasqueradeSubnet != "172.46.0.0/24" {
		t.Errorf("ic_lan's firewall intent after the move = %+v, want NAT of 172.46.0.0/24 on lanbb", in)
	}
}

// Re-review NI2: a network that carries no gateway on this host — on a VLAN,
// or host-isolated — moves on the same subnet with its VM running; nothing
// collides, so nothing is refused. The isolation intent survives the
// retirement of the old device.
//
// Mutation: collide on the same subnet alone (drop ServingGateway and
// WouldServeGateway) — both redeploys are refused.
func TestFleet_SameSubnetMoveWithoutAGatewayIsNotRefused(t *testing.T) {
	for _, tc := range []struct{ name, extra string }{
		{"vlan", "    vlan: 30\n    underlay: eth0\n"},
		{"host-isolation", "    host-isolation: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 1, SharedCRDT: true})
			ctx := context.Background()
			seedTestImageEverywhere(t, c)
			n := c.Nodes[0]
			n.Net.SetDHCPConflicts(true)
			n.Net.SetIntents(true)
			cl := c.SelfClient(n)
			yaml := strings.Replace(composeIfaceChangeOneVM, "    dhcp: true\n", "    dhcp: true\n"+tc.extra, 1)
			if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(yaml, "IFACE", "lanaa")); err != nil {
				t.Fatalf("first deploy: %v", err)
			}
			if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(yaml, "IFACE", "lanbb")); err != nil {
				t.Fatalf("redeploy onto lanbb with ia running and no gateway here: %v", err)
			}
			if _, err := cl.RestartVM(ctx, &pb.RestartVMRequest{Name: "ia"}); err != nil {
				t.Fatalf("restart ia: %v", err)
			}
			reconcileNetworks(t, n)
			if got := vmBridges(n, "ia"); got != "lanbb" {
				t.Errorf("ia restarted on %q, want lanbb", got)
			}
			if tc.name == "host-isolation" {
				if in := netIntent(t, n, "ic_lan"); in == nil || !in.Isolate || in.Bridge != "lanbb" {
					t.Errorf("ic_lan's isolation intent after the move = %+v, want isolation on lanbb", in)
				}
			}
		})
	}
}

// Re-review NI3: after a daemon restart, a stopped VM's network has moved
// and its new device cannot be set up. The start leaves the VM on its old
// bridge, which is never swept for the attempt, and the VM starts there.
//
// Mutation: sweep the old bridge when the new provision fails — lanaa is
// swept.
func TestFleet_FailedMoveAtStartKeepsTheOldBridge(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	n := c.Nodes[0]
	cl := c.SelfClient(n)
	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "lanaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "ia", Force: true}); err != nil {
		t.Fatalf("stop ia: %v", err)
	}
	n.Server.ForgetNetworkReconcileForTests()
	def, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "lanbb", Subnet: "172.47.0.0/24"})
	if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "ic_lan", StackName: "ic", Type: "bridge", Config: string(def)}); err != nil {
		t.Fatal(err)
	}
	n.Net.FailProvision("ic_lan", errors.New("create bridge lanbb: exit status 2"))

	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "ia"}); err != nil {
		t.Fatalf("start ia: %v", err)
	}
	if got := vmBridges(n, "ia"); got != "lanaa" {
		t.Errorf("ia started on %q, want lanaa (its network's new device failed)", got)
	}
	if got := n.Net.Sweeps("lanaa"); got != 0 {
		t.Errorf("lanaa, ia's bridge, was swept %d times", got)
	}
	if b, _ := n.Net.CreatedBridges(); !strings.Contains(strings.Join(b, ","), "lanaa") {
		t.Errorf("bridges %v, want lanaa kept", b)
	}
	if !hasVMEvent(t, n, "ia", "vm.nic_moved", "error") {
		t.Errorf("no vm.nic_moved error event says why ia stayed on lanaa")
	}
}

// Re-review NI5: the record of a moved-off device survives a daemon restart.
// An operator's bridge (no litevirt record, so no sweep) that a network
// moved off while a VM ran on it has litevirt's gateway and dnsmasq retired
// after the restart, once the VM has gone; the bridge itself is the
// operator's and stays.
//
// Mutation: keep the record in memory only (no state path) — opaa keeps
// serving after the restart.
func TestFleet_MovedOffDeviceRecordSurvivesARestart(t *testing.T) {
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	ctx := context.Background()
	seedTestImageEverywhere(t, c)
	n := c.Nodes[0]
	n.Server.SetNetworkDeviceStatePath(filepath.Join(t.TempDir(), "network-devices.json"))
	n.Net.SetOperatorBridge("opaa")
	cl := c.SelfClient(n)
	if _, err := deployStream(t, ctx, cl, strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "opaa")); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	moved := strings.ReplaceAll(strings.ReplaceAll(composeIfaceChangeOneVM, "IFACE", "opbb"), "172.46.0.0/24", "172.47.0.0/24")
	if _, err := deployStream(t, ctx, cl, moved); err != nil {
		t.Fatalf("redeploy onto opbb: %v", err)
	}
	if got := n.Net.Serving(); strings.Join(got, ",") != "opaa,opbb" {
		t.Fatalf("serving %v while ia runs on opaa, want [opaa opbb]", got)
	}

	n.Server.ForgetNetworkReconcileForTests() // a daemon restart
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "ia", Force: true}); err != nil {
		t.Fatalf("stop ia: %v", err)
	}
	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "ia"}); err != nil {
		t.Fatalf("start ia: %v", err)
	}
	reconcileNetworks(t, n)
	if got := n.Net.Serving(); strings.Join(got, ",") != "opbb" {
		t.Errorf("serving %v after the restart once ia left opaa, want [opbb]", got)
	}
	if got := n.Net.Retires("opaa"); got != 1 {
		t.Errorf("opaa retired %d times, want 1", got)
	}
}

// Re-review NI4: a VM still running on the device its network moved off is
// live-migrated: it lands on the network's device now on the target, which
// never had the old one.
//
// Mutation: drop NICBridges from the migration parameters — the guest lands
// on lanaa.
func TestFleet_LiveMigrationMovesANICOntoItsNetworksDevice(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "lanbb", Subnet: "172.47.0.0/24"})
	if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: "mv_lan", StackName: "mv", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	const mac = "52:54:00:47:00:07"
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "mover", HostName: src.Name, State: "running", Spec: `{"name":"mover","cpu":1,"memory_mib":512}`,
		CPUActual: 1, MemActual: 512,
	}, []corrosion.InterfaceRecord{{VMName: "mover", NetworkName: "mv_lan", MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
	dom := `<domain type="kvm"><name>mover</name><memory unit="MiB">512</memory><vcpu>1</vcpu><devices>` +
		`<interface type="bridge"><mac address="` + mac + `"/><source bridge="lanaa"/><model type="virtio"/></interface>` +
		`</devices></domain>`
	src.Virt.SetInactiveXML("mover", dom)
	src.Virt.SetActiveXML("mover", dom)
	src.Virt.SetState("mover", "running")
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		x := p.DestXML
		if x == "" {
			x = dom
		}
		dst.Virt.LandMigrated(x)
		return nil
	}
	if err := migrateAt(t, c, src, "mover", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := strings.Join(domainBridges(dst.Virt.DefinedXML("mover")), ","); got != "lanbb" {
		t.Errorf("mover landed on %q on %s, want lanbb, the device mv_lan is on now", got, dst.Name)
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
