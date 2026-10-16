// Fleet scenarios: a VM's seed after a failover names its NICs as the seed
// its last host rebuilt at each NIC attach and detach did (T2 concern 2).
//
// Multi-node by construction: the attach and detach are sent to the node that
// does not own the VM and reach the owner over real gRPC, and the failover
// start is the survivor's reconciler (internal/health) writing a seed from the
// replicated records alone.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// seededVMCluster is a 2-node cluster, operation protocol (and, latched,
// hardware_v2) latched, with VM name created on the first node from spec and
// the seed a cloud image's create writes there, stamped. It returns the
// cluster, the seed path of each node, and each node's gate.
func seededVMCluster(t *testing.T, latched bool, name string, nets map[string]compose.NetworkDef, spec *pb.VMSpec) (*Cluster, map[string]string, map[string]*health.Checker) {
	t.Helper()
	cloudinit.UseGoISOWithoutGenisoimage()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	home := c.Nodes[0]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	for nn, def := range nets {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, home.DB, corrosion.NetworkRecord{Name: nn, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	spec.Name = name
	spec.Placement = &pb.PlacementSpec{Host: home.Name}
	if _, err := c.SelfClient(home).CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	gates := gateAll(t, c)
	if latched {
		latchHardwareV2(t, c, gates)
	} else {
		latchOperationProtocol(t, c, gates)
	}
	isos := map[string]string{}
	for _, n := range c.Nodes {
		isos[n.Name] = filepath.Join(c.tmpRoot, n.Name, "data", "cloudinit", name+".iso")
	}
	vm, err := corrosion.GetVM(ctx, home.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	var stored pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &stored); err != nil {
		t.Fatal(err)
	}
	nc, err := cloudinit.SeedNetworkConfig(ctx, home.DB, name, &stored, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: name, LocalHostname: name,
		UserData: cloudinit.SpecUserData(&stored), NetworkConfig: nc,
		VendorData: cloudinit.SeedVendorData(&stored, nc)}, isos[home.Name]); err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.StampSeed(isos[home.Name], cloudinit.SpecUUID(vm.Spec)); err != nil {
		t.Fatal(err)
	}
	return c, isos, gates
}

// failOver moves name onto to as a failover coordinator does (the owner
// transfer to a pending row), with its former host's domain gone, and runs
// to's reconciler: the start defines the domain there and writes its seed.
func failOver(t *testing.T, c *Cluster, name string, from, to *Node) {
	t.Helper()
	ctx := context.Background()
	vm, err := corrosion.GetVM(ctx, to.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if err := corrosion.TransferVMOwner(ctx, to.DB, name, to.Name, "pending", vm.OwnerEpoch); err != nil {
		t.Fatalf("transfer %s to %s: %v", name, to.Name, err)
	}
	_ = from.Virt.DestroyDomain(name)
	_ = from.Virt.UndefineDomain(name, false)
	rec := health.NewReconciler(to.Name, filepath.Join(c.tmpRoot, to.Name, "data"), to.DB, to.Virt)
	rec.SetNetworkProvision(to.Net.Provision)
	rec.ReconcileOnce(ctx)
	if !to.Virt.DomainExists(name) {
		t.Fatalf("%s: the failover start defined no domain of %s", to.Name, name)
	}
}

func mustReadSeedAt(t *testing.T, where, path string) cloudinit.Seed {
	t.Helper()
	sd, err := cloudinit.ReadSeed(path)
	if err != nil {
		t.Fatalf("%s: read seed: %v", where, err)
	}
	return sd
}

// T2 concern 2: [A, B, C] created; B detached and D attached on its owner.
// The owner's seed keeps A eth0 and C eth2 and names D eth3. A failover to a
// host with no seed of the VM wrote eth<position> — C eth1, D eth2 — and the
// guest, re-applying the seed on every boot, renamed both. The survivor's
// seed names the NICs exactly as the owner's did.
//
// The same holds where the survivor keeps a seed a deleted VM of the name
// left (stamped for another VM): its names are not this VM's.
//
// Mutation: name the NICs by position where no seed is readable (the
// round-5 code) — red; take the names from whatever seed is there — the
// residue case leaves every NIC unnamed.
func TestFleet_FailoverToASeedlessHostKeepsNICNames(t *testing.T) {
	for _, tc := range []struct {
		name             string
		latched, residue bool
	}{{"latched", true, false}, {"unlatched", false, false}, {"latched, a deleted VM's seed there", true, true}} {
		latched, residue := tc.latched, tc.residue
		t.Run(tc.name, func(t *testing.T) {
			const (
				macA = "52:54:00:5f:01:0a"
				macB = "52:54:00:5f:01:0b"
				macC = "52:54:00:5f:01:0c"
			)
			c, isos, _ := seededVMCluster(t, latched, "nm", map[string]compose.NetworkDef{
				"na": {Type: "bridge", Subnet: "10.71.0.0/24", DHCP: true},
				"nb": {Type: "bridge", Subnet: "10.72.0.0/24", DHCP: true},
				"nc": {Type: "bridge", Subnet: "10.73.0.0/24", DHCP: true},
				"nd": {Type: "bridge", Subnet: "10.74.0.0/24", DHCP: true},
			}, &pb.VMSpec{Cpu: 1, MemoryMib: 256,
				CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: nm\n"},
				Network: []*pb.NetworkAttachment{
					{Name: "na", Mac: macA}, {Name: "nb", Mac: macB}, {Name: "nc", Mac: macC},
				}})
			home, survivor := c.Nodes[0], c.Nodes[1]

			mustDetachNIC(t, c, survivor, "nm", macB)
			d := mustAttachNIC(t, c, survivor, "nm", "nd")
			owner := mustReadSeedAt(t, "owner", isos[home.Name]).NetworkConfig
			for _, want := range []string{
				"  eth0:\n    match:\n      macaddress: \"" + macA + "\"\n    set-name: eth0\n",
				"  eth2:\n    match:\n      macaddress: \"" + macC + "\"\n    set-name: eth2\n",
				"  eth3:\n    match:\n      macaddress: \"" + strings.ToLower(d.MAC) + "\"\n    set-name: eth3\n",
			} {
				if !strings.Contains(strings.ToLower(owner), strings.ToLower(want)) {
					t.Fatalf("setup: the owner's seed lacks\n%s\nin\n%s", want, owner)
				}
			}

			if _, err := os.Stat(isos[survivor.Name]); err == nil {
				t.Fatal("setup: the survivor holds a seed before the failover")
			}
			if residue {
				if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: "nm", LocalHostname: "nm",
					UserData: "#cloud-config\nhostname: gone\n"}, isos[survivor.Name]); err != nil {
					t.Fatal(err)
				}
				if err := cloudinit.StampSeed(isos[survivor.Name], "uuid-of-a-deleted-vm"); err != nil {
					t.Fatal(err)
				}
			}
			failOver(t, c, "nm", home, survivor)
			got := mustReadSeedAt(t, "survivor", isos[survivor.Name])
			if got.NetworkConfig != owner {
				t.Errorf("the survivor's seed names the NICs\n%s\nwant the owner's\n%s", got.NetworkConfig, owner)
			}
			if got.VendorData != cloudinit.NetworkUpdatesVendorData {
				t.Errorf("survivor vendor-data = %q", got.VendorData)
			}
		})
	}
}

// T2 N6: a failover leaves the VM's stamped seed on its former host, and
// nothing removes it when that host rejoins. The VM fails over, a NIC with a
// static address is attached on the survivor, and the VM goes back to its
// former host, by a live migration or a failover. That host reused its stale
// seed as it was — the migration dropped the source's request — and the
// guest, applying a seed's network-config on every boot, lost the attached
// NIC's configuration. The former host's seed takes the VM's current NICs,
// named as on the survivor, its instance-id and user-data unchanged.
//
// Mutation: keep EnsureCloudInit's early return for the VM's own seed —
// "migrate back" goes red; reuse the reconciler's own seed as it is — "fail
// over back" goes red.
func TestFleet_FailbackRefreshesTheFormerHostsSeed(t *testing.T) {
	for _, back := range []string{"migrate back", "fail over back"} {
		t.Run(back, func(t *testing.T) {
			ctx := context.Background()
			const (
				macA     = "52:54:00:5f:02:0a"
				userData = "#cloud-config\nhostname: fb\n"
			)
			c, isos, gates := seededVMCluster(t, true, "fb", map[string]compose.NetworkDef{
				"na":    {Type: "bridge", Subnet: "10.76.0.0/24", DHCP: true},
				"hinet": {Type: "bridge", Subnet: "10.77.0.0/24", HostIsolation: true},
			}, &pb.VMSpec{Cpu: 1, MemoryMib: 256,
				CloudInit: &pb.CloudInitSpec{Userdata: userData},
				Network:   []*pb.NetworkAttachment{{Name: "na", Mac: macA}}})
			home, survivor := c.Nodes[0], c.Nodes[1]
			stale := mustReadSeedAt(t, "home before the failover", isos[home.Name])

			failOver(t, c, "fb", home, survivor)
			if _, err := c.SelfClient(home).AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "fb",
				Nic: &pb.NetworkAttachment{Name: "hinet", Ip: "10.77.0.9"}}); err != nil {
				t.Fatalf("attach a static NIC through %s: %v", home.Name, err)
			}
			now := mustReadSeedAt(t, "survivor", isos[survivor.Name])
			if !strings.Contains(now.NetworkConfig, "    set-name: eth1\n    addresses:\n      - 10.77.0.9/24\n") {
				t.Fatalf("setup: the survivor's seed does not configure the attached NIC:\n%s", now.NetworkConfig)
			}
			if !cloudinit.SeedIsFor(isos[home.Name], vmSpecUUIDOf(t, home, "fb")) {
				t.Fatal("setup: the former host does not hold the VM's stamped seed")
			}

			switch back {
			case "migrate back":
				for _, n := range c.Nodes {
					n.Server.SetGate(quorumGranted{&fleetGate{Checker: gates[n.Name], reach: c.reach}})
				}
				mustMigrateVM(t, c, survivor, "fb", home.Name)
			default:
				failOver(t, c, "fb", survivor, home)
			}
			got := mustReadSeedAt(t, "former host", isos[home.Name])
			if got.NetworkConfig != now.NetworkConfig || got.VendorData != now.VendorData {
				t.Errorf("the former host's seed:\n%s\n%q\nwant the survivor's:\n%s\n%q", got.NetworkConfig, got.VendorData, now.NetworkConfig, now.VendorData)
			}
			if got.MetaData != stale.MetaData || got.UserData != stale.UserData {
				t.Errorf("the former host's seed changed identity or user-data: %q %q", got.MetaData, got.UserData)
			}
		})
	}
}
