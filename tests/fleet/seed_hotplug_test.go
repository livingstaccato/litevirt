// Fleet scenario: a cloud-init VM's seed follows NIC hot-plug.
//
// Lab 2 (d53dc770, C2/C3): on a hardware_v2-latched cluster attach-nic and
// detach-nic change only vm_nics, while the seed's network-config was derived
// from the spec and the legacy vm_interfaces rows. The owner's seed was never
// rewritten, and a seed rebuilt on another host (migration, failover) named
// the detached NIC with its static address and left out the attached one.
//
// Multi-node by construction: the attach and detach are sent to the node
// that does NOT own the VM and reach the owner over real gRPC, and the
// migration target builds its copy of the seed from the network-config the
// source derives and sends it.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutation: read the seed's NIC set from the live vm_interfaces rows again —
// the latched case keeps A and misses B; drop the owner's rebuild on detach —
// the owner's seed keeps A; drop use-routes for isolated NICs — the
// isolated-NIC check goes red; rewrite the instance-id or the user-data on a
// rebuild — the identity check goes red.
func TestFleet_SeedFollowsNICHotplug(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed: the scenario reads the seeds back")
	}
	for _, latched := range []bool{true, false} {
		name := "unlatched"
		if latched {
			name = "latched"
		}
		t.Run(name, func(t *testing.T) { seedFollowsNICHotplug(t, latched) })
	}
}

func seedFollowsNICHotplug(t *testing.T, latched bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		// A NIC's bridge is the provisioner fake's; nothing touches a host
		// device.
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	for name, def := range map[string]compose.NetworkDef{
		"stnet":  {Type: "bridge", Subnet: "10.61.0.0/24", DHCP: true},
		"dnet":   {Type: "bridge", Subnet: "10.62.0.0/24", DHCP: true},
		"isonet": {Type: "isolated", Subnet: "10.63.0.0/24", DHCP: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}

	const (
		macA     = "52:54:00:5f:00:0a" // static on stnet, detached
		macD     = "52:54:00:5f:00:0d" // DHCP on dnet, stays
		userData = "#cloud-config\nhostname: sh\n"
	)
	if _, err := c.SelfClient(src).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sh", Cpu: 1, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Host: src.Name},
		CloudInit: &pb.CloudInitSpec{Userdata: userData},
		Network: []*pb.NetworkAttachment{
			{Name: "stnet", Mac: macA, Ip: "10.61.0.50"},
			{Name: "dnet", Mac: macD},
		},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	gates := gateAll(t, c)
	if latched {
		latchHardwareV2(t, c, gates)
	} else {
		latchOperationProtocol(t, c, gates)
	}

	// The seed a cloud image's create writes: the spec has no image here, so
	// the scenario writes it as CreateVM does, from the same derivation.
	srcISO := filepath.Join(c.tmpRoot, src.Name, "data", "cloudinit", "sh.iso")
	dstISO := filepath.Join(c.tmpRoot, dst.Name, "data", "cloudinit", "sh.iso")
	vm, err := corrosion.GetVM(ctx, src.DB, "sh")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	nc, err := cloudinit.SeedNetworkConfig(ctx, src.DB, "sh", &spec)
	if err != nil || !strings.Contains(nc, "10.61.0.50/24") {
		t.Fatalf("create-time network-config: %v\n%s", err, nc)
	}
	if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: "sh", LocalHostname: "sh", UserData: userData, NetworkConfig: nc}, srcISO); err != nil {
		t.Fatal(err)
	}

	// Attach B on the isolated network and detach A, both sent to dst.
	b := mustAttachNIC(t, c, dst, "sh", "isonet")
	mustDetachNIC(t, c, dst, "sh", macA)

	assertSeed := func(where, path string) {
		t.Helper()
		sd, err := cloudinit.ReadSeed(path)
		if err != nil {
			t.Fatalf("%s: read seed: %v", where, err)
		}
		if sd.InstanceID() != "sh" || sd.UserData != userData {
			t.Errorf("%s: the seed's identity or user-data changed: %q %q", where, sd.MetaData, sd.UserData)
		}
		got := strings.ToLower(sd.NetworkConfig)
		for _, gone := range []string{macA, "10.61.0.50"} {
			if strings.Contains(got, gone) {
				t.Errorf("%s: the detached NIC's %s is in the seed:\n%s", where, gone, got)
			}
		}
		if !strings.Contains(got, macD) || !strings.Contains(got, strings.ToLower(b.MAC)) || strings.Count(got, "macaddress:") != 2 {
			t.Errorf("%s: want exactly D and the attached B (%s):\n%s", where, b.MAC, got)
		}
		if !strings.Contains(got, strings.ToLower(b.MAC)+"\"\n    set-name: eth1\n    dhcp4: true\n    dhcp4-overrides:\n      route-metric: 101\n      use-routes: false\n") {
			t.Errorf("%s: the isolated NIC takes routes from its lease:\n%s", where, got)
		}
	}
	assertSeed("owner after attach and detach", srcISO)

	// A live move: the target builds its own copy of the seed.
	if _, err := os.Stat(dstISO); err == nil {
		t.Fatal("the target holds a seed before the move")
	}
	// The fleet runs no peer-probe loop, so the real checker counts one live
	// voter of two and refuses the move with no_quorum; quorum is not what
	// this scenario is about (migratableMirrorCluster).
	for _, n := range c.Nodes {
		n.Server.SetGate(quorumGranted{&fleetGate{Checker: gates[n.Name], reach: c.reach}})
	}
	mustMigrateVM(t, c, src, "sh", dst.Name)
	if moved, err := corrosion.GetVM(ctx, src.DB, "sh"); err != nil || moved == nil || moved.HostName != dst.Name {
		t.Fatalf("sh after the move = %+v (err %v), want it on %s", moved, err, dst.Name)
	}
	assertSeed("migration target", dstISO)
}
