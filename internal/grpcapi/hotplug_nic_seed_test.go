package grpcapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Lab 2 (d53dc770, C2/C3): a hot attach or detach left the VM's seed as it
// was, so a guest that applied it again had no entry for an attached NIC
// (netplan left it down) and one for a NIC it no longer had (init-local
// failed: "Not all expected physical devices present"). The owner rewrites
// the seed's network-config on every attach and detach, on both kinds of
// cluster, and keeps its instance-id and user-data: the guest is not a new
// instance.
//
// The VM's seed was written with an instance-id that is not the VM's name,
// as a replaced VM's is (vm_replace_cleanup renames the replacement's seed).
//
// Mutation: drop the rebuild from the attach — B's MAC is missing after it;
// from the detach — A is still there after it; rebuild with the VM's name as
// instance-id — the identity check goes red.
func TestNICHotplug_RebuildsTheSeed(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	const (
		macA     = "52:54:00:5e:00:0a" // static, detached
		macD     = "52:54:00:5e:00:0d" // stays
		macB     = "52:54:00:5e:00:0b" // attached
		userData = "#cloud-config\nhostname: hp\n"
	)
	for _, latched := range []bool{true, false} {
		name := "unlatched"
		if latched {
			name = "latched"
		}
		t.Run(name, func(t *testing.T) {
			s := hotplugDiskServer(t)
			setDeviceGate(s, true, latched)
			ctx := adminCtx()
			spec := &pb.VMSpec{Name: "hp", Cpu: 2, MemoryMib: 4096,
				CloudInit: &pb.CloudInitSpec{Userdata: userData},
				Network: []*pb.NetworkAttachment{
					{Name: "lan", Mac: macA, Ip: "10.9.0.50"},
					{Name: "lan3", Mac: macD},
				}}
			// Both NIC tables, as CreateVM writes them (and as the backfill
			// leaves a VM created before vm_nics by the time hardware_v2
			// latches).
			ifaces := []corrosion.InterfaceRecord{
				{VMName: "hp", NetworkName: "lan", Ordinal: 0, MAC: macA, IP: "10.9.0.50"},
				{VMName: "hp", NetworkName: "lan3", Ordinal: 1, MAC: macD},
			}
			var nics []corrosion.NICRecord
			for _, i := range ifaces {
				nics = append(nics, corrosion.NICRecord{VMName: "hp", ID: corrosion.DeterministicNICID("hp", i.MAC),
					NetworkName: i.NetworkName, MAC: i.MAC, Ordinal: i.Ordinal, IP: i.IP})
			}
			if err := corrosion.InsertVMWithHardware(ctx, s.db, corrosion.VMRecord{
				Name: "hp", HostName: "test-host", State: "running", CPUActual: 2, MemActual: 4096,
				Spec: seedSpecJSON(t, spec),
			}, ifaces, nil, nics, nil, true); err != nil {
				t.Fatal(err)
			}
			iso := lv.CloudInitISOPath(s.dataDir, "hp")
			nc, err := cloudinit.SeedNetworkConfig(ctx, s.db, "hp", spec)
			if err != nil || !strings.Contains(nc, macA) {
				t.Fatalf("create-time network-config: %v\n%s", err, nc)
			}
			if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: "hp-first", LocalHostname: "hp",
				UserData: userData, NetworkConfig: nc}, iso); err != nil {
				t.Fatal(err)
			}
			read := func() cloudinit.Seed {
				t.Helper()
				sd, err := cloudinit.ReadSeed(iso)
				if err != nil {
					t.Fatalf("read seed: %v", err)
				}
				if sd.InstanceID() != "hp-first" || sd.UserData != userData {
					t.Fatalf("the seed's identity or user-data changed: %q %q", sd.MetaData, sd.UserData)
				}
				return sd
			}

			if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "hp",
				Nic: &pb.NetworkAttachment{Name: "lan2", Mac: macB}}); err != nil {
				t.Fatalf("attach: %v", err)
			}
			if got := read().NetworkConfig; !strings.Contains(got, macB) || !strings.Contains(got, macA) {
				t.Errorf("after the attach, want A, D and B in the seed:\n%s", got)
			}

			if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "hp", NicMac: macA}); err != nil {
				t.Fatalf("detach: %v", err)
			}
			got := read().NetworkConfig
			if strings.Contains(got, macA) || strings.Contains(got, "10.9.0.50") {
				t.Errorf("after the detach, the detached NIC is in the seed:\n%s", got)
			}
			if !strings.Contains(got, macD) || !strings.Contains(got, macB) || strings.Count(got, "macaddress:") != 2 {
				t.Errorf("after the detach, want exactly D and B:\n%s", got)
			}
		})
	}
}

// A VM with no seed on its host (no cloud image, or a seed this host never
// had) gets none from a hot attach.
//
// Mutation: rebuild whether or not a seed exists — a seed appears.
func TestNICHotplug_NoSeedStaysNoSeed(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "plain", "running")
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "plain",
		Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:5e:01:01"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if _, err := os.Stat(lv.CloudInitISOPath(s.dataDir, "plain")); !os.IsNotExist(err) {
		t.Errorf("a VM with no seed got one: %v", err)
	}
}
