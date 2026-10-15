package grpcapi

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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
// Round 1: the running guest's seed cdrom is reloaded after each rebuild, so
// the guest reads the new seed without waiting for the domain's next start,
// and the seed carries the vendor-data that has cloud-init apply it again.
//
// Mutation: drop the rebuild from the attach — B's MAC is missing after it;
// from the detach — A is still there after it; rebuild with the VM's name as
// instance-id — the identity check goes red; drop the reload — the reload
// counts go red; rebuild with no vendor-data — the vendor-data check goes red.
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
			fake := s.virt.(*libvirtfake.Fake)
			fake.SetState("hp", libvirtfake.StateRunning)
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
				if sd.VendorData != cloudinit.NetworkUpdatesVendorData {
					t.Errorf("the rebuilt seed's vendor-data = %q, want the network update events", sd.VendorData)
				}
				return sd
			}
			reloads := func() int {
				n := 0
				for _, e := range fake.EventLog() {
					if e.Op == "reload-cdrom" && e.Domain == "hp" && e.Note == "path="+iso {
						n++
					}
				}
				return n
			}

			if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "hp",
				Nic: &pb.NetworkAttachment{Name: "lan2", Mac: macB}}); err != nil {
				t.Fatalf("attach: %v", err)
			}
			if got := read().NetworkConfig; !strings.Contains(got, macB) || !strings.Contains(got, macA) {
				t.Errorf("after the attach, want A, D and B in the seed:\n%s", got)
			}
			if n := reloads(); n != 1 {
				t.Errorf("after the attach, the running guest's seed cdrom was reloaded %d times, want 1", n)
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
			if n := reloads(); n != 2 {
				t.Errorf("after the detach, the seed cdrom was reloaded %d times in all, want 2", n)
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

// hpSeededVM is a running VM "hp" with one NIC row and a seed on this host.
func hpSeededVM(t *testing.T, s *Server, state string) string {
	t.Helper()
	ctx := adminCtx()
	const mac = "52:54:00:5e:02:01"
	spec := &pb.VMSpec{Name: "hp", Cpu: 2, MemoryMib: 4096, Network: []*pb.NetworkAttachment{{Name: "lan", Mac: mac}}}
	if err := corrosion.InsertVMWithHardware(ctx, s.db, corrosion.VMRecord{
		Name: "hp", HostName: "test-host", State: state, CPUActual: 2, MemActual: 4096, Spec: seedSpecJSON(t, spec),
	}, []corrosion.InterfaceRecord{{VMName: "hp", NetworkName: "lan", MAC: mac}}, nil,
		[]corrosion.NICRecord{{VMName: "hp", ID: corrosion.DeterministicNICID("hp", mac), NetworkName: "lan", MAC: mac}}, nil, true); err != nil {
		t.Fatal(err)
	}
	if state == "running" {
		s.virt.(*libvirtfake.Fake).SetState("hp", libvirtfake.StateRunning)
	}
	iso := lv.CloudInitISOPath(s.dataDir, "hp")
	if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: "hp", LocalHostname: "hp"}, iso); err != nil {
		t.Fatal(err)
	}
	return iso
}

// Round 1: a reload that fails leaves the attach done — the NIC is attached
// and the seed rebuilt — and says what to do: a VM event naming `lv restart`,
// which starts the domain again and so opens the new seed.
//
// Mutation: fail the attach on a reload error — red; drop the event — red.
func TestNICHotplug_SeedReloadFailureIsReported(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	iso := hpSeededVM(t, s, "running")
	s.virt.(*libvirtfake.Fake).FailReloadCDROM = func(string, string) error { return errors.New("injected media change failure") }
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "hp",
		Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:5e:02:02"}}); err != nil {
		t.Fatalf("attach failed on a seed reload failure: %v", err)
	}
	if sd, err := cloudinit.ReadSeed(iso); err != nil || !strings.Contains(sd.NetworkConfig, "52:54:00:5e:02:02") {
		t.Fatalf("the seed was not rebuilt: %+v %v", sd, err)
	}
	evs, err := corrosion.ListVMEvents(ctx, s.db, "hp", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "seed.reload_failed" && strings.Contains(e.Detail, "lv restart hp") && strings.Contains(e.Detail, "injected media change failure") {
			found = true
		}
	}
	if !found {
		t.Errorf("no seed.reload_failed event naming `lv restart hp`: %+v", evs)
	}
}

// A stopped VM's seed is rebuilt and not reloaded: no domain holds it open,
// and its next start opens the new one.
//
// Mutation: reload whether or not the VM runs — the fake refuses a stopped
// domain and the test sees a reload attempt (a seed.reload_failed event).
func TestNICHotplug_StoppedVMSeedIsNotReloaded(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	iso := hpSeededVM(t, s, "stopped")
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "hp",
		Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:5e:03:02"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if sd, err := cloudinit.ReadSeed(iso); err != nil || !strings.Contains(sd.NetworkConfig, "52:54:00:5e:03:02") {
		t.Fatalf("the stopped VM's seed was not rebuilt: %+v %v", sd, err)
	}
	for _, e := range s.virt.(*libvirtfake.Fake).EventLog() {
		if e.Op == "reload-cdrom" {
			t.Errorf("a stopped VM's seed cdrom was reloaded: %+v", e)
		}
	}
	evs, _ := corrosion.ListVMEvents(ctx, s.db, "hp", 50, "")
	for _, e := range evs {
		if e.Type == "seed.reload_failed" {
			t.Errorf("a stopped VM's seed reload was attempted: %+v", e)
		}
	}
}
