package grpcapi

import (
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// staleSeedAfterAFailedAttach is a running VM x with NIC A whose seed here
// is stamped for it, and a NIC B attached while no ISO writer was there: B
// is attached, the seed does not list it, and the seed is marked stale. It
// returns the server and the seed's path.
func staleSeedAfterAFailedAttach(t *testing.T) (*Server, string) {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:77:00:01"}}}
	var iso string
	t.Run("write the seed", func(t *testing.T) {
		useSeedISOWriter(t)
		iso = r2VM(t, s, spec, []corrosion.InterfaceRecord{{VMName: "x", NetworkName: "lan", MAC: "52:54:00:77:00:01"}}, "running",
			cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: cloudinit.SpecUserData(spec)}, "uuid-x")
	})
	t.Run("attach B with no ISO writer", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:77:00:02"}}); err != nil {
			t.Fatalf("attach B: %v", err)
		}
	})
	if len(vmEventsOf(t, s, "x", "seed.rebuild_failed")) != 1 || !cloudinit.SeedMarkedStale(iso) {
		t.Fatal("setup: the failed rebuild was not reported, or left no stale mark")
	}
	if strings.Contains(mustReadSeed(t, iso).NetworkConfig, "52:54:00:77:00:02") {
		t.Fatal("setup: the seed lists B")
	}
	return s, iso
}

const seedRetryB = "macaddress: \"52:54:00:77:00:02\"\n    set-name: eth1\n"

// F4 (lab 2 seed hot-plug proof): a start of a defined domain — lv restart,
// lv stop then lv start — on a host whose seed of the VM is marked stale
// tries its rebuild again before the domain boots. Here it succeeds: the seed
// lists B, named eth1 as every host derives it, and the mark is gone; no new
// warning.
//
// Mutation: do not retry the rebuild on a start — the seed lacks B and the
// mark stays, both cases.
func TestStart_RetriesAStaleSeedsRebuild(t *testing.T) {
	for _, how := range []string{"restart", "stop, start"} {
		t.Run(how, func(t *testing.T) {
			s, iso := staleSeedAfterAFailedAttach(t)
			t.Run(how, func(t *testing.T) {
				useSeedISOWriter(t)
				if how == "restart" {
					if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "x"}); err != nil {
						t.Fatalf("restart: %v", err)
					}
					return
				}
				if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "x", Force: true}); err != nil {
					t.Fatalf("stop: %v", err)
				}
				if cloudinit.SeedMarkedStale(iso) == false || strings.Contains(mustReadSeed(t, iso).NetworkConfig, "52:54:00:77:00:02") {
					t.Fatal("the stop rebuilt the seed; it is the start that must")
				}
				if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "x"}); err != nil {
					t.Fatalf("start: %v", err)
				}
			})
			if nc := mustReadSeed(t, iso).NetworkConfig; !strings.Contains(nc, seedRetryB) {
				t.Errorf("the start did not bring the seed up to date: want B eth1:\n%s", nc)
			}
			if cloudinit.SeedMarkedStale(iso) {
				t.Error("the rebuild before the start succeeded and left the stale mark")
			}
			if n := len(vmEventsOf(t, s, "x", "seed.rebuild_failed")); n != 1 {
				t.Errorf("seed.rebuild_failed events = %d, want only the attach's", n)
			}
		})
	}
}

// F4: a start whose retried rebuild fails again still starts the VM, as main
// did, on the seed as it is, with the seed.rebuild_failed warning again naming
// the seed, the host and that the VM started on it; the mark stays.
//
// Mutation: do not retry — no second warning; refuse the start on the failure
// — the restart fails.
func TestStart_AStaleSeedWhoseRebuildFailsAgainStillStarts(t *testing.T) {
	s, iso := staleSeedAfterAFailedAttach(t)
	t.Setenv("PATH", t.TempDir())
	if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "x"}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if st, err := s.virt.DomainState("x"); err != nil || st != "running" {
		t.Fatalf("domain state after the restart = %q (%v), want running", st, err)
	}
	evs := vmEventsOf(t, s, "x", "seed.rebuild_failed")
	if len(evs) != 2 {
		t.Fatalf("seed.rebuild_failed events = %d, want the attach's and the start's", len(evs))
	}
	var start *corrosion.VMEventRecord
	for i := range evs {
		if strings.Contains(evs[i].Detail, "starts on it") {
			start = &evs[i]
		}
	}
	if start == nil || start.Severity != "warning" || !strings.Contains(start.Detail, iso) || !strings.Contains(start.Detail, s.hostName) {
		t.Errorf("want a start's seed.rebuild_failed warning naming %s and %s: %+v", iso, s.hostName, evs)
	}
	if !cloudinit.SeedMarkedStale(iso) {
		t.Error("a failed retry removed the stale mark")
	}
}

// F4: a start whose caller already tried the VM's seed for this start (the
// reconciler rewrites the VM's own seed before it defines the domain, and
// marks the context) is not tried again by the start hook: one failure, one
// warning. Unmarked, the hook tries it.
//
// Mutation: ignore the context mark — the marked case rebuilds the seed.
func TestPrepareHardwareForStart_ASeedTheCallerTriedIsNotTriedAgain(t *testing.T) {
	for _, tried := range []bool{true, false} {
		s, iso := staleSeedAfterAFailedAttach(t)
		vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
		if err != nil || vm == nil {
			t.Fatalf("GetVM: %v", err)
		}
		// The hook runs before the domain boots: it is shut off.
		if err := s.virt.DestroyDomain("x"); err != nil {
			t.Fatal(err)
		}
		ctx := adminCtx()
		if tried {
			ctx = cloudinit.WithSeedTriedForStart(ctx)
		}
		t.Run("prepare", func(t *testing.T) {
			useSeedISOWriter(t)
			release, err := s.PrepareHardwareForStart(ctx, vm)
			if err != nil {
				t.Fatalf("PrepareHardwareForStart: %v", err)
			}
			release()
		})
		rebuilt := strings.Contains(mustReadSeed(t, iso).NetworkConfig, seedRetryB)
		if rebuilt == tried || cloudinit.SeedMarkedStale(iso) != tried {
			t.Errorf("tried=%v: rebuilt=%v, still marked=%v", tried, rebuilt, cloudinit.SeedMarkedStale(iso))
		}
	}
}

// Review M4: the start hook can run over a domain that is already active (a
// start that finds it running in libvirt). Its seed is not rebuilt there: the
// running guest holds the old one open, and the mark stays for its next
// start, or an attach or detach, which reloads the cdrom.
//
// Mutation: drop the active check — the seed is rebuilt and the mark goes.
func TestPrepareHardwareForStart_AnActiveDomainsStaleSeedIsLeft(t *testing.T) {
	s, iso := staleSeedAfterAFailedAttach(t)
	vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	t.Run("prepare", func(t *testing.T) {
		useSeedISOWriter(t)
		release, err := s.PrepareHardwareForStart(adminCtx(), vm)
		if err != nil {
			t.Fatalf("PrepareHardwareForStart: %v", err)
		}
		release()
	})
	if strings.Contains(mustReadSeed(t, iso).NetworkConfig, seedRetryB) || !cloudinit.SeedMarkedStale(iso) {
		t.Error("the seed of an active domain was rebuilt under its guest, or lost its mark")
	}
}

// Review M3: a start's retry holds no VM lock on every path (the health
// restarts and the reconciler hold only the start lease), so an attach can
// commit and rebuild the seed between the retry's derivation of the
// network-config and its rewrite, which then drops the attached NIC from the
// seed. Derived again after the rewrite, a NIC set that moved keeps the seed
// marked stale, so the next start or attach puts the NIC back.
//
// Mutation: drop the check after the rewrite — the seed lacks C and is not
// marked.
func TestPrepareHardwareForStart_AnAttachDuringTheRetryKeepsTheMark(t *testing.T) {
	s, iso := staleSeedAfterAFailedAttach(t)
	vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if err := s.virt.DestroyDomain("x"); err != nil {
		t.Fatal(err)
	}
	attached := false
	seedStartRebuildRaced = func() {
		if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan3", Mac: "52:54:00:77:00:03"}}); err != nil {
			t.Errorf("attach C: %v", err)
			return
		}
		attached = true
	}
	t.Cleanup(func() { seedStartRebuildRaced = nil })
	t.Run("prepare", func(t *testing.T) {
		useSeedISOWriter(t)
		release, err := s.PrepareHardwareForStart(adminCtx(), vm)
		if err != nil {
			t.Fatalf("PrepareHardwareForStart: %v", err)
		}
		release()
	})
	if !attached {
		t.Fatal("setup: the attach did not run inside the retry")
	}
	if nc := mustReadSeed(t, iso).NetworkConfig; strings.Contains(nc, "52:54:00:77:00:03") {
		t.Fatalf("setup: the retry's rewrite did not overwrite the attach's seed:\n%s", nc)
	}
	if !cloudinit.SeedMarkedStale(iso) {
		t.Error("a seed that lacks a NIC the attach committed during the retry is not marked stale")
	}
}

// Review M1: a cutover's runtime handoff starts the VM under its name with
// StartDomain, outside the start hook. The replacement's seed, marked stale
// under its temporary name, moves to the VM's name with its mark, and is
// rebuilt before that start, as on every other start.
//
// Mutation: drop the retry from finishVMReplaceRuntime — the seed lacks B.
func TestFinishVMReplaceRuntime_RetriesAStaleSeedBeforeItsStart(t *testing.T) {
	s, iso := staleSeedAfterAFailedAttach(t)
	if err := s.virt.DestroyDomain("x"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.UndefineDomain("x", false); err != nil {
		t.Fatal(err)
	}
	// The replacement's seed under its temporary name, as the cutover left it.
	tmp := lv.CloudInitISOPath(s.dataDir, "x-next")
	for _, mv := range [][2]string{{iso, tmp}, {cloudinit.SeedOwnerPath(iso), cloudinit.SeedOwnerPath(tmp)}, {cloudinit.SeedStalePath(iso), cloudinit.SeedStalePath(tmp)}} {
		if err := os.Rename(mv[0], mv[1]); err != nil {
			t.Fatal(err)
		}
	}
	dom := "<domain type='kvm'><name>x-next</name><uuid>uuid-x</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>" +
		"<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='" + tmp + "'/><target dev='sdb' bus='sata'/><readonly/></disk>" +
		"<interface type='bridge'><mac address='52:54:00:77:00:01'/><source bridge='br0'/></interface>" +
		"<interface type='bridge'><mac address='52:54:00:77:00:02'/><source bridge='br1'/></interface>" +
		"</devices></domain>"
	vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	cl := corrosion.VMReplaceCleanup{OperationID: "op-x", AcceptedState: "running",
		Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-x"},
		Manifest: corrosion.VMReplaceManifest{
			HostName: s.hostName, ReplacedVM: "x", Replacement: "x-next",
			ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-x",
		}}
	t.Run("handoff", func(t *testing.T) {
		useSeedISOWriter(t)
		if err := s.finishVMReplaceRuntime(adminCtx(), cl); err != nil {
			t.Fatalf("finishVMReplaceRuntime: %v", err)
		}
	})
	if st, err := s.virt.DomainState("x"); err != nil || st != "running" {
		t.Fatalf("setup: the handoff did not start the domain: %q (%v)", st, err)
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Fatal("setup: the seed did not move to the VM's name")
	}
	if nc := mustReadSeed(t, iso).NetworkConfig; !strings.Contains(nc, seedRetryB) || cloudinit.SeedMarkedStale(iso) {
		t.Errorf("the handoff started the VM on its stale seed (marked=%v):\n%s", cloudinit.SeedMarkedStale(iso), nc)
	}
}
