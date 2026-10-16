package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
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
