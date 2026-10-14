package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// notRunningLikeLibvirt makes the fake's shutdown and destroy of a domain
// that is not active fail as libvirt's do ("Requested operation is not valid:
// domain is not running"); the fake itself accepts them. other, when set, is
// what they return for an active domain.
func notRunningLikeLibvirt(f *libvirtfake.Fake, other error) {
	fail := func(name string) error {
		if active, err := f.DomainIsActive(name); err == nil && !active {
			return errors.New("shutdown domain " + name + ": Requested operation is not valid: domain is not running")
		}
		return other
	}
	f.FailShutdownDomain = fail
	f.FailDestroyDomain = fail
}

// Lab 2 O-4: `lv stop` of a VM that is already stopped returned
// `Internal … domain is not running`. A stop is now idempotent, as a start of
// a running VM is (StartVM heals the row and succeeds): the domain is not
// running, so the stop is done; the operator's stop is recorded, so HA leaves
// the VM stopped.
//
// Mutations: no not-running check — Internal: red. Any stop failure taken
// as done — the running domain whose shutdown fails succeeds: red.
func TestStopVM_AnAlreadyStoppedVMIsStopped(t *testing.T) {
	for _, force := range []bool{false, true} {
		s := hotplugDiskServer(t)
		ctx := adminCtx()
		fake := s.virt.(*libvirtfake.Fake)
		seedNICVM(t, s, "vm1", "error")
		fake.SetState("vm1", libvirtfake.StateShutdown)
		notRunningLikeLibvirt(fake, nil)
		if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: force}); err != nil {
			t.Fatalf("force=%v: stop of a stopped VM: %v", force, err)
		}
		vm, err := corrosion.GetVM(context.Background(), s.db, "vm1")
		if err != nil || vm == nil || vm.State != "stopped" || vm.StateDetail != "operator-stop" {
			t.Fatalf("force=%v: row %+v (%v), want stopped/operator-stop", force, vm, err)
		}

		// A domain that IS running and whose stop fails is still an error.
		seedNICVM(t, s, "vm2", "running")
		fake.SetState("vm2", libvirtfake.StateRunning)
		notRunningLikeLibvirt(fake, errors.New("internal error: qemu monitor timed out"))
		if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm2", Force: force}); status.Code(err) != codes.Internal {
			t.Fatalf("force=%v: a failed stop of a running domain = %v, want Internal", force, err)
		}
		if vm, _ := corrosion.GetVM(context.Background(), s.db, "vm2"); vm == nil || vm.StateDetail == "operator-stop" {
			t.Fatalf("force=%v: a failed stop recorded %+v", force, vm)
		}
	}
}

// Lab 2 C2 P-4: `lv ct stop` of a container that is already stopped returned
// `Internal … lxc-stop … is not running`. It now succeeds and records the
// operator's stop; a failed stop of a container that is running is still an
// error.
//
// Mutations: no state check — Internal: red. Any stop failure taken as done —
// the running container's failed stop succeeds: red.
func TestStopContainer_AnAlreadyStoppedContainerIsStopped(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "ct1", Template: "download", Distro: "alpine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rt.stopErr = errors.New("lxc-stop ct1: ct1 is not running")
	rt.stateByName = map[string]string{"ct1": "stopped"}
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("stop of a stopped container: %v", err)
	}
	row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1")
	if row == nil || row.State != "stopped" || row.StateDetail != "operator-stop" {
		t.Fatalf("row %+v, want stopped/operator-stop", row)
	}

	rt.stopErr = nil
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rt.stopErr = errors.New("lxc-stop ct1: timed out")
	rt.stateByName["ct1"] = "running"
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "ct1"}); status.Code(err) != codes.Internal {
		t.Fatalf("a failed stop of a running container = %v, want Internal", err)
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1"); row == nil || row.State != "running" {
		t.Fatalf("a failed stop changed the row: %+v", row)
	}
}
