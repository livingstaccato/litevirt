package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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
// running, so the stop is done. For a row that does not hold set-aside copies
// the operator's stop is recorded, so HA leaves the VM stopped, and the VM's
// event says the stop was a no-op.
//
// Mutations: no not-running check — Internal: red. Any stop failure taken
// as done — the running domain whose shutdown fails succeeds: red. The
// active-state read's error taken as "not active" — red (review M4). The
// no-op not marked in the event — red.
func TestStopVM_AnAlreadyStoppedVMIsStopped(t *testing.T) {
	for _, force := range []bool{false, true} {
		s := hotplugDiskServer(t)
		ctx := adminCtx()
		fake := s.virt.(*libvirtfake.Fake)
		// The row says running; the domain is shut off (it stopped on its
		// own, and the row has not caught up).
		seedNICVM(t, s, "vm1", "running")
		fake.SetState("vm1", libvirtfake.StateShutdown)
		notRunningLikeLibvirt(fake, nil)
		if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: force}); err != nil {
			t.Fatalf("force=%v: stop of a stopped VM: %v", force, err)
		}
		vm, err := corrosion.GetVM(context.Background(), s.db, "vm1")
		if err != nil || vm == nil || vm.State != "stopped" || vm.StateDetail != "operator-stop" {
			t.Fatalf("force=%v: row %+v (%v), want stopped/operator-stop", force, vm, err)
		}
		if d := stoppedEventDetail(t, s, "vm1"); !strings.Contains(d, "already stopped") {
			t.Fatalf("force=%v: the vm.stopped event %q does not say the stop was a no-op", force, d)
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

		// Whether the domain is active cannot be read: the stop's failure
		// stands (review M4).
		seedNICVM(t, s, "vm3", "running")
		fake.SetState("vm3", libvirtfake.StateShutdown)
		fake.FailShutdownDomain = func(string) error { return errors.New("domain is not running") }
		fake.FailDestroyDomain = fake.FailShutdownDomain
		fake.FailDomainState = func(name string) error {
			if name == "vm3" {
				return errors.New("libvirt connection lost")
			}
			return nil
		}
		if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm3", Force: force}); status.Code(err) != codes.Internal {
			t.Fatalf("force=%v: a stop whose domain state cannot be read = %v, want Internal", force, err)
		}
		if vm, _ := corrosion.GetVM(context.Background(), s.db, "vm3"); vm == nil || vm.State != "running" || vm.StateDetail == "operator-stop" {
			t.Fatalf("force=%v: a stop whose domain state cannot be read recorded %+v", force, vm)
		}
		fake.FailDomainState = nil
	}
}

// heldVM seeds vm1 in state with a host-local disk and a set-aside copy beside
// it (which state holds), its domain shut off and refusing a stop as libvirt
// does. It returns the copy's path.
func heldVM(t *testing.T, s *Server, state string) string {
	t.Helper()
	fake := s.virt.(*libvirtfake.Fake)
	path := filepath.Join(s.dataDir, "disks", "vm1-root.qcow2")
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: state, Spec: seedSpecJSON(t, &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512}),
	}, nil, []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	copyPath := path + ".superseded-20261001T000000.000000000Z"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("the only copy of the VM's data from before the failover"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StateShutdown)
	notRunningLikeLibvirt(fake, nil)
	return copyPath
}

// heldUntouched fails unless vm1's row is still state and its copy still held.
func heldUntouched(t *testing.T, s *Server, state, copyPath string) {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, "vm1")
	if err != nil || vm == nil || vm.State != state || vm.StateDetail == "operator-stop" {
		t.Fatalf("%s: row %+v (%v), want it left %s", state, vm, err, state)
	}
	copies, err := health.ListSupersededDisks(context.Background(), s.db, s.dataDir)
	if err != nil || len(copies) != 1 || copies[0].Path != copyPath || copies[0].Held == "" {
		t.Fatalf("%s: copies %+v (%v), want %s still held", state, copies, err, copyPath)
	}
}

// Review M6: a VM in error holds its set-aside disk copies (a failover start
// that failed may need one put back). A stop that finds its domain already
// not running stopped nothing, so it must not end that hold by writing
// stopped/operator-stop: the row is left as it was, the copy stays held, and
// the answer is still success, with the no-op in the VM's event.
//
// Mutation: the no-op writes operator-stop over a holding row — the row reads
// stopped and the copy is no longer held: red.
func TestStopVM_ANoOpStopKeepsTheHoldOnSetAsideCopies(t *testing.T) {
	s := hotplugDiskServer(t)
	copyPath := heldVM(t, s, "error")
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop of an errored VM whose domain is not running: %v", err)
	}
	heldUntouched(t, s, "error", copyPath)
	if d := stoppedEventDetail(t, s, "vm1"); !strings.Contains(d, "already stopped") {
		t.Fatalf("the vm.stopped event %q does not say the stop was a no-op", d)
	}
}

// Fix round 2: a VM in pending or starting is being started (a failover's,
// an onboot's or a self-heal's start), and the reconciler will start its
// domain. A stop that finds the domain not running yet answers
// FailedPrecondition, saying the stop was not applied and what to do: a
// success the start then overrides would be a false answer. Nothing is
// changed: the row, the held copy, no vm.stopped event. (Main answered
// Internal.)
//
// Mutation: pending/starting answered as a no-op success again — red.
func TestStopVM_AVMBeingStartedRefusesTheStop(t *testing.T) {
	for _, state := range []string{"pending", "starting"} {
		for _, force := range []bool{false, true} {
			s := hotplugDiskServer(t)
			copyPath := heldVM(t, s, state)
			_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "vm1", Force: force})
			if status.Code(err) != codes.FailedPrecondition ||
				!strings.Contains(err.Error(), "being started") || !strings.Contains(err.Error(), "not applied") ||
				!strings.Contains(err.Error(), "lv stop vm1") {
				t.Fatalf("%s force=%v: stop = %v, want FailedPrecondition saying it is being started, the stop was not applied, and to stop it once it runs", state, force, err)
			}
			heldUntouched(t, s, state, copyPath)
			evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "vm1", 50, "")
			for _, e := range evs {
				if e.Type == "vm.stopped" {
					t.Fatalf("%s force=%v: a refused stop recorded %+v", state, force, e)
				}
			}
		}
	}
}

// stoppedEventDetail is the detail of vm's newest vm.stopped event.
func stoppedEventDetail(t *testing.T, s *Server, vm string) string {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 50, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	for _, e := range evs {
		if e.Type == "vm.stopped" {
			return e.Detail
		}
	}
	t.Fatalf("no vm.stopped event for %s: %+v", vm, evs)
	return ""
}

// Lab 2 C2 P-4: `lv ct stop` of a container that is already stopped returned
// `Internal … lxc-stop … is not running`. It now succeeds and records the
// operator's stop; a failed stop of a container that is running is still an
// error.
//
// Mutations: no state check — Internal: red. Any stop failure taken as done —
// the running container's failed stop succeeds: red. The no-op not marked in
// the audit row — red.
func TestStopContainer_AnAlreadyStoppedContainerIsStopped(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "ct1", Template: "download", Distro: "alpine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rt.stopErr = errors.New("lxc-stop ct1: ct1 is not running")
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("stop of a stopped container: %v", err)
	}
	row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1")
	if row == nil || row.State != "stopped" || row.StateDetail != "operator-stop" {
		t.Fatalf("row %+v, want stopped/operator-stop", row)
	}
	audits, err := s.db.Query(context.Background(), `SELECT detail, result FROM audit_log WHERE action = 'ct.stop' AND target = 'ct1'`)
	if err != nil || len(audits) != 1 || audits[0].String("result") != "ok" || !strings.Contains(audits[0].String("detail"), "already stopped") {
		t.Fatalf("ct.stop audit rows %+v (%v), want one ok row saying the stop was a no-op", audits, err)
	}

	rt.stopErr = nil
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	rt.stopErr = errors.New("lxc-stop ct1: timed out")
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "ct1"}); status.Code(err) != codes.Internal {
		t.Fatalf("a failed stop of a running container = %v, want Internal", err)
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1"); row == nil || row.State != "running" {
		t.Fatalf("a failed stop changed the row: %+v", row)
	}
}
