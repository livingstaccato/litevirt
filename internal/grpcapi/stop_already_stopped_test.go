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

// Review M6: a VM in error, pending or starting holds its set-aside disk
// copies (a failover start that failed or is under way may need one put
// back). A stop that finds its domain already not running stopped nothing,
// so it must not end that hold by writing stopped/operator-stop: the row is
// left as it was, the copy stays held, and the answer is still success, with
// the no-op in the VM's event.
//
// Mutation: the no-op writes operator-stop over a holding row — the row reads
// stopped and the copy is no longer held: red.
func TestStopVM_ANoOpStopKeepsTheHoldOnSetAsideCopies(t *testing.T) {
	for _, state := range []string{"error", "pending", "starting"} {
		s := hotplugDiskServer(t)
		ctx := adminCtx()
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

		if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
			t.Fatalf("%s: stop of a VM whose domain is not running: %v", state, err)
		}
		vm, err := corrosion.GetVM(context.Background(), s.db, "vm1")
		if err != nil || vm == nil || vm.State != state || vm.StateDetail == "operator-stop" {
			t.Fatalf("%s: row %+v (%v), want it left %s", state, vm, err, state)
		}
		copies, err := health.ListSupersededDisks(context.Background(), s.db, s.dataDir)
		if err != nil || len(copies) != 1 || copies[0].Path != copyPath || copies[0].Held == "" {
			t.Fatalf("%s: copies %+v (%v), want %s still held", state, copies, err, copyPath)
		}
		if d := stoppedEventDetail(t, s, "vm1"); !strings.Contains(d, "already stopped") {
			t.Fatalf("%s: the vm.stopped event %q does not say the stop was a no-op", state, d)
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
