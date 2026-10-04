package grpcapi

import (
	"context"
	"database/sql/driver"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// handoffFault is what the lv_test_handoff_fault() SQL function runs, from a
// trigger, while one statement of the cold firmware handoff is executing. It is
// the only way to act between two of the handoff's writes: a Go-side hook would
// have to live in the code under test.
var (
	handoffFault         atomic.Pointer[func() error]
	registerHandoffFault sync.Once
)

// registerHandoffFaultFunc makes lv_test_handoff_fault() known to SQLite. It is
// registered on modernc's package-level driver, which hands it only to
// connections opened AFTERWARDS — so it must run before the test client opens.
func registerHandoffFaultFunc() {
	registerHandoffFault.Do(func() {
		sqlite.MustRegisterScalarFunction("lv_test_handoff_fault", 0,
			func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
				if f := handoffFault.Load(); f != nil {
					return nil, (*f)()
				}
				return int64(0), nil
			})
	})
}

func installHandoffFault(t *testing.T, fn func() error) {
	t.Helper()
	handoffFault.Store(&fn)
	t.Cleanup(func() { handoffFault.Store(nil) })
}

// coldFirmwareHandoffFixture is a stopped Secure Boot VM on the test server's
// host with two shared-storage disks, ready for handOffColdFirmwareVM.
func coldFirmwareHandoffFixture(t *testing.T) (*Server, *corrosion.VMRecord, []corrosion.DiskRecord) {
	t.Helper()
	registerHandoffFaultFunc()
	s := testServerWithLocks(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "fw", HostName: s.hostName, Spec: `{"name":"fw","secure_boot":true,"firmware":"uefi","uuid":"u1"}`, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: "fw", DiskName: "root", HostName: s.hostName, Path: "/srv/nfs/fw-root.qcow2", StorageType: "nfs"},
		{VMName: "fw", DiskName: "data", HostName: s.hostName, Path: "/srv/nfs/fw-data.qcow2", StorageType: "nfs"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "fw")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: vm=%v err=%v", vm, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, "fw")
	if err != nil || len(disks) != 2 {
		t.Fatalf("GetVMDisks: %d disks, err=%v", len(disks), err)
	}
	return s, vm, disks
}

// assertFirmwareHandoffConsistent fails unless the VM and every one of its disk
// records name the same host — and that host is the source, since the handoff
// under test did not complete.
func assertFirmwareHandoffConsistent(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	vm, err := corrosion.GetVM(ctx, s.db, "fw")
	if err != nil || vm == nil {
		t.Fatalf("GetVM after the handoff: vm=%v err=%v", vm, err)
	}
	if vm.HostName != s.hostName {
		t.Errorf("VM owner = %q after a failed handoff, want the source %q", vm.HostName, s.hostName)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, "fw")
	if err != nil {
		t.Fatalf("GetVMDisks after the handoff: %v", err)
	}
	for _, d := range disks {
		if d.HostName != vm.HostName {
			t.Errorf("disk %q is recorded on %q while its VM belongs to %q — ownership half-transferred",
				d.DiskName, d.HostName, vm.HostName)
		}
	}
}

// A client that disconnects (or hits its deadline) while the handoff is being
// written cancels the request context between two of its writes. The handoff
// used to commit one disk record per statement and then the VM row, rolling
// back on that same context: once it was cancelled every later write — the
// rollback's included — failed, leaving a disk recorded on the target while the
// VM still belonged to the source.
//
// The fault fires inside the SECOND disk-placement write to the target: it
// cancels the request and fails the write in flight, as the cancellation
// interrupting it would.
func TestColdFirmwareHandoff_CancelMidHandoffKeepsVMAndDisksTogether(t *testing.T) {
	s, vm, _ := coldFirmwareHandoffFixture(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	var moves atomic.Int32
	installHandoffFault(t, func() error {
		if moves.Add(1) < 2 {
			return nil
		}
		cancel()
		return errors.New("request cancelled mid-handoff")
	})
	if err := s.db.Execute(context.Background(),
		`CREATE TRIGGER handoff_fault BEFORE UPDATE OF host_name ON vm_disks
		 WHEN NEW.host_name = 't1'
		 BEGIN SELECT lv_test_handoff_fault(); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	err := s.handOffColdFirmwareVM(ctx, vm, &corrosion.HostRecord{Name: "t1"},
		firmwareSpec{SecureBoot: true, Firmware: "uefi", UUID: "u1"})
	if err == nil {
		t.Fatal("the handoff reported success although it was cancelled mid-write")
	}
	if got := moves.Load(); got < 2 {
		t.Fatalf("the fault fired on %d disk write(s), want 2 — the handoff never reached the point under test (err=%v)", got, err)
	}
	assertFirmwareHandoffConsistent(t, s)
}

// A daemon that dies part-way through the handoff gets no rollback at all.
// Modelled here as the VM-row transfer failing and no later write landing — the
// triggers refuse the VM's move to the target and any disk write back to the
// source. With the placement and ownership changes in one transaction there is
// no intermediate state for a crash to expose.
func TestColdFirmwareHandoff_InterruptedHandoffKeepsVMAndDisksTogether(t *testing.T) {
	s, vm, _ := coldFirmwareHandoffFixture(t)
	for _, ddl := range []string{
		`CREATE TRIGGER handoff_vm_dies BEFORE UPDATE OF host_name ON vms
		 WHEN NEW.host_name = 't1'
		 BEGIN SELECT RAISE(ABORT, 'daemon died before the VM row moved'); END;`,
		`CREATE TRIGGER handoff_no_rollback BEFORE UPDATE OF host_name ON vm_disks
		 WHEN NEW.host_name = '` + s.hostName + `'
		 BEGIN SELECT RAISE(ABORT, 'daemon died before its rollback'); END;`,
	} {
		if err := s.db.Execute(context.Background(), ddl); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
	}

	err := s.handOffColdFirmwareVM(adminCtx(), vm, &corrosion.HostRecord{Name: "t1"},
		firmwareSpec{SecureBoot: true, Firmware: "uefi", UUID: "u1"})
	if err == nil {
		t.Fatal("the handoff reported success although the VM row never moved")
	}
	assertFirmwareHandoffConsistent(t, s)
}

// The control: with nothing injected, the handoff moves the VM and every disk
// record to the target together, keeping the VM stopped and advancing its owner
// epoch exactly once.
func TestColdFirmwareHandoff_MovesVMAndDisksTogether(t *testing.T) {
	s, vm, disks := coldFirmwareHandoffFixture(t)
	if err := s.handOffColdFirmwareVM(adminCtx(), vm, &corrosion.HostRecord{Name: "t1"},
		firmwareSpec{SecureBoot: true, Firmware: "uefi", UUID: "u1"}); err != nil {
		t.Fatalf("handoff: %v", err)
	}
	ctx := context.Background()
	got, err := corrosion.GetVM(ctx, s.db, "fw")
	if err != nil || got == nil {
		t.Fatalf("GetVM: vm=%v err=%v", got, err)
	}
	if got.HostName != "t1" || got.State != "stopped" {
		t.Errorf("VM = (%q,%q), want (t1,stopped)", got.HostName, got.State)
	}
	if got.OwnerEpoch != vm.OwnerEpoch+1 {
		t.Errorf("owner epoch = %d, want %d — a migration is one ownership transition", got.OwnerEpoch, vm.OwnerEpoch+1)
	}
	after, err := corrosion.GetVMDisks(ctx, s.db, "fw")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	byName := map[string]string{}
	for _, d := range disks {
		byName[d.DiskName] = d.Path
	}
	for _, d := range after {
		if d.HostName != "t1" {
			t.Errorf("disk %q on %q, want t1", d.DiskName, d.HostName)
		}
		if d.Path != byName[d.DiskName] {
			t.Errorf("disk %q path = %q, want it unchanged (%q) on shared storage", d.DiskName, d.Path, byName[d.DiskName])
		}
	}
}
