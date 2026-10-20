package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// migratingRowServer is a server with "web" recorded migrating to "peer" on
// this host, its domain defined here in state dom.
func migratingRowServer(t *testing.T, dom libvirtfake.State) (*Server, *libvirtfake.Fake, *corrosion.VMRecord) {
	t.Helper()
	s, fake := provableCreateServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "web", HostName: s.hostName, State: "migrating", StateDetail: "→ peer",
		CPUActual: 1, MemActual: 256, Spec: `{"name":"web","cpu":1,"memory_mib":256}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>web</name><uuid>33333333-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("web", dom)
	vm, err := corrosion.GetVM(adminCtx(), s.db, "web")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	return s, fake, vm
}

// wantMigratingRefusal fails unless err is the FailedPrecondition that names
// the move.
func wantMigratingRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "migrating") {
		t.Fatalf("%s = %v; want FailedPrecondition naming the move", what, err)
	}
}

// The start primitive every operator and orchestration start goes through
// refuses a row recorded migrating by itself: no caller has to remember the
// guard, and none can bypass it.
//
// Mutation: the refusal removed from startVMLocked and from
// PrepareHardwareForStart — web boots on its source, red.
func TestStartVMLocked_RefusesARowRecordedMigrating(t *testing.T) {
	s, fake, vm := migratingRowServer(t, libvirtfake.StateDefined)
	_, err := s.startVMLocked(adminCtx(), vm)
	wantMigratingRefusal(t, "startVMLocked of a row recorded migrating", err)
	if st, _ := fake.RawState("web"); st == libvirtfake.StateRunning {
		t.Fatal("web was started on its source")
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, "web"); row == nil || row.State != "migrating" {
		t.Fatalf("web = %+v; want still migrating", row)
	}
}

// The pre-start hook shared with the automated start paths (the reconciler,
// the health checker, a restore) refuses a row recorded migrating, reading
// the row itself: a stale record saying stopped does not get past it.
//
// Mutation: the refusal removed, or the row not re-read — the stale record
// passes, red.
func TestPrepareHardwareForStart_RefusesARowRecordedMigrating(t *testing.T) {
	s, _, vm := migratingRowServer(t, libvirtfake.StateDefined)
	_, err := s.PrepareHardwareForStart(adminCtx(), vm)
	wantMigratingRefusal(t, "PrepareHardwareForStart of a row recorded migrating", err)
	stale := *vm
	stale.State, stale.StateDetail = "stopped", ""
	_, err = s.PrepareHardwareForStart(adminCtx(), &stale)
	wantMigratingRefusal(t, "PrepareHardwareForStart with a stale record of a row recorded migrating", err)
}

// The stop primitive refuses a row recorded migrating: only StopVM, which
// asks the move's target first (or finds the guest running here), records
// such a row stopped. Recorded stopped by anything else, the row would let
// the next start make a second copy.
//
// Mutation: the refusal removed — the guest is destroyed and the row written
// stopped, red.
func TestStopVMLocked_RefusesARowRecordedMigrating(t *testing.T) {
	s, fake, vm := migratingRowServer(t, libvirtfake.StateRunning)
	_, err := s.stopVMLocked(adminCtx(), vm, true, 0)
	wantMigratingRefusal(t, "stopVMLocked of a row recorded migrating", err)
	if st, _ := fake.RawState("web"); st != libvirtfake.StateRunning {
		t.Fatalf("web on its source = %v; want untouched, running", st)
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, "web"); row == nil || row.State != "migrating" {
		t.Fatalf("web = %+v; want still migrating", row)
	}
	// StopVM's own path, once it has found the guest running here, stops it.
	if _, err := s.stopMoveLeftLocked(context.Background(), vm, true, 0); err != nil {
		t.Fatalf("the stop StopVM makes after its check: %v", err)
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, "web"); row == nil || row.State != "stopped" {
		t.Fatalf("web after StopVM's stop = %+v; want stopped", row)
	}
}
