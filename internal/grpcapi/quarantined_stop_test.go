package grpcapi

import (
	"context"
	"encoding/json"
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

// A refusal under release probation says it lifts by itself; one under a
// rollback quarantine says to upgrade or reseed. Probation needs neither, so
// the rollback remedy would send an operator to rebuild a host that is about
// to recover on its own.
//
// Mutation: return the upgrade/reseed remedy unconditionally — the
// probation case goes red.
func TestQuarantineRemedy_BySource(t *testing.T) {
	s := testServer(t)
	s.db.EnterReleaseProbation([]string{"release_2099_01_v1"})
	if got := s.quarantineRemedy(); !strings.Contains(got, "lifts by itself") || strings.Contains(got, "reseed") {
		t.Errorf("probation remedy: %q, want that it lifts by itself", got)
	}
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	if got := s.quarantineRemedy(); !strings.Contains(got, "reseed the host") || strings.Contains(got, "lifts by itself") {
		t.Errorf("rollback remedy: %q, want upgrade/reseed", got)
	}
}

// qsServer is a server owning web, running, on a libvirt fake.
func qsServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServerWithLocks(t)
	f := libvirtfake.New()
	s.virt = f
	if err := f.DefineDomain("<domain><name>web</name></domain>"); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("web"); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running", Spec: string(spec)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	return s, f
}

func qsRow(t *testing.T, s *Server) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, "web")
	if err != nil {
		t.Fatal(err)
	}
	return vm
}

// Under write quarantine `lv stop --force` writes its marker, for the row's
// incarnation, before the domain is destroyed, and answers stopped. The row
// is left as it was: nothing replicated is written.
//
// Red on 884306b75: the forced stop is refused, FailedPrecondition.
func TestStopVM_QuarantinedForceWritesMarkerBeforeKill(t *testing.T) {
	s, f := qsServer(t)
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	markedAtKill := false
	f.FailDestroyDomain = func(string) error {
		_, ok, err := health.ReadOperatorStopMarker(s.dataDir, "web")
		markedAtKill = ok && err == nil
		return nil
	}
	out, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true})
	if err != nil {
		t.Fatalf("StopVM --force under quarantine: %v", err)
	}
	if out.State != pb.VMState_VM_STOPPED || out.StateDetail != quarantinedStopDetail {
		t.Errorf("answer %v/%q", out.State, out.StateDetail)
	}
	if !markedAtKill {
		t.Errorf("the domain was destroyed before its marker was on disk")
	}
	if active, _ := f.DomainIsActive("web"); active {
		t.Errorf("web still runs")
	}
	row := qsRow(t, s)
	m, ok, err := health.ReadOperatorStopMarker(s.dataDir, "web")
	if err != nil || !ok || m.Host != s.hostName || m.Incarnation != corrosion.IncarnationOf(row.CreatedAt) || m.Quarantine == "" {
		t.Errorf("marker %+v ok=%v err=%v, want this host and incarnation %q", m, ok, err, row.CreatedAt)
	}
	if row.State != "running" {
		t.Errorf("row %s/%q, want it untouched (running)", row.State, row.StateDetail)
	}
}

// A marker that cannot be written refuses the forced stop before libvirt is
// touched, FailedPrecondition, naming why.
//
// Mutation, refuse-on-unwritable (the write error ignored): the domain is
// destroyed: red.
func TestStopVM_QuarantinedForceRefusedWhenMarkerUnwritable(t *testing.T) {
	s, f := qsServer(t)
	if err := os.WriteFile(health.OperatorStopMarkerDir(s.dataDir), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	_, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "could not be written") ||
		!strings.Contains(err.Error(), "left running") {
		t.Errorf("StopVM --force, marker unwritable: %v", err)
	}
	if active, _ := f.DomainIsActive("web"); !active {
		t.Errorf("the guest was killed without a marker")
	}
}

// The replay waits out the quarantine, then records operator-stop through
// the ordinary stop record and removes the marker; a marker whose VM is
// gone, or is another incarnation, is removed with nothing recorded.
//
// Red on 884306b75: does not compile (no replay).
//
// Mutation, the replay (persistVMState skipped): the row stays running: red.
func TestReplayOperatorStopMarkers(t *testing.T) {
	s, _ := qsServer(t)
	ctx := adminCtx()
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatal(err)
	}
	var pending, corrupt int
	s.SetOperatorStopMarkerObserver(func(p, c int) { pending, corrupt = p, c })
	s.ReplayOperatorStopMarkers(ctx)
	if row := qsRow(t, s); row.State != "running" || pending != 1 || corrupt != 0 {
		t.Errorf("replay under quarantine: row %s, pending %d corrupt %d; want running, 1, 0", row.State, pending, corrupt)
	}
	s.db.SetWriteQuarantine(nil)
	s.ReplayOperatorStopMarkers(ctx)
	if row := qsRow(t, s); row.State != "stopped" || row.StateDetail != "operator-stop" {
		t.Errorf("after the lift: row %s/%q, want stopped/operator-stop", row.State, row.StateDetail)
	}
	if _, ok, _ := health.ReadOperatorStopMarker(s.dataDir, "web"); ok || pending != 0 {
		t.Errorf("after the lift: marker kept=%v pending=%d", ok, pending)
	}

	// Stale markers: another incarnation of web, and a VM with no row.
	for _, m := range []health.OperatorStopMarker{
		{VM: "web", Host: s.hostName, Incarnation: "1999-01-01T00:00:00Z"},
		{VM: "gone", Host: s.hostName, Incarnation: "1999-01-01T00:00:00Z"},
	} {
		if err := health.WriteOperatorStopMarker(s.dataDir, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpdateVMState(context.Background(), s.db, "web", "stopped", "out-of-band"); err != nil {
		t.Fatal(err)
	}
	s.ReplayOperatorStopMarkers(ctx)
	if names, _ := health.ListOperatorStopMarkers(s.dataDir); len(names) != 0 {
		t.Errorf("stale markers kept: %v", names)
	}
	if row := qsRow(t, s); row.StateDetail != "out-of-band" {
		t.Errorf("a stale marker was recorded over another incarnation: %s/%q", row.State, row.StateDetail)
	}
}

// `lv start` of a VM a marker holds: refused under quarantine; out of it the
// stop is recorded first and the start goes on. A corrupt marker refuses it
// whatever the quarantine.
//
// Red on 884306b75: does not compile.
func TestStartVM_HeldByOperatorStopMarker(t *testing.T) {
	s, f := qsServer(t)
	ctx := adminCtx()
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatal(err)
	}
	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still in write quarantine") {
		t.Errorf("StartVM under quarantine: %v, want FailedPrecondition", err)
	}
	if active, _ := f.DomainIsActive("web"); active {
		t.Fatalf("web was started under quarantine with its marker")
	}
	s.db.SetWriteQuarantine(nil)
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM after the lift: %v", err)
	}
	if active, _ := f.DomainIsActive("web"); !active {
		t.Errorf("web not started after the lift")
	}
	if _, ok, _ := health.ReadOperatorStopMarker(s.dataDir, "web"); ok {
		t.Errorf("the marker outlived the recorded stop")
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "web", 100, "")
	recorded := false
	for _, e := range evs {
		recorded = recorded || (e.Type == "vm.stopped" && strings.Contains(e.Detail, "write quarantine"))
	}
	if !recorded {
		t.Errorf("the start did not record the forced stop first")
	}

	// A corrupt marker refuses the start, quarantine or not.
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(health.OperatorStopMarkerDir(s.dataDir), "web.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.StartVM(ctx, &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("StartVM with a corrupt marker: %v", err)
	}
	// The recorded stop is its remedy.
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("a recorded stop left the corrupt marker: %v", err)
	}
}

// qsForceStopped is qsServer with web force-stopped under write quarantine,
// the quarantine still holding.
func qsForceStopped(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, f := qsServer(t)
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM --force under quarantine: %v", err)
	}
	return s, f
}

func qsMarked(t *testing.T, s *Server) bool {
	t.Helper()
	_, ok, err := health.ReadOperatorStopMarker(s.dataDir, "web")
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	return ok
}

// RestartVM's start, like the drain's and an update's restart, goes through
// startVMLocked, whose gate is the only one on those paths: a VM its marker
// holds is not started by a restart.
//
// Mutation: the gate dropped from startVMLockedWithin — web boots: red.
func TestRestartVM_HeldByOperatorStopMarker(t *testing.T) {
	s, f := qsForceStopped(t)
	if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "web"}); err == nil || !strings.Contains(err.Error(), "lv stop --force") {
		t.Errorf("RestartVM of a marked VM under quarantine: %v, want refused naming the forced stop", err)
	}
	if active, _ := f.DomainIsActive("web"); active {
		t.Errorf("a restart started a VM its marker holds")
	}
}

// A destroy that fails while the guest still runs stopped nothing: the
// marker goes again, so it does not hold a guest nobody stopped.
//
// Mutation: the marker kept on a failed destroy — red.
func TestStopVM_QuarantinedForceDestroyFailsRemovesMarker(t *testing.T) {
	s, f := qsServer(t)
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	f.FailDestroyDomain = func(string) error { return errors.New("libvirt: destroy refused") }
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); status.Code(err) != codes.Internal {
		t.Errorf("StopVM --force, destroy failing: %v, want Internal", err)
	}
	if active, _ := f.DomainIsActive("web"); !active {
		t.Fatalf("setup: the guest stopped")
	}
	if qsMarked(t, s) {
		t.Errorf("a marker is left for a guest that was not stopped")
	}
}

// A guest started again since the forced stop (by something that does not
// read the marker) is never recorded stopped: the replay drops the marker
// and records the skip.
//
// Mutation: the "guest runs again" branch dropped — the row is written
// stopped over a running guest: red.
func TestReplayOperatorStopMarkers_GuestRunsAgain(t *testing.T) {
	s, f := qsForceStopped(t)
	s.db.SetWriteQuarantine(nil)
	if err := f.StartDomain("web"); err != nil {
		t.Fatal(err)
	}
	s.ReplayOperatorStopMarkers(adminCtx())
	if row := qsRow(t, s); row.State != "running" {
		t.Errorf("row %s/%q, want running: a stop recorded over a running guest", row.State, row.StateDetail)
	}
	if qsMarked(t, s) {
		t.Errorf("the marker of a guest running again is kept")
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "web", 100, "")
	skipped := false
	for _, e := range evs {
		skipped = skipped || e.Type == "vm.stop.replay_skipped"
	}
	if !skipped {
		t.Errorf("no vm.stop.replay_skipped event")
	}
}

// A row that names another host (same incarnation, same epoch) is not this
// host's to record: the marker is dropped and the row left as it is.
//
// Mutation: the "row on another host" branch dropped — the guarded write
// refuses, the marker is kept for ever: red.
func TestReplayOperatorStopMarkers_RowOnAnotherHost(t *testing.T) {
	s, _ := qsForceStopped(t)
	s.db.SetWriteQuarantine(nil)
	if err := corrosion.UpdateVMHost(context.Background(), s.db, "web", "other-host", "running"); err != nil {
		t.Fatal(err)
	}
	s.ReplayOperatorStopMarkers(adminCtx())
	if row := qsRow(t, s); row.HostName != "other-host" || row.State != "running" {
		t.Errorf("row %s %s/%q, want left running on other-host", row.HostName, row.State, row.StateDetail)
	}
	if qsMarked(t, s) {
		t.Errorf("the marker of a VM on another host is kept")
	}
}

// B1: an ownership that left this host and came back (owner epoch +2,
// same created_at) is a later one. The marker does not hold it and is
// dropped; the stop is not recorded over it, running or pending.
//
// Red on 195477326: running — the replay records stopped/operator-stop over
// the returned VM; pending — the marker is kept for ever.
func TestReplayOperatorStopMarkers_LaterOwnershipIsNotRecordedOver(t *testing.T) {
	for _, back := range []string{"running", "pending"} {
		t.Run(back, func(t *testing.T) {
			s, _ := qsForceStopped(t)
			s.db.SetWriteQuarantine(nil)
			ctx := context.Background()
			row := qsRow(t, s)
			if err := corrosion.TransferVMOwner(ctx, s.db, "web", "other-host", "running", row.OwnerEpoch); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.TransferVMOwner(ctx, s.db, "web", s.hostName, back, row.OwnerEpoch+1); err != nil {
				t.Fatal(err)
			}
			now := qsRow(t, s)
			if why, _ := health.OperatorStopHold(s.dataDir, s.hostName, now); why != "" {
				t.Errorf("the marker holds a later ownership: %s", why)
			}
			s.ReplayOperatorStopMarkers(adminCtx())
			if after := qsRow(t, s); after.State != back || after.StateDetail == "operator-stop" {
				t.Errorf("row %s/%q, want %s: an earlier ownership's stop recorded over it", after.State, after.StateDetail, back)
			}
			if qsMarked(t, s) {
				t.Errorf("the marker of an earlier ownership is kept")
			}
		})
	}
}

// A marker of the same ownership over a row being started (pending) is
// kept, and `lv start` says how to clear it rather than "retry" for ever.
//
// Red on 195477326: Unavailable "retry lv start".
func TestStartVM_HeldRowStateSaysRecordTheStop(t *testing.T) {
	s, _ := qsForceStopped(t)
	s.db.SetWriteQuarantine(nil)
	if err := corrosion.UpdateVMState(context.Background(), s.db, "web", "pending", ""); err != nil {
		t.Fatal(err)
	}
	_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv stop web") {
		t.Errorf("StartVM over a held pending row: %v, want FailedPrecondition naming lv stop web", err)
	}
}

// `lv start` on a host in write quarantine is refused before anything runs:
// the start could not be recorded.
//
// Red on 195477326: the domain is started, unrecorded.
func TestStartVM_RefusedUnderWriteQuarantine(t *testing.T) {
	s, f := qsServer(t)
	if err := f.DestroyDomain("web"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMState(context.Background(), s.db, "web", "stopped", "operator-stop"); err != nil {
		t.Fatal(err)
	}
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	_, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot record a start") ||
		!strings.Contains(err.Error(), "reseed") {
		t.Errorf("StartVM under write quarantine: %v, want FailedPrecondition with the remedy", err)
	}
	if active, _ := f.DomainIsActive("web"); active {
		t.Errorf("a start under write quarantine ran the guest")
	}
	s.db.SetWriteQuarantine(nil)
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM once the quarantine lifted: %v", err)
	}
}

// B2: a cutover's runtime handoff starts the VM with StartDomain outside the
// start primitive; a forced stop's marker is the operator's stop there too.
//
// Red on 195477326: x boots.
func TestFinishVMReplaceRuntime_HonoursOperatorStopMarker(t *testing.T) {
	s, fake := provableCreateServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "x", HostName: s.hostName, State: "running",
		CPUActual: 1, MemActual: 512, Spec: `{"name":"x","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	if err := health.WriteOperatorStopMarker(s.dataDir, health.OperatorStopMarker{
		VM: "x", Host: s.hostName, Incarnation: corrosion.IncarnationOf(vm.CreatedAt), OwnerEpoch: vm.OwnerEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	dom := "<domain type='kvm'><name>x-next</name><uuid>uuid-x</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices></devices></domain>"
	cl := corrosion.VMReplaceCleanup{OperationID: "op-x", AcceptedState: "running",
		Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-x"},
		Manifest: corrosion.VMReplaceManifest{
			HostName: s.hostName, ReplacedVM: "x", Replacement: "x-next",
			ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-x",
		}}
	if err := s.finishVMReplaceRuntime(adminCtx(), cl); err != nil {
		t.Errorf("handoff of a marked VM: %v, want done with the VM down", err)
	}
	if st, _ := fake.RawState("x"); st == libvirtfake.StateRunning {
		t.Fatal("the handoff started a VM its operator force-stopped")
	}
}

// The owner-epoch backfill waits only for a pending marker at owner epoch 0:
// the backfill graduates only epoch 0, so a marker at a later epoch cannot
// be moved by it and must not stop it for every VM on the host.
//
// Mutation: report any pending marker (pending > 0) — red.
func TestReplayOperatorStopMarkers_ReportsOnlyEpochZeroPending(t *testing.T) {
	s := testServerWithLocks(t)
	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	put := func(epoch int64) {
		if err := health.WriteOperatorStopMarker(s.dataDir, health.OperatorStopMarker{
			VM: "web", Host: s.hostName, Incarnation: "i", OwnerEpoch: epoch}); err != nil {
			t.Fatal(err)
		}
	}
	put(2)
	if s.ReplayOperatorStopMarkers(adminCtx()) {
		t.Error("a pending marker at owner epoch 2 holds the backfill")
	}
	put(0)
	if !s.ReplayOperatorStopMarkers(adminCtx()) {
		t.Error("a pending marker at owner epoch 0 does not hold the backfill")
	}
}
