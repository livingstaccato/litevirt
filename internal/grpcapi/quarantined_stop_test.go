package grpcapi

import (
	"context"
	"encoding/json"
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
