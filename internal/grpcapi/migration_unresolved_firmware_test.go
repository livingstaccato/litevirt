package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A Secure Boot / vTPM VM recorded migrating on a source that lost power,
// followed from failover's hold through each host's return to one running
// copy. Each step a hold's condition names is the one these tests take, and
// each ending resolves vm.migration_unresolved.

// fwFailedSource is os1's move from src-host to dst-host, its source dead
// mid-move: the source's marker in migrating (or, for window, still
// prepared with the row already migrating), the guest landed on dst-host or
// not, the source's domain shut off by the power loss (reason unknown).
// dstDown makes dst-host unanswerable to everyone: failover's asks, and the
// source's calls.
type fwFailedSource struct {
	*fwlRig
	dstDown atomic.Bool
	window  bool
}

func newFwFailedSource(t *testing.T, window, landed bool) *fwFailedSource {
	t.Helper()
	f := &fwFailedSource{fwlRig: newFwdRig(t, fwlOpts{}), window: window}
	r := f.fwlRig
	if window {
		r.crashAt(fwmig.PhasePrepared)
		if err := corrosion.UpdateVMState(context.Background(), r.src.db, fwlVM, "migrating", migratingDetailPrefix+"dst-host"); err != nil {
			t.Fatal(err)
		}
	} else {
		r.crashAt(fwmig.PhaseMigrating)
		if landed {
			r.land()
		}
	}
	r.srcFake.SetState(fwlVM, libvirtfake.StateShutdown)
	r.srcFake.SetStateReason(fwlVM, "unknown")
	unreach := status.Error(codes.Unavailable, "connection refused")
	r.peerC.dialErr = func() error {
		if f.dstDown.Load() {
			return unreach
		}
		return nil
	}
	withMigratingInventory(t, func(ctx context.Context, host string) (runtimeInventory, error) {
		if f.dstDown.Load() {
			return runtimeInventory{}, errors.New("connection refused")
		}
		return r.dst.collectRuntimeInventory(ctx), nil
	})
	old := migratingFirmwareHook
	migratingFirmwareHook = func(ctx context.Context, _ *Server, host, vm string) (*pb.FirmwareMoveHostRecords, error) {
		if f.dstDown.Load() {
			return nil, unreach
		}
		return r.dst.localFirmwareMoveRecords(ctx, vm), nil
	}
	t.Cleanup(func() { migratingFirmwareHook = old })
	if row := r.row(); row.State != "migrating" || row.HostName != "src-host" {
		t.Fatalf("fixture: row %s on %s, want migrating on src-host", row.State, row.HostName)
	}
	return f
}

// settle is failover's decision while src-host is down.
func (f *fwFailedSource) settle() failover.MigratingDecision {
	return f.src.SettleFailedSourceMigrations(context.Background(), "src-host", []corrosion.VMRecord{*f.row()}, time.Time{})[fwlVM]
}

// condition is vm.migration_unresolved's detail, and whether it is open.
func (f *fwFailedSource) condition() (string, bool) {
	return unresolvedDetail(f.t, f.src, fwlVM)
}

// requireNames: the condition is open and its detail names each of want.
func (f *fwFailedSource) requireNames(want, notWant []string) string {
	f.t.Helper()
	detail, open := f.condition()
	if !open {
		f.t.Fatal("vm.migration_unresolved is not open")
	}
	for _, w := range want {
		if !strings.Contains(detail, w) {
			f.t.Errorf("vm.migration_unresolved does not name %q: %s", w, detail)
		}
	}
	for _, w := range notWant {
		if strings.Contains(detail, w) {
			f.t.Errorf("vm.migration_unresolved names %q, which is not true here: %s", w, detail)
		}
	}
	return detail
}

// runningOn names the hosts whose domain of os1 runs.
func (f *fwFailedSource) runningOn() []string {
	var on []string
	for _, h := range []struct {
		name string
		f    *libvirtfake.Fake
	}{{"src-host", f.srcFake}, {"dst-host", f.dstFake}} {
		if st, ok := h.f.RawState(fwlVM); ok && st == libvirtfake.StateRunning {
			on = append(on, h.name)
		}
	}
	return on
}

// requireNotStartable: no copy of os1 runs, and its start is refused.
func (f *fwFailedSource) requireNotStartable(why string) {
	f.t.Helper()
	if on := f.runningOn(); len(on) != 0 {
		f.t.Fatalf("%s: os1 runs on %v", why, on)
	}
	if _, err := f.src.StartVM(adminCtx(), &pb.StartVMRequest{Name: fwlVM}); err == nil {
		f.t.Fatalf("%s: lv start os1 was not refused", why)
	}
}

// startOnSource is `lv start os1`, which must leave os1 running on src-host
// alone.
func (f *fwFailedSource) startOnSource() {
	f.t.Helper()
	if _, err := f.src.StartVM(adminCtx(), &pb.StartVMRequest{Name: fwlVM}); err != nil {
		f.t.Fatalf("lv start os1: %v", err)
	}
	f.requireOneCopyOn("src-host", "after lv start os1")
}

// requireOneCopyOn: os1 runs on host alone, its row there and running.
func (f *fwFailedSource) requireOneCopyOn(host, why string) {
	f.t.Helper()
	if on := f.runningOn(); len(on) != 1 || on[0] != host {
		f.t.Fatalf("%s: os1 runs on %v, want %s alone", why, on, host)
	}
	if row := f.row(); row.HostName != host || row.State != "running" {
		f.t.Fatalf("%s: row %s on %s, want running on %s", why, row.State, row.HostName, host)
	}
}

// requireResolved: vm.migration_unresolved is resolved once each host ran
// its minute's pass.
func (f *fwFailedSource) requireResolved(why string) {
	f.t.Helper()
	f.src.FirmwareMoveRecoveryOnce(context.Background())
	f.dst.FirmwareMoveRecoveryOnce(context.Background())
	if detail, open := f.condition(); open {
		f.t.Fatalf("%s: vm.migration_unresolved is still open with one copy running: %s", why, detail)
	}
}

// requireParked: the source's marker is parked p, from from.
func (f *fwFailedSource) requireParked(p, from fwmig.Phase) {
	f.t.Helper()
	m, ok := f.marker()
	if !ok || m.Phase != p || m.ParkedFrom != from {
		f.t.Fatalf("marker %v %s (from %s), want parked %s from %s", ok, m.Phase, m.ParkedFrom, p, from)
	}
}

// acceptSourceAndStart: dst-host answered again holding no copy, and the
// source's next pass parks the move source_state_suspect, the doctor's
// --accept-source --acknowledge-rollback returns os1 to src-host stopped,
// and `lv start os1` runs it there alone.
func (f *fwFailedSource) acceptSourceAndStart() {
	f.t.Helper()
	f.requireParked(fwmig.PhaseSourceStateSuspect, fwmig.PhaseCutover)
	if _, err := f.doctor(actAcceptSource, withAck); err != nil {
		f.t.Fatalf("lv doctor firmware-move os1 --accept-source --acknowledge-rollback: %v", err)
	}
	if row := f.row(); row.HostName != "src-host" || row.State != "stopped" {
		f.t.Fatalf("row %s on %s after --accept-source, want stopped on src-host", row.State, row.HostName)
	}
	f.startOnSource()
}

// TestFailedFirmwareSource_TargetDown: failover's hold of os1 while neither
// host answers names no `lv` command, and says what each host's return does;
// each is followed here:
//
//   - window (the source's marker still prepared): src-host back, the move
//     parks target_unreachable from prepared; `lv host fence-confirm
//     dst-host` resolves it on the next pass, and `lv start os1` runs it.
//   - migrating: src-host back, the move parks target_unreachable from
//     cutover; nothing lv offers starts it (the doctor's --accept-source and
//     lv start refuse), and a fence of dst-host does not resolve it. dst-host
//     answering again settles it: holding the guest, the move finishes there;
//     holding none, --accept-source --acknowledge-rollback then lv start.
//
// Every ending leaves one running copy and resolves the condition, which
// stays open while the move is parked.
//
// Mutations: name the fence as the migrating case's remedy (round-3 text) —
// red; resolve the condition while the source's marker is parked
// (migrationSettled without the marker check) — the window arm, red; drop
// the minute pass's sweep — the arm that finishes on dst-host, red; the
// round-3 doctor refusal ("resolved by fence") — red.
func TestFailedFirmwareSource_TargetDown(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name           string
		window, landed bool
	}{
		{"window", true, false},
		{"migrating/target_holds_the_guest", false, true},
		{"migrating/target_holds_none", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFwFailedSource(t, c.window, c.landed)
			f.dstDown.Store(true)
			if d := f.settle(); d.Verdict != failover.MigratingHold {
				t.Fatalf("decision %+v, want a hold", d)
			}
			f.requireNames([]string{"cannot be asked", "No `lv` command starts it", "both down", "none handles this yet",
				"Bring dst-host back", "Or bring src-host back",
				"`lv doctor firmware-move os1 --accept-source --acknowledge-rollback` then `lv start os1`",
				"from prepared, `lv host fence-confirm dst-host`",
				"from cutover, no `lv` command handles it yet and a fence of dst-host does not resolve it"},
				[]string{"--adopt-target-copy", "goes on with"})

			// src-host comes back; dst-host still does not answer.
			f.restart()
			from := fwmig.PhaseCutover
			if c.window {
				from = fwmig.PhasePrepared
			}
			f.requireParked(fwmig.PhaseTargetUnreachable, from)
			f.requireNotStartable("parked, dst-host down")
			f.src.FirmwareMoveRecoveryOnce(ctx)
			if _, open := f.condition(); !open {
				t.Fatal("vm.migration_unresolved was resolved while the move is parked and nothing runs")
			}

			if c.window {
				// dst-host powered off, and confirmed so.
				f.fenceTarget()
				f.src.FirmwareMoveRecoveryOnce(ctx)
				if m, ok := f.marker(); ok {
					t.Fatalf("the fence of dst-host did not resolve a move parked from prepared: %s from %s", m.Phase, m.ParkedFrom)
				}
				f.startOnSource()
				f.requireResolved("window, fenced, started")
				return
			}

			// Nothing lv offers settles it while dst-host is down.
			_, err := f.doctor(actAcceptSource, withAck)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "no `lv` command handles it yet") ||
				strings.Contains(err.Error(), "resolved by fence") {
				t.Fatalf("--accept-source: %v, want a refusal saying no `lv` command handles it yet", err)
			}
			if _, err := f.doctor(actAdopt); err == nil {
				t.Fatal("--adopt-target-copy was not refused with dst-host down")
			}
			f.requireNotStartable("doctor refused")

			// dst-host answers again.
			f.dstDown.Store(false)
			f.src.FirmwareMoveRecoveryOnce(ctx)
			if c.landed {
				if _, ok := f.marker(); ok {
					t.Fatal("dst-host holds the guest and answers, and the move did not finish")
				}
				f.requireOneCopyOn("dst-host", "the move finished on dst-host")
				f.requireResolved("finished on dst-host")
				return
			}
			f.acceptSourceAndStart()
			f.requireResolved("accepted the source's copy and started")
		})
	}
}

// TestFailedFirmwareSource_TargetBackWithNoCopy: dst-host answers again
// while src-host is down, holding no domain of os1 (its incoming copy died
// with it). Failover goes on and skips the firmware VM, and the condition no
// longer says dst-host cannot be asked: it says no copy is there, that no lv
// command starts os1 while src-host is down, and what src-host's return then
// takes, which is followed here to one copy on src-host.
//
// Mutations: recover without raising (the round-3 firmware recoverVM) — the
// condition keeps "cannot be asked", red.
func TestFailedFirmwareSource_TargetBackWithNoCopy(t *testing.T) {
	for _, window := range []bool{false, true} {
		t.Run(map[bool]string{false: "migrating", true: "window"}[window], func(t *testing.T) {
			f := newFwFailedSource(t, window, false)
			f.dstDown.Store(true)
			if d := f.settle(); d.Verdict != failover.MigratingHold {
				t.Fatalf("decision %+v, want a hold", d)
			}
			f.dstDown.Store(false)
			if d := f.settle(); d.Verdict != failover.MigratingRecover {
				t.Fatalf("decision %+v once dst-host answers with no copy, want the recovery to go on (and skip it)", d)
			}
			f.requireNames([]string{"holds no domain of it", "only src-host's firmware state is left",
				"No `lv` command starts it while src-host is down", "Power src-host back on",
				"`lv doctor firmware-move os1 --accept-source --acknowledge-rollback` then `lv start os1`"},
				[]string{"cannot be asked", "next poll names"})
			if row := f.row(); row.HostName != "src-host" || row.State != "migrating" {
				t.Fatalf("row %s on %s, want it left migrating on src-host", row.State, row.HostName)
			}
			if on := f.runningOn(); len(on) != 0 {
				t.Fatalf("os1 runs on %v", on)
			}

			// src-host powered back on, dst-host answering.
			f.restart()
			if window {
				if m, ok := f.marker(); ok {
					t.Fatalf("a move that had not reached the migration was not undone: %s from %s", m.Phase, m.ParkedFrom)
				}
				f.startOnSource()
				f.requireResolved("window, undone, started")
				return
			}
			f.acceptSourceAndStart()
			f.requireResolved("accepted the source's copy and started")
		})
	}
}

// TestFailedFirmwareSource_TargetProvenOff: dst-host is powered off and
// confirmed so while src-host is down. Failover goes on and skips the
// firmware VM, and the condition says what src-host's return takes, which is
// followed here: from prepared the fence resolves the move and lv start runs
// it; from cutover nothing lv offers settles it and the fence does not, and
// only dst-host answering again does.
//
// Mutations: the round-3 text (no `lv` command while both are down, fence
// resolves) — red.
func TestFailedFirmwareSource_TargetProvenOff(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name           string
		window, landed bool
	}{
		{"window", true, false},
		{"migrating/target_holds_the_guest", false, true},
		{"migrating/target_holds_none", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFwFailedSource(t, c.window, c.landed)
			f.dstDown.Store(true)
			f.fenceTarget()
			if d := f.settle(); d.Verdict != failover.MigratingRecover {
				t.Fatalf("decision %+v with dst-host proven off, want the recovery to go on (and skip it)", d)
			}
			f.requireNames([]string{"proven powered off", "No `lv` command starts it while src-host is down", "Power src-host back on",
				"From prepared, the fence of dst-host resolves it", "From cutover, no `lv` command handles it yet and the fence does not resolve it",
				"the move commits there and os1 runs on dst-host",
				"`lv doctor firmware-move os1 --accept-source --acknowledge-rollback` then `lv start os1`"},
				[]string{"cannot be asked"})

			f.restart()
			f.src.FirmwareMoveRecoveryOnce(ctx)
			if c.window {
				if m, ok := f.marker(); ok {
					t.Fatalf("the fence of dst-host did not resolve a move parked from prepared: %s from %s", m.Phase, m.ParkedFrom)
				}
				f.startOnSource()
				f.requireResolved("window, fenced, started")
				return
			}
			f.requireParked(fwmig.PhaseTargetUnreachable, fwmig.PhaseCutover)
			f.requireNotStartable("parked from cutover, dst-host fenced")
			if _, err := f.doctor(actAcceptSource, withAck); err == nil || !strings.Contains(err.Error(), "no `lv` command handles it yet") {
				t.Fatalf("--accept-source: %v, want a refusal saying no `lv` command handles it yet", err)
			}

			// dst-host answers again, still fenced.
			f.dstDown.Store(false)
			f.src.FirmwareMoveRecoveryOnce(ctx)
			if c.landed {
				// The move commits there; the source keeps its state while
				// its cleanup refuses a fenced target.
				if m, ok := f.marker(); ok && m.Phase != fwmig.PhaseCleaning {
					t.Fatalf("dst-host holds the guest and answers, and the move did not commit: %s from %s", m.Phase, m.ParkedFrom)
				}
				f.requireOneCopyOn("dst-host", "the move committed on dst-host")
				f.requireResolved("committed on dst-host")
				return
			}
			f.acceptSourceAndStart()
			f.requireResolved("accepted the source's copy and started")
		})
	}
}
