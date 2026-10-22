package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// withMigratingInventory answers failover's ask of a migration target with
// ask, for the test.
func withMigratingInventory(t *testing.T, ask func(ctx context.Context, host string) (runtimeInventory, error)) {
	t.Helper()
	old := migratingInventoryHook
	migratingInventoryHook = func(ctx context.Context, _ *Server, host string) (runtimeInventory, error) { return ask(ctx, host) }
	t.Cleanup(func() { migratingInventoryHook = old })
}

// unresolvedDetail is vm's vm.migration_unresolved detail, and whether it is open.
func unresolvedDetail(t *testing.T, s *Server, vm string) (string, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	if err != nil {
		t.Fatal(err)
	}
	var ev migrationUnresolvedEvidence
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	return ev.Detail, ok && row.Lifecycle != corrosion.ConditionResolved
}

// A Secure Boot / vTPM VM recorded migrating on a failed source is never
// re-pointed by failover, whatever its target reports: its move is settled by
// its firmware records. The hold names the step that settles it, by what the
// target holds, and each arm takes that step:
//
//   - unreachable: no `lv` command starts it while the source and the
//     target are both down; bringing one back is the remedy
//     (TestFailedFirmwareSource_* follow each return). A target proven off
//     then lets the recovery go on (where failover skips a firmware VM), and
//     the condition stays, saying what the source's return then takes;
//   - paused: fence-confirm of the source, then --adopt-target-copy: the VM
//     runs on the target alone, its row there, and the condition is
//     resolved;
//   - running or shut off: no `lv` command; `virsh suspend` or
//     `virsh start --paused` on the target pauses it, and the paused arm's
//     steps follow;
//   - any other active state (pm-suspended, crashed, shutting down): no
//     lv command and no known safe host step — contact the maintainers.
//
// Mutations: re-point a firmware VM like any other (drop the firmware
// branch) — the running arm's row moves to dst-host, red; give every held
// state the paused advice — the running and shut-off arms, red; give the
// unreachable target the paused advice — red; resolve the condition when a
// firmware VM is recovered — the unreachable arm, red; name `virsh start`
// for every active state — the pmsuspended arm, red; leave the condition
// open once the doctor settled the row (no resolution after the doctor's
// action) — the paused, running and shut-off arms, red.
func TestSettleFailedSourceMigrations_FirmwareVMIsHeldForTheDoctor(t *testing.T) {
	ctx := context.Background()
	settle := func(t *testing.T, r *fwlRig) failover.MigratingDecision {
		t.Helper()
		return r.src.SettleFailedSourceMigrations(ctx, "src-host", []corrosion.VMRecord{*r.row()}, time.Time{})[fwlVM]
	}
	held := func(t *testing.T, r *fwlRig, d failover.MigratingDecision, want, notWant []string) {
		t.Helper()
		if d.Verdict != failover.MigratingHold {
			t.Fatalf("decision %+v, want a hold", d)
		}
		if row := r.row(); row.HostName != "src-host" || row.State != "migrating" {
			t.Fatalf("the firmware VM's row was moved to %s %s", row.HostName, row.State)
		}
		detail, open := unresolvedDetail(t, r.src, fwlVM)
		if !open {
			t.Fatal("held with no vm.migration_unresolved")
		}
		for _, w := range want {
			if !strings.Contains(detail, w) {
				t.Errorf("the hold does not name %q: %s", w, detail)
			}
		}
		for _, w := range notWant {
			if strings.Contains(detail, w) {
				t.Errorf("the hold names %q, which does not settle this state: %s", w, detail)
			}
		}
	}
	rig := func(t *testing.T, st libvirtfake.State) *fwlRig {
		r, _ := lostWithOwed(t, false, false, st)
		withMigratingInventory(t, func(ctx context.Context, host string) (runtimeInventory, error) {
			return r.dst.collectRuntimeInventory(ctx), nil
		})
		old := migratingFirmwareHook
		migratingFirmwareHook = func(ctx context.Context, _ *Server, host, vm string) (*pb.FirmwareMoveHostRecords, error) {
			return r.dst.localFirmwareMoveRecords(ctx, vm), nil
		}
		t.Cleanup(func() { migratingFirmwareHook = old })
		if row := r.row(); row.State != "migrating" || row.HostName != "src-host" {
			t.Fatalf("fixture: row %s on %s, want migrating on src-host", row.State, row.HostName)
		}
		return r
	}
	// adoptPaused takes the paused arm's steps on a target that holds the
	// guest paused: the source confirmed off, then the doctor's adopt. The
	// VM ends running on dst-host alone, its row there.
	adoptPaused := func(t *testing.T, r *fwlRig) {
		t.Helper()
		held(t, r, settle(t, r), []string{"lv host fence-confirm src-host", "lv doctor firmware-move " + fwlVM + " --adopt-target-copy"},
			[]string{"No `lv` command"})
		// `lv host fence-confirm src-host`, as it records it.
		if err := corrosion.RecordFenceWithState(ctx, r.src.db,
			corrosion.FenceLogRecord{ID: "fc-src", HostName: "src-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
			t.Fatal(err)
		}
		if d := settle(t, r); d.Verdict != failover.MigratingHold || strings.Contains(d.Detail, "fence-confirm") ||
			!strings.Contains(d.Detail, "--adopt-target-copy") {
			t.Fatalf("decision %+v, want a hold naming the doctor alone once the source is proven off", d)
		}
		if _, err := r.doctor(actAdopt); err != nil {
			t.Fatalf("lv doctor firmware-move %s --adopt-target-copy: %v", fwlVM, err)
		}
		if row := r.row(); row.HostName != "dst-host" || row.State != "running" {
			t.Fatalf("row %s %s after the doctor, want running on dst-host", row.HostName, row.State)
		}
		var running []string
		for name, f := range map[string]*libvirtfake.Fake{"src-host": r.srcFake, "dst-host": r.dstFake} {
			if st, ok := f.RawState(fwlVM); ok && st == libvirtfake.StateRunning {
				running = append(running, name)
			}
		}
		if len(running) != 1 || running[0] != "dst-host" {
			t.Fatalf("the VM runs on %v, want dst-host alone", running)
		}
		if _, ok, _ := fwmig.New(r.dst.dataDir).GetHold(fwlVM); ok {
			t.Error("the target's hold is still there after the adoption")
		}
		if detail, open := unresolvedDetail(t, r.src, fwlVM); open {
			t.Fatalf("vm.migration_unresolved is still open after the adoption left one copy, on dst-host: %s", detail)
		}
	}

	t.Run("unreachable/no_lv_command_while_both_are_down", func(t *testing.T) {
		r := rig(t, "")
		withMigratingInventory(t, func(context.Context, string) (runtimeInventory, error) {
			return runtimeInventory{}, errors.New("connection refused")
		})
		want := []string{"cannot be asked", "No `lv` command starts it", "both down", "Bring dst-host back", "Or bring src-host back",
			"lv host fence-confirm dst-host", "lv start " + fwlVM}
		held(t, r, settle(t, r), want, []string{"--adopt-target-copy", "goes on with"})
		// The target powered off, its guest with it, and confirmed so. The
		// recovery goes on — failover then skips a firmware VM, which
		// TestFleet_Failover_MigratingFirmwareRowWithBothHostsDownIsNotStarted
		// follows — and the condition stays, still saying what brings it back.
		_ = r.dstFake.DestroyDomain(fwlVM)
		if err := corrosion.RecordFenceWithState(ctx, r.src.db,
			corrosion.FenceLogRecord{ID: "fc-dst", HostName: "dst-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
			t.Fatal(err)
		}
		if d := settle(t, r); d.Verdict != failover.MigratingRecover {
			t.Fatalf("decision %+v once dst-host is proven off, want the recovery to go on", d)
		}
		if detail, open := unresolvedDetail(t, r.src, fwlVM); !open || !strings.Contains(detail, "proven powered off") ||
			!strings.Contains(detail, "No `lv` command starts it while src-host is down") {
			t.Fatalf("condition open %v, detail %q: it must stay, saying what brings the VM back", open, detail)
		}
	})
	t.Run("paused/fence_confirm_the_source_then_adopt", func(t *testing.T) {
		r := rig(t, "")
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
			t.Fatalf("fixture: target %s, want paused", st)
		}
		adoptPaused(t, r)
	})
	t.Run("running/no_lv_command_then_suspend", func(t *testing.T) {
		r := rig(t, libvirtfake.StateRunning)
		held(t, r, settle(t, r), []string{"No `lv` command", "virsh suspend " + fwlVM}, []string{"lv host fence-confirm"})
		r.dstFake.SetState(fwlVM, libvirtfake.StatePaused) // `virsh suspend` on dst-host
		adoptPaused(t, r)
	})
	t.Run("pmsuspended/no_known_step", func(t *testing.T) {
		r := rig(t, libvirtfake.StateRunning)
		migratingFirmwareHook = func(ctx context.Context, _ *Server, host, vm string) (*pb.FirmwareMoveHostRecords, error) {
			rec := r.dst.localFirmwareMoveRecords(ctx, vm)
			rec.Domain = &pb.TargetDomain{Present: true, State: "pmsuspended"}
			return rec, nil
		}
		held(t, r, settle(t, r), []string{"pmsuspended", "contact the litevirt maintainers"}, []string{"virsh start", "virsh suspend", "lv host fence-confirm"})
	})
	t.Run("shut_off/no_lv_command_then_start_paused", func(t *testing.T) {
		r := rig(t, libvirtfake.StateShutdown)
		held(t, r, settle(t, r), []string{"No `lv` command", "virsh start --paused " + fwlVM}, []string{"lv host fence-confirm"})
		r.dstFake.SetState(fwlVM, libvirtfake.StatePaused) // `virsh start --paused` on dst-host
		adoptPaused(t, r)
	})
}

// A target that answers with an incomplete inventory that does not list the
// VM may still run it: the VM is held, its condition naming the next poll
// and repair-owner.
//
// Mutation: an incomplete inventory recovers (RuntimeUnknown → recover) — red.
func TestSettleFailedSourceMigrations_IncompleteInventoryHolds(t *testing.T) {
	ctx := context.Background()
	withMigratingInventory(t, func(_ context.Context, host string) (runtimeInventory, error) {
		return runtimeInventory{Host: host, Complete: false}, nil
	})
	s := testServerWithLocks(t)
	vm := corrosion.VMRecord{Name: "vm-u", HostName: "src", State: "migrating", StateDetail: migratingDetailPrefix + "tgt"}
	d := s.SettleFailedSourceMigrations(ctx, "src", []corrosion.VMRecord{vm}, time.Time{})["vm-u"]
	if d.Verdict != failover.MigratingHold {
		t.Fatalf("decision %+v, want a hold: an incomplete inventory is no proof of absence", d)
	}
	detail, open := unresolvedDetail(t, s, "vm-u")
	if !open || !strings.Contains(detail, "incomplete inventory") || !strings.Contains(detail, "next poll") ||
		!strings.Contains(detail, "lv doctor repair-owner vm-u tgt") {
		t.Fatalf("condition open %v, detail %q; want it naming the incomplete inventory, the next poll and repair-owner", open, detail)
	}
}

// Failover asks each migration target once per pass, whatever the number of
// VMs held against it, at most migratingProbeConcurrency at a time, and gives
// up on what is left once migratingProbeBudget is spent: a target that does
// not answer holds its own VMs, and never the rest of the recovery for longer
// than the budget.
//
// Mutations: ask per VM (no per-target memo) — the call count per target is
// 3, red; drop the semaphore — the in-flight peak exceeds the bound, red;
// drop the pass's budget, or bound each ask by the caller's ctx and not the
// budget's — the second arm runs past it, red; ignore askBy — the third arm
// runs to the 5s budget, red.
func TestSettleFailedSourceMigrations_AsksEachTargetOnceWithinABudget(t *testing.T) {
	ctx := context.Background()
	setBounds := func(t *testing.T, timeout, budget time.Duration, conc int) {
		t.Helper()
		ot, ob, oc := migratingProbeTimeout, migratingProbeBudget, migratingProbeConcurrency
		migratingProbeTimeout, migratingProbeBudget, migratingProbeConcurrency = timeout, budget, conc
		t.Cleanup(func() { migratingProbeTimeout, migratingProbeBudget, migratingProbeConcurrency = ot, ob, oc })
	}
	vmsFor := func(targets ...string) []corrosion.VMRecord {
		var out []corrosion.VMRecord
		for _, tg := range targets {
			for i := 0; i < 3; i++ {
				out = append(out, corrosion.VMRecord{Name: fmt.Sprintf("%s-vm%d", tg, i), HostName: "src",
					State: "migrating", StateDetail: migratingDetailPrefix + tg})
			}
		}
		return out
	}
	// ask answers "fast-*" at once with a complete inventory holding none of
	// the VMs, and blocks any other target until its ask is cancelled.
	type probe struct {
		mu        sync.Mutex
		calls     map[string]int
		in, peak  atomic.Int32
		completed atomic.Int32
		// latest is the latest deadline any ask was given; first is when the
		// first ask began.
		latest, first time.Time
	}
	ask := func(p *probe) func(ctx context.Context, host string) (runtimeInventory, error) {
		return func(ctx context.Context, host string) (runtimeInventory, error) {
			p.mu.Lock()
			p.calls[host]++
			if p.first.IsZero() {
				p.first = time.Now()
			}
			if dl, ok := ctx.Deadline(); !ok {
				p.latest = time.Now().Add(time.Hour)
			} else if dl.After(p.latest) {
				p.latest = dl
			}
			p.mu.Unlock()
			n := p.in.Add(1)
			defer p.in.Add(-1)
			for {
				pk := p.peak.Load()
				if n <= pk || p.peak.CompareAndSwap(pk, n) {
					break
				}
			}
			if strings.HasPrefix(host, "fast-") {
				p.completed.Add(1)
				return runtimeInventory{Host: host, Complete: true}, nil
			}
			<-ctx.Done()
			return runtimeInventory{}, ctx.Err()
		}
	}

	t.Run("every_target_asked_once", func(t *testing.T) {
		setBounds(t, 100*time.Millisecond, 5*time.Second, 2)
		p := &probe{calls: map[string]int{}}
		withMigratingInventory(t, ask(p))
		s := testServerWithLocks(t)
		vms := vmsFor("fast-a", "fast-b", "dead-a", "dead-b", "dead-c", "dead-d")
		start := time.Now()
		got := s.SettleFailedSourceMigrations(ctx, "src", vms, time.Time{})
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("the pass took %s; 4 dead targets at 2 at a time and 100ms each should take ~200ms", el)
		}
		for host, n := range p.calls {
			if n != 1 {
				t.Errorf("%s was asked %d times, want once for its 3 VMs", host, n)
			}
		}
		if len(p.calls) != 6 {
			t.Errorf("asked %v, want each of the 6 targets", p.calls)
		}
		if pk := p.peak.Load(); pk > 2 {
			t.Errorf("%d asks in flight at once, want at most 2", pk)
		}
		for _, vm := range vms {
			d := got[vm.Name]
			want := failover.MigratingHold
			if strings.HasPrefix(vm.Name, "fast-") {
				want = failover.MigratingRecover
			}
			if d.Verdict != want {
				t.Errorf("%s: %+v, want verdict %d", vm.Name, d, want)
			}
		}
	})
	t.Run("the_budget_bounds_the_pass", func(t *testing.T) {
		setBounds(t, 200*time.Millisecond, 250*time.Millisecond, 1)
		p := &probe{calls: map[string]int{}}
		withMigratingInventory(t, ask(p))
		s := testServerWithLocks(t)
		vms := vmsFor("dead-a", "dead-b", "dead-c", "dead-d", "dead-e", "dead-f")
		start := time.Now()
		got := s.SettleFailedSourceMigrations(ctx, "src", vms, time.Time{})
		// Every ask ends by the budget, set before the first ask began, not
		// by its own timeout past it.
		if late := p.latest.Sub(p.first); late > 250*time.Millisecond {
			t.Fatalf("an ask was given until %s after the first ask began, past the pass's 250ms budget", late)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("the pass took %s against a 250ms budget (6 dead targets at 200ms each, 1 at a time)", el)
		}
		unasked := 0
		for _, vm := range vms {
			d := got[vm.Name]
			if d.Verdict != failover.MigratingHold {
				t.Errorf("%s: %+v, want a hold", vm.Name, d)
			}
			if strings.Contains(d.Detail, "not asked within") {
				unasked++
			}
		}
		if unasked == 0 {
			t.Error("every target was asked; the budget did not cut the pass short")
		}
	})
	t.Run("the_polls_deadline_bounds_the_pass", func(t *testing.T) {
		// The coordinator's one deadline for the poll, already mostly spent
		// by another held host: it, not this call's own budget, ends the asks.
		setBounds(t, 5*time.Second, 5*time.Second, 4)
		p := &probe{calls: map[string]int{}}
		withMigratingInventory(t, ask(p))
		s := testServerWithLocks(t)
		vms := vmsFor("dead-a", "dead-b")
		start := time.Now()
		got := s.SettleFailedSourceMigrations(ctx, "src", vms, start.Add(150*time.Millisecond))
		if late := p.latest.Sub(start); late > 150*time.Millisecond+50*time.Millisecond {
			t.Fatalf("an ask was given until %s after the pass began, past the poll's deadline 150ms out", late)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("the pass took %s against the poll's deadline 150ms out", el)
		}
		for _, vm := range vms {
			if d := got[vm.Name]; d.Verdict != failover.MigratingHold {
				t.Errorf("%s: %+v, want a hold", vm.Name, d)
			}
		}
	})
}
