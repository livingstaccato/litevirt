// Fleet scenarios for a start of a VM while a move of it is under way, or
// after one left its row `migrating`: the start never makes a second copy.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// countOp is how many of log's events are op on domain.
func countOp(log []libvirtfake.Event, op, domain string) int {
	n := 0
	for _, e := range log {
		if e.Op == op && e.Domain == domain {
			n++
		}
	}
	return n
}

// `lv start` of a VM asked on its source while a cold move of it runs. In the
// copy (before the handoff) the start waits for the move on the VM's lock
// and is then refused, the VM being the target's. Between the handoff and
// the source's cleanup the row already names the target, so the start goes
// there. Either way the source's domain is never started and is gone at the
// end, and the guest runs on one host at most.
//
// Mutation: StartVM without the VM's lock — the start runs mid-move and the
// move fails on the active source domain, red.
func TestFleet_AStartDuringAColdMoveWaitsForItAndMakesNoSecondCopy(t *testing.T) {
	for _, window := range []string{"copy", "handoff"} {
		t.Run(window, func(t *testing.T) {
			sc := newColdStoppedScenario(t)
			startErr := make(chan error, 1)
			var once sync.Once
			midMove := func() {
				once.Do(func() {
					go func() {
						_, err := sc.c.SelfClient(sc.src).StartVM(context.Background(), &pb.StartVMRequest{Name: "os1"})
						startErr <- err
					}()
					// The start is given time to act before the move goes on.
					select {
					case err := <-startErr:
						startErr <- err
					case <-time.After(time.Second):
					}
				})
			}
			if window == "copy" {
				sc.dst.Virt.FailDefineDomain = func(string) error { midMove(); return nil }
			} else {
				sc.src.Server.SetColdMoveAfterHandoffForTest(func(string) { midMove() })
			}
			if err := sc.migrateCold(t); err != nil {
				t.Fatalf("migrate --cold with a start asked mid-move: %v", err)
			}
			var err error
			select {
			case err = <-startErr:
			case <-time.After(15 * time.Second):
				t.Fatal("the start asked mid-move never ended")
			}
			wantState := "running" // the start went to the target, which owns os1
			if window == "copy" {
				if status.Code(err) != codes.Aborted {
					t.Fatalf("start asked in the copy = %v; want Aborted, the VM having moved", err)
				}
				wantState = "stopped"
			} else if err != nil {
				t.Fatalf("start asked after the handoff = %v; want it started on the target", err)
			}
			if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != wantState {
				t.Fatalf("os1 = %s on %s; want %s on %s", vm.State, vm.HostName, wantState, sc.dst.Name)
			}
			if sc.src.Virt.DomainExists("os1") {
				t.Errorf("os1 is still defined on the source")
			}
			if countOp(sc.src.Virt.EventLog(), "start", "os1") != 0 {
				t.Errorf("os1 was started on the source")
			}
		})
	}
}

// leftMigrating is a 2-node cluster with "web" recorded migrating from node 0
// to node 1, as a daemon that died mid-move leaves it, with its domain
// defined and shut off on node 0.
func leftMigrating(t *testing.T) (*Cluster, *Node, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), src.DB, corrosion.VMRecord{
		Name: "web", HostName: src.Name, State: "migrating", StateDetail: "→ " + dst.Name,
		Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>web</name><uuid>33333333-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
		t.Fatalf("define web: %v", err)
	}
	return c, src, dst
}

// A VM whose row is left migrating may run on the move's target: `lv start`
// and `lv restart` on its source are refused, naming the move, and start
// nothing. `lv stop` still settles the row, resolving the VM's
// vm.migration_unresolved, after which it starts again.
//
// Mutations: no in-flight-move refusal in the start gates — the start boots
// web on the source, red. None in RestartVM — the restart boots it, red. The
// stop does not resolve the condition — red. The stop taken as allowed when
// the target cannot be asked — red.
func TestFleet_AVMLeftMigratingIsNotStartedOnItsSource(t *testing.T) {
	c, src, dst := leftMigrating(t)
	ctx := context.Background()
	cl := c.SelfClient(src)
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, src.DB, corrosion.HealthCondition{
		Evaluator: "drain", Code: "vm.migration_unresolved", SubjectKind: "vm", SubjectID: "web",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical, Hosts: []string{src.Name, dst.Name},
		Evidence: "{}", FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: src.Name,
	}); err != nil {
		t.Fatalf("raise vm.migration_unresolved: %v", err)
	}
	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "web"}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "migrating") {
		t.Fatalf("start of a VM left migrating = %v; want FailedPrecondition naming the move", err)
	}
	if _, err := cl.RestartVM(ctx, &pb.RestartVMRequest{Name: "web"}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "migrating") {
		t.Fatalf("restart of a VM left migrating = %v; want FailedPrecondition naming the move", err)
	}
	if n := countOp(src.Virt.EventLog(), "start", "web"); n != 0 {
		t.Fatalf("web was started %d time(s) on its source", n)
	}
	// The target is asked whether the guest runs there first: one that
	// cannot be asked refuses the stop.
	restore := dst.RefuseRPCs("GetRuntimeInventory")
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "web"}); status.Code(err) != codes.Unavailable ||
		!strings.Contains(err.Error(), dst.Name) {
		t.Fatalf("stop with the target not answering = %v; want Unavailable naming %s", err, dst.Name)
	}
	if row, _ := corrosion.GetVM(ctx, src.DB, "web"); row == nil || row.State != "migrating" {
		t.Fatalf("web after the refused stop = %+v; want still migrating", row)
	}
	restore()
	// The target has no domain of it: the stop goes ahead.
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "web"}); err != nil {
		t.Fatalf("stop of a VM left migrating: %v", err)
	}
	if row, _ := corrosion.GetVM(ctx, src.DB, "web"); row == nil || row.State != "stopped" {
		t.Fatalf("web after stop = %+v; want stopped", row)
	}
	if cond, ok, _ := corrosion.GetHealthCondition(ctx, src.DB, "drain", "vm.migration_unresolved", "vm", "web"); !ok || cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("vm.migration_unresolved after the stop = %+v (found %v); want resolved", cond, ok)
	}
	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("start after the stop settled the row: %v", err)
	}
}

// Deleting a VM whose move was left unresolved resolves its
// vm.migration_unresolved.
//
// Mutation: the delete does not resolve it — red.
func TestFleet_DeletingAVMResolvesItsUnresolvedMigration(t *testing.T) {
	c, src, dst := leftMigrating(t)
	ctx := context.Background()
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, src.DB, corrosion.HealthCondition{
		Evaluator: "drain", Code: "vm.migration_unresolved", SubjectKind: "vm", SubjectID: "web",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical, Hosts: []string{src.Name, dst.Name},
		Evidence: "{}", FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: src.Name,
	}); err != nil {
		t.Fatalf("raise vm.migration_unresolved: %v", err)
	}
	if _, err := c.SelfClient(src).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web"}); err != nil {
		t.Fatalf("delete web: %v", err)
	}
	if cond, ok, _ := corrosion.GetHealthCondition(ctx, src.DB, "drain", "vm.migration_unresolved", "vm", "web"); !ok || cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("vm.migration_unresolved after the delete = %+v (found %v); want resolved", cond, ok)
	}
}

// stopWeb stops web through src's API.
func stopWeb(c *Cluster, src *Node) error {
	_, err := c.SelfClient(src).StopVM(context.Background(), &pb.StopVMRequest{Name: "web"})
	return err
}

// webState is web's row state.
func webState(t *testing.T, n *Node) string {
	t.Helper()
	row, err := corrosion.GetVM(context.Background(), n.DB, "web")
	if err != nil || row == nil {
		t.Fatalf("GetVM web: %+v %v", row, err)
	}
	return row.State
}

// A stop of a VM left migrating whose target cannot be asked goes ahead only
// on proof the guest cannot run there: the target fenced or removed over a
// proof-grade fence (an IPMI or Redfish power-off, or `lv host fence-confirm`).
// A target that merely does not answer, or is fenced over a fence that proves
// nothing (an SSH poweroff), still refuses, naming the way out.
//
// Mutations: an unanswering target taken as absent — not-fenced,
// returned-after-fence and unproven-fence go red. No proof read — fenced and
// removed go red. A fenced state taken as proof without its fence row —
// unproven-fence goes red. A removed or rowless target taken as off without
// a proof-grade fence — removed-unproven goes red.
func TestFleet_StopOfAVMLeftMigratingWhoseTargetIsGone(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		prove func(t *testing.T, src, dst *Node)
		ok    bool
	}{
		{"fenced", func(t *testing.T, src, dst *Node) {
			if err := corrosion.RecordFenceWithState(ctx, src.DB, corrosion.FenceLogRecord{
				ID: "f-confirm", HostName: dst.Name, Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"removed", func(t *testing.T, src, dst *Node) {
			if err := corrosion.UpdateHostState(ctx, src.DB, dst.Name, "removed"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(1100 * time.Millisecond) // the fence row is stamped to the second, after the removal
			if err := corrosion.InsertFenceLog(ctx, src.DB, corrosion.FenceLogRecord{
				ID: "f-confirm", HostName: dst.Name, Method: "manual", Result: "manual-confirmed"}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"not-fenced", func(*testing.T, *Node, *Node) {}, false},
		{"removed-unproven", func(t *testing.T, src, dst *Node) {
			// Removed without a confirmed power-off (`lv host rm --dead`
			// alone): it may still run the guest.
			if err := corrosion.UpdateHostState(ctx, src.DB, dst.Name, "removed"); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"returned-after-fence", func(t *testing.T, src, dst *Node) {
			// Confirmed off once, and back since: that fence proves nothing now.
			if err := corrosion.RecordFenceWithState(ctx, src.DB, corrosion.FenceLogRecord{
				ID: "f-confirm", HostName: dst.Name, Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpdateHostState(ctx, src.DB, dst.Name, "active"); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"unproven-fence", func(t *testing.T, src, dst *Node) {
			if err := corrosion.RecordFenceWithState(ctx, src.DB, corrosion.FenceLogRecord{
				ID: "f-ssh", HostName: dst.Name, Method: "ssh", Result: "fenced"}, "fenced"); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, src, dst := leftMigrating(t)
			dst.RefuseRPCs("GetRuntimeInventory") // gone: it answers nothing
			tc.prove(t, src, dst)
			err := stopWeb(c, src)
			if tc.ok {
				if err != nil {
					t.Fatalf("stop with %s proven off: %v", dst.Name, err)
				}
				if st := webState(t, src); st != "stopped" {
					t.Fatalf("web after the stop = %s; want stopped", st)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "lv host fence-confirm "+dst.Name) {
				t.Fatalf("stop with %s not proven off = %v; want it refused, naming lv host fence-confirm %s", dst.Name, err, dst.Name)
			}
			if st := webState(t, src); st != "migrating" {
				t.Fatalf("web after the refused stop = %s; want migrating", st)
			}
		})
	}
}

// The stop arms of a VM left migrating, each pinned:
//   - runs-here: the guest still runs on the source (libvirtd may still run
//     the move's job after a daemon restart). The job is aborted first, so a
//     cut-over cannot land under the stop, and the guest is stopped here.
//   - undefined-here: the source has no domain (a cut-over undefined it) and
//     the target none either. The stop settles the record.
//   - target-defined: the target holds a domain of it that is not running (a
//     paused guest reads so too). Refused.
//   - stopped-under-the-lock: the guest ran here when the stop looked, and no
//     longer when it holds the lock. Refused for a retry, which asks the
//     target.
//
// Mutations: no abort before the stop — runs-here red. A no-domain error on
// a migrating row taken as a failure — undefined-here red. The target's
// defined domain taken as absent — target-defined red. No re-check under the
// lock — stopped-under-the-lock red.
func TestFleet_StopArmsOfAVMLeftMigrating(t *testing.T) {
	t.Run("runs-here", func(t *testing.T) {
		c, src, _ := leftMigrating(t)
		src.Virt.SetState("web", "running")
		if err := stopWeb(c, src); err != nil {
			t.Fatalf("stop of web running on its source: %v", err)
		}
		if n := src.Virt.AbortedMigrations("web"); n < 1 {
			t.Fatalf("web's migration job aborted %d time(s) before the stop; want it aborted", n)
		}
		if st := webState(t, src); st != "stopped" {
			t.Fatalf("web = %s; want stopped", st)
		}
	})
	t.Run("undefined-here", func(t *testing.T) {
		c, src, _ := leftMigrating(t)
		if err := src.Virt.UndefineDomain("web", false); err != nil {
			t.Fatal(err)
		}
		if err := stopWeb(c, src); err != nil {
			t.Fatalf("stop of web with no domain on either host: %v", err)
		}
		if st := webState(t, src); st != "stopped" {
			t.Fatalf("web = %s; want stopped", st)
		}
	})
	t.Run("target-defined", func(t *testing.T) {
		c, src, dst := leftMigrating(t)
		if err := dst.Virt.DefineDomain(`<domain type='kvm'><name>web</name><uuid>33333333-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
			t.Fatal(err)
		}
		if err := stopWeb(c, src); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "virsh domstate web") {
			t.Fatalf("stop with web defined on %s = %v; want refused, naming virsh domstate", dst.Name, err)
		}
		if st := webState(t, src); st != "migrating" {
			t.Fatalf("web = %s; want migrating", st)
		}
	})
	t.Run("stopped-under-the-lock", func(t *testing.T) {
		c, src, _ := leftMigrating(t)
		src.Virt.SetState("web", "running")
		var calls atomic.Int32
		src.Virt.FailDomainState = func(name string) error {
			buf := make([]byte, 32<<10)
			if name == "web" && strings.Contains(string(buf[:runtime.Stack(buf, false)]), "(*Server).StopVM(") && calls.Add(1) >= 2 {
				return errors.New("test: web's state cannot be read under the stop's lock")
			}
			return nil
		}
		if err := stopWeb(c, src); status.Code(err) != codes.Aborted {
			t.Fatalf("stop whose guest stopped running here under the lock = %v; want Aborted", err)
		}
		if st := webState(t, src); st != "migrating" {
			t.Fatalf("web = %s; want migrating", st)
		}
	})
}

// A delete of a VM left migrating asks the move's target as a stop does: one
// whose guest runs there is refused, naming repair-owner.
//
// Mutation: no check in DeleteVM — the delete goes ahead, red.
func TestFleet_DeleteOfAVMLeftMigratingWhoseGuestRunsOnTheTarget(t *testing.T) {
	c, src, dst := leftMigrating(t)
	if err := dst.Virt.DefineDomain(`<domain type='kvm'><name>web</name><uuid>33333333-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	dst.Virt.SetState("web", "running")
	_, err := c.SelfClient(src).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv doctor repair-owner web "+dst.Name) {
		t.Fatalf("delete of web running on %s = %v; want refused, naming repair-owner", dst.Name, err)
	}
	if st := webState(t, src); st != "migrating" {
		t.Fatalf("web = %s; want migrating", st)
	}
}

// A row a daemon left migrating (it died mid-move) carries
// vm.migration_unresolved once the daemon is back, naming the move's target.
//
// Mutation: nothing raised at start — red.
func TestFleet_ARowLeftMigratingRaisesItsConditionAtStart(t *testing.T) {
	_, src, dst := leftMigrating(t)
	src.Server.RaiseLeftMigrating(context.Background())
	cond, ok, err := corrosion.GetHealthCondition(context.Background(), src.DB, "drain", "vm.migration_unresolved", "vm", "web")
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, dst.Name) {
		t.Fatalf("vm.migration_unresolved = %+v ok=%v err=%v; want it open, naming %s", cond, ok, err, dst.Name)
	}
}
