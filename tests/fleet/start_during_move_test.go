// Fleet scenarios for a start of a VM while a move of it is under way, or
// after one left its row `migrating`: the start never makes a second copy.
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
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
// stop does not resolve the condition — red.
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
