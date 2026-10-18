// Fleet scenarios for a drain's LIVE move under the VM's migration policy
// timeout (compose `migrate.timeout-sec`). `lv migrate` has always given up on
// a live move that outlives it; a drain did not, so one guest whose memory
// never converged held its drain worker, and the drain, for as long as libvirt
// kept copying.
//
// Multi-node by construction: the move is from one daemon to another, and
// the record the drain leaves — the VM's owner — is the replicated row.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// stuckLiveDrain is two nodes with "slow" running on src, every disk on
// shared storage (none recorded), with a migration policy timeout of 1s. The
// source's libvirt holds the live move until the migration job is aborted,
// then ends it as completeAfterAbort says: failed (libvirt aborted the job,
// the guest stayed) or completed (the cut-over won the race with the abort).
type stuckLiveDrain struct {
	c        *Cluster
	src, dst *Node
}

func newStuckLiveDrain(t *testing.T, completeAfterAbort bool) *stuckLiveDrain {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	sc := &stuckLiveDrain{c: c, src: c.Nodes[0], dst: c.Nodes[1]}
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	spec, err := json.Marshal(&pb.VMSpec{
		Name: "slow", Cpu: 1, MemoryMib: 256,
		Migrate: &pb.MigrationPolicy{TimeoutSec: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, sc.src.DB, corrosion.VMRecord{
		Name: "slow", HostName: sc.src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	sc.src.Virt.SetState("slow", "running")

	aborted := make(chan struct{})
	var once sync.Once
	sc.src.Virt.OnAbortMigration = func(name string) {
		if name == "slow" {
			once.Do(func() { close(aborted) })
		}
	}
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "slow" {
			return nil
		}
		select {
		case <-aborted:
			if completeAfterAbort {
				return nil
			}
			return errors.New("operation aborted: migration out job: canceled by client")
		case <-time.After(20 * time.Second):
			// Never aborted: the move fails on its own, as a live move that
			// did not converge eventually may.
			return errors.New("test: the stuck live move was never aborted")
		}
	}
	return sc
}

func (sc *stuckLiveDrain) drain(t *testing.T) (*pb.DrainProgress, error) {
	t.Helper()
	st, err := sc.c.SelfClient(sc.src).DrainHost(context.Background(), &pb.DrainHostRequest{Name: sc.src.Name})
	if err != nil {
		return nil, err
	}
	var last *pb.DrainProgress
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return last, nil
		}
		if rerr != nil {
			return last, rerr
		}
		if p.GetVmName() == "slow" {
			last = p
		}
	}
}

func (sc *stuckLiveDrain) srcOps(op string) int {
	n := 0
	for _, e := range sc.src.Virt.EventLog() {
		if e.Op == op && e.Domain == "slow" {
			n++
		}
	}
	return n
}

// A live drain move that outlives the VM's migration policy timeout is
// aborted: the guest keeps running on the source, never shut down for a cold
// move, and the drain goes on and ends incomplete, naming the VM, as it does
// for any VM it could not move. The host carries a drain_move_timed_out
// condition naming the VM until it is undrained.
//
// Mutations: apply no timeout to the drain's live move — the drain waits the
// fake's 20s, then falls back to a cold move (shutdown recorded, elapsed and
// abort count go red). Fall back to the cold move after a timeout — the
// shutdown count goes red. Skip raising the condition — goes red. Skip its
// resolve on undrain — goes red.
func TestFleet_DrainLiveMoveIsAbortedAtItsMigrationPolicyTimeout(t *testing.T) {
	sc := newStuckLiveDrain(t, false)
	ctx := context.Background()

	start := time.Now()
	p, err := sc.drain(t)
	elapsed := time.Since(start)
	if elapsed > 15*time.Second {
		t.Fatalf("the drain took %v; the VM's 1s migration timeout did not bound its live move", elapsed)
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "slow") ||
		!strings.Contains(err.Error(), "timeout") {
		t.Fatalf("drain = %v; want FailedPrecondition, incomplete, naming the timed-out VM slow", err)
	}
	if p == nil || p.Status != "failed" || p.Strategy != pb.MigrateStrategy_MIGRATE_LIVE ||
		!strings.Contains(p.Error, "timeout_sec") || !strings.Contains(p.Error, sc.src.Name) {
		t.Fatalf("drain progress for slow = %+v; want a failed LIVE move naming its timeout and the host it keeps running on", p)
	}
	if n := sc.src.Virt.AbortedMigrations("slow"); n != 1 {
		t.Fatalf("libvirt migration job aborted %d time(s), want 1", n)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("the timed-out VM was shut down %d time(s) on the source; a timed-out live move must leave it running", n)
	}
	if st, _ := sc.src.Virt.DomainState("slow"); st != "running" {
		t.Fatalf("source domain state = %q, want running", st)
	}
	row, err := corrosion.GetVM(ctx, sc.src.DB, "slow")
	if err != nil || row == nil || row.HostName != sc.src.Name || row.State != "running" {
		t.Fatalf("VM row = %+v (err %v); want running on %s", row, err, sc.src.Name)
	}

	cond, ok, err := corrosion.GetHealthCondition(ctx, sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name)
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, "slow") {
		t.Fatalf("drain_move_timed_out = %+v ok=%v err=%v; want it raised on %s naming slow", cond, ok, err, sc.src.Name)
	}

	if _, err := sc.c.SelfClient(sc.dst).UndrainHost(ctx, &pb.UndrainHostRequest{Name: sc.src.Name}); err != nil {
		t.Fatalf("undrain: %v", err)
	}
	cond, ok, err = corrosion.GetHealthCondition(ctx, sc.dst.DB, "drain", "drain_move_timed_out", "host", sc.src.Name)
	if err != nil || !ok || cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("drain_move_timed_out after undrain = %+v ok=%v err=%v; want it resolved", cond, ok, err)
	}
}

// The abort races the cut-over and loses: libvirt completed the move. The
// guest runs on the target only, so the drain records it there, as any
// completed live move — one copy, owned where it runs.
//
// Mutation: treat every move that reached its timeout as failed — the row
// stays on the source while the guest runs on the target, and goes red. (At
// the base, with no timeout, the move falls back to a cold one: red.)
func TestFleet_DrainLiveMoveThatCompletesAsItIsAbortedIsRecordedOnTheTarget(t *testing.T) {
	sc := newStuckLiveDrain(t, true)
	ctx := context.Background()

	p, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for slow = %+v; want done (libvirt cut over)", p)
	}
	if n := sc.src.Virt.AbortedMigrations("slow"); n != 1 {
		t.Fatalf("libvirt migration job aborted %d time(s), want 1", n)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("the VM was shut down %d time(s) for a cold move; libvirt had already moved it live", n)
	}
	row, err := corrosion.GetVM(ctx, sc.src.DB, "slow")
	if err != nil || row == nil || row.HostName != sc.dst.Name || row.State != "running" {
		t.Fatalf("VM row = %+v (err %v); want it running, owned by %s, where it runs", row, err, sc.dst.Name)
	}
	if _, ok, _ := corrosion.GetHealthCondition(ctx, sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name); ok {
		t.Fatal("drain_move_timed_out was raised for a move that completed")
	}
}
