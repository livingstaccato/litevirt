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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
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
	// hookLog is where the VM's pre_migrate/post_migrate hooks append
	// "<event> <host> <state>", one line per run.
	hookLog string
}

// hooks is every pre_migrate/post_migrate run so far, in order.
func (sc *stuckLiveDrain) hooks(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(sc.hookLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), " ", "_"))
}

func newStuckLiveDrain(t *testing.T, completeAfterAbort bool) *stuckLiveDrain {
	t.Helper()
	return newStuckLiveDrainTimeout(t, completeAfterAbort, 1)
}

// newStuckLiveDrainTimeout is newStuckLiveDrain with the VM's migration
// policy timeout timeoutSec (0: none).
func newStuckLiveDrainTimeout(t *testing.T, completeAfterAbort bool, timeoutSec int32) *stuckLiveDrain {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	sc := &stuckLiveDrain{c: c, src: c.Nodes[0], dst: c.Nodes[1]}
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	sc.hookLog = filepath.Join(c.tmpRoot, "hooks.log")
	hook := `echo "$LV_EVENT $LV_VM_HOST $LV_VM_STATE" >> ` + sc.hookLog
	spec, err := json.Marshal(&pb.VMSpec{
		Name: "slow", Cpu: 1, MemoryMib: 256,
		Migrate: &pb.MigrationPolicy{TimeoutSec: timeoutSec},
		Hooks:   &pb.HooksSpec{PreMigrate: hook, PostMigrate: hook},
	})
	if err != nil {
		t.Fatal(err)
	}
	// One disk, on shared storage: the move is live, and its row is what a
	// commit after the cut-over checks for drift. Its file exists, so a start
	// of the VM here would succeed.
	nfsDisk := filepath.Join(c.tmpRoot, "nfs", "slow-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(nfsDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nfsDisk, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, sc.src.DB, corrosion.VMRecord{
		Name: "slow", HostName: sc.src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{VMName: "slow", DiskName: "root", HostName: sc.src.Name,
		Path: nfsDisk, SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"}}); err != nil {
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

// abortStuckLiveDrain starts sc's drain, waits until libvirt holds the live
// move, and sends `lv operation abort slow --force` to the other host (it is
// forwarded to the VM's). It returns the drain's last frame for slow, its
// error, and how long it took.
func abortStuckLiveDrain(t *testing.T, sc *stuckLiveDrain) (*pb.DrainProgress, error, time.Duration) {
	t.Helper()
	entered := make(chan struct{})
	var once sync.Once
	stuck := sc.src.Virt.FailMigrateToTarget
	sc.src.Virt.FailMigrateToTarget = func(name, uri string) error {
		if name == "slow" {
			once.Do(func() { close(entered) })
		}
		return stuck(name, uri)
	}
	type res struct {
		p   *pb.DrainProgress
		err error
	}
	out := make(chan res, 1)
	start := time.Now()
	go func() { p, err := sc.drain(t); out <- res{p, err} }()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the drain's live move never reached libvirt")
	}
	resp, err := sc.c.SelfClient(sc.dst).AbortVMOperation(context.Background(),
		&pb.AbortVMOperationRequest{VmName: "slow", Force: true})
	if err != nil || !resp.GetAborted() {
		t.Fatalf("operation abort = %+v, %v; want the drain's move of slow aborted", resp, err)
	}
	select {
	case r := <-out:
		return r.p, r.err, time.Since(start)
	case <-time.After(30 * time.Second):
		t.Fatal("the drain did not end after its live move was aborted")
		return nil, nil, 0
	}
}

// `lv operation abort <vm> --force` ends a drain's live move that has no
// migration policy timeout: the libvirt migration job is aborted, the guest
// keeps running on the source, never shut down for a cold move, and the drain
// ends incomplete.
//
// Mutations: do not abort the libvirt job when the move is cancelled — the
// move holds until the fake's 20s, then falls back, red. Leave cancelled moves
// out of the drain's summary — red.
func TestFleet_OperationAbortEndsAStuckLiveDrainMove(t *testing.T) {
	sc := newStuckLiveDrainTimeout(t, false, 0)
	p, err, elapsed := abortStuckLiveDrain(t, sc)
	if elapsed > 15*time.Second {
		t.Fatalf("the drain took %v; the abort did not end its live move", elapsed)
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "drain incomplete") ||
		!strings.Contains(err.Error(), "slow was cancelled by `lv operation abort`") {
		t.Fatalf("drain = %v; want FailedPrecondition, incomplete, naming slow's cancelled move", err)
	}
	if p == nil || p.Status != "failed" || p.Strategy != pb.MigrateStrategy_MIGRATE_LIVE ||
		!strings.Contains(p.Error, "lv operation abort") || !strings.Contains(p.Error, sc.src.Name) {
		t.Fatalf("drain progress for slow = %+v; want a failed LIVE move naming the abort and the host it keeps running on", p)
	}
	if n := sc.src.Virt.AbortedMigrations("slow"); n != 1 {
		t.Fatalf("libvirt migration job aborted %d time(s), want 1", n)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("the VM was shut down %d time(s) on the source; an aborted live move must leave it running", n)
	}
	if st, _ := sc.src.Virt.DomainState("slow"); st != "running" {
		t.Fatalf("source domain state = %q, want running", st)
	}
	row, rerr := corrosion.GetVM(context.Background(), sc.src.DB, "slow")
	if rerr != nil || row == nil || row.HostName != sc.src.Name || row.State != "running" {
		t.Fatalf("VM row = %+v (err %v); want running on %s", row, rerr, sc.src.Name)
	}
	if _, ok, _ := corrosion.GetHealthCondition(context.Background(), sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name); ok {
		t.Fatal("drain_move_timed_out was raised for a move an operator aborted")
	}
}

// The live move cut over as the abort reached libvirt: the guest runs on the
// target only, and the drain records it there — one copy, owned where it runs.
//
// Mutation: treat every aborted move as failed — the row stays on the source
// while the guest runs on the target, red.
func TestFleet_OperationAbortOfALiveDrainMoveThatCompletesIsRecordedOnTheTarget(t *testing.T) {
	sc := newStuckLiveDrainTimeout(t, true, 0)
	p, err, elapsed := abortStuckLiveDrain(t, sc)
	if elapsed > 15*time.Second {
		t.Fatalf("the drain took %v; the abort did not reach its live move", elapsed)
	}
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for slow = %+v; want done (libvirt cut over)", p)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("the VM was shut down %d time(s); libvirt had already moved it live", n)
	}
	row, rerr := corrosion.GetVM(context.Background(), sc.src.DB, "slow")
	if rerr != nil || row == nil || row.HostName != sc.dst.Name || row.State != "running" {
		t.Fatalf("VM row = %+v (err %v); want it running, owned by %s", row, rerr, sc.dst.Name)
	}
	if n := sc.src.Virt.AbortedMigrations("slow"); n != 1 {
		t.Fatalf("libvirt migration job aborted %d time(s), want 1", n)
	}
}

// An operator abort of a live drain move (no policy timeout) that libvirt
// does not answer within the grace is handed to the background owner, as a
// timed-out one is: the row stays migrating on the source in the window, the
// drain names the move as finishing in the background, and the owner records
// where the guest ends — the target when the move completed, the source when
// it failed. Never the target while libvirt may still fail it.
//
// Mutation: let an aborted move skip the hand-off (pending && !aborted) — the
// frame is done and the row is committed to the target while libvirt is still
// moving the guest, red.
func TestFleet_OperationAbortOfALiveDrainMoveLibvirtDoesNotAnswerIsFinishedInTheBackground(t *testing.T) {
	for _, complete := range []bool{true, false} {
		name := "fails"
		if complete {
			name = "completes"
		}
		t.Run(name, func(t *testing.T) {
			sc := newStuckLiveDrainTimeout(t, false, 0)
			ctx := context.Background()
			release := releaseOnCleanup(t)
			sc.src.Server.SetDrainAbortGraceForTest(300 * time.Millisecond)
			entered := make(chan struct{})
			var once sync.Once
			sc.src.Virt.FailMigrateToTarget = func(n, _ string) error {
				if n != "slow" {
					return nil
				}
				once.Do(func() { close(entered) })
				<-release
				if !complete {
					return errors.New("operation failed: migration out job: unexpectedly failed")
				}
				cutOver(t, sc)
				return nil
			}
			type res struct {
				p   *pb.DrainProgress
				err error
			}
			out := make(chan res, 1)
			go func() { p, err := sc.drain(t); out <- res{p, err} }()
			select {
			case <-entered:
			case <-time.After(15 * time.Second):
				t.Fatal("the live move never reached libvirt")
			}
			resp, err := sc.c.SelfClient(sc.dst).AbortVMOperation(ctx, &pb.AbortVMOperationRequest{VmName: "slow", Force: true})
			if err != nil || !resp.GetAborted() {
				t.Fatalf("abort = %+v, %v", resp, err)
			}
			var r res
			select {
			case r = <-out:
			case <-time.After(15 * time.Second):
				t.Fatal("the drain still waits on the unanswered abort")
			}
			if r.p == nil || r.p.Status != "failed" || !strings.Contains(r.p.Error, "background") ||
				!strings.Contains(r.p.Error, "lv operation abort") {
				t.Fatalf("frame = %+v (err %v); want failed, aborted, left to the background", r.p, r.err)
			}
			if r.err == nil || !strings.Contains(r.err.Error(), "the cancelled move of slow is finishing in the background") {
				t.Fatalf("drain = %v; want it to name slow's cancelled move finishing in the background", r.err)
			}
			row, _ := corrosion.GetVM(ctx, sc.src.DB, "slow")
			if row == nil || row.HostName != sc.src.Name || row.State != "migrating" {
				t.Fatalf("row in the window = %+v; want migrating on %s", row, sc.src.Name)
			}
			close(release)
			want := sc.src.Name
			if complete {
				want = sc.dst.Name
			}
			waitRow(t, sc.src, want, "running")
			if n := sc.srcOps("shutdown"); n != 0 {
				t.Fatalf("shut down %d time(s)", n)
			}
			if got := sc.src.Virt.DomainExists("slow"); got == complete {
				t.Fatalf("source domain exists = %v with complete=%v", got, complete)
			}
		})
	}
}

// An abort that reaches libvirt before the migration job exists fails ("no
// job is active"). It is sent again until libvirt takes it, so the move is
// still aborted, within the grace, and the guest stays on the source.
//
// Mutations: send the abort once — the move is never aborted, the drain
// hands it to the background at the grace, red. Keep re-sending after the
// move returned — the count grows, red.
func TestFleet_OperationAbortThatLibvirtRefusesIsSentAgain(t *testing.T) {
	sc := newStuckLiveDrainTimeout(t, false, 0)
	sc.src.Server.SetDrainAbortGraceForTest(5 * time.Second)
	var refused atomic.Bool
	sc.src.Virt.FailAbortMigration = func(name string) error {
		if name == "slow" && refused.CompareAndSwap(false, true) {
			return errors.New("Requested operation is not valid: no job is active on the domain")
		}
		return nil
	}
	p, err, elapsed := abortStuckLiveDrain(t, sc)
	if elapsed > 4*time.Second {
		t.Fatalf("the drain took %v; the refused abort was not sent again", elapsed)
	}
	if p == nil || p.Status != "failed" || strings.Contains(p.Error, "background") ||
		!strings.Contains(p.Error, "lv operation abort") {
		t.Fatalf("drain progress for slow = %+v (err %v); want the move aborted, not left to the background", p, err)
	}
	if n := sc.src.Virt.AbortedMigrations("slow"); n != 2 {
		t.Fatalf("abort sent %d time(s), want 2 (refused, then taken)", n)
	}
	// Nothing is sent once the move has returned: past two re-send periods,
	// still 2.
	time.Sleep(2 * time.Second)
	if n := sc.src.Virt.AbortedMigrations("slow"); n != 2 {
		t.Fatalf("abort sent %d time(s) after the move returned, want still 2", n)
	}
	waitRow(t, sc.src, sc.src.Name, "running")
}

// An abort that lands before libvirt is asked (here, while the target admits
// the VM) is reported as the abort it is, not as the target refusing the
// move, and libvirt is never asked to migrate.
//
// Mutation: report the interrupted step's error — "target admission refused:
// ... context canceled", red.
func TestFleet_OperationAbortBeforeTheLiveMoveStartsIsReportedAsAnAbort(t *testing.T) {
	sc := newStuckLiveDrainTimeout(t, false, 0)
	entered := make(chan struct{})
	var once sync.Once
	sc.dst.HookUnary("ReserveHostCapacity", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(15 * time.Second):
			return h(ctx, req)
		}
	})
	type res struct {
		p   *pb.DrainProgress
		err error
	}
	out := make(chan res, 1)
	go func() { p, err := sc.drain(t); out <- res{p, err} }()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the live move never reached the target's admission")
	}
	resp, err := sc.c.SelfClient(sc.src).AbortVMOperation(context.Background(),
		&pb.AbortVMOperationRequest{VmName: "slow", Force: true})
	if err != nil || !resp.GetAborted() {
		t.Fatalf("operation abort = %+v, %v; want the drain's move of slow aborted", resp, err)
	}
	var r res
	select {
	case r = <-out:
	case <-time.After(10 * time.Second):
		t.Fatal("the drain did not end after its move was aborted")
	}
	if r.p == nil || r.p.Status != "failed" ||
		!strings.HasPrefix(r.p.Error, "live move was cancelled by `lv operation abort slow --force` before libvirt started it") {
		t.Fatalf("drain progress for slow = %+v; want the abort reported as such", r.p)
	}
	if n := sc.srcOps("migrate"); n != 0 {
		t.Fatalf("libvirt was asked to migrate %d time(s)", n)
	}
	row, rerr := corrosion.GetVM(context.Background(), sc.src.DB, "slow")
	if rerr != nil || row == nil || row.HostName != sc.src.Name || row.State != "running" {
		t.Fatalf("VM row = %+v (err %v); want running on %s", row, rerr, sc.src.Name)
	}
}
