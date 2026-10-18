// Fleet scenarios for a drain's timed-out live move whose abort libvirt does
// not answer within its bound. The move is handed to a background owner and
// the drain goes on. Until libvirt ends the job the guest may still cut over,
// so the VM's row says `migrating` (as `lv migrate` writes it), the VM's lock
// and the target's capacity reservation stay with the move, and nothing — a
// cold move, a re-drain, the source's reconciler after a daemon restart —
// may start it anywhere: one copy at every moment.
package fleet

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// handOffDrain makes src's libvirt ignore the abort of slow's move until
// release is closed, then end it: completed (the guest is undefined on src
// and runs on dst, as a cut-over leaves it) or failed. It drains src and
// returns the drain's last frame for slow and its end, failing the test if
// the drain waits on the unanswered abort.
func handOffDrain(t *testing.T, sc *stuckLiveDrain, release <-chan struct{}, complete bool) (*pb.DrainProgress, error) {
	t.Helper()
	sc.src.Server.SetDrainAbortGraceForTest(300 * time.Millisecond)
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "slow" {
			return nil
		}
		<-release // the abort is not answered
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
	case r := <-out:
		return r.p, r.err
	case <-time.After(15 * time.Second):
		t.Fatal("the drain is still waiting on a live move whose abort libvirt did not answer")
		return nil, nil
	}
}

// cutOver leaves slow as a completed libvirt migration does: undefined on
// the source, running on the target.
func cutOver(t *testing.T, sc *stuckLiveDrain) {
	if err := sc.src.Virt.UndefineDomain("slow", false); err != nil {
		t.Errorf("undefine slow on the source: %v", err)
	}
	sc.dst.Virt.SetState("slow", "running")
}

func releaseOnCleanup(t *testing.T) chan struct{} {
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	return release
}

func waitRow(t *testing.T, n *Node, host, state string) *corrosion.VMRecord {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(15 * time.Second)
	for {
		row, _ := corrosion.GetVM(ctx, n.DB, "slow")
		if row != nil && row.HostName == host && row.State == state {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("VM row = %+v; want %s on %s", row, state, host)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// reconcileSource runs one pass of the source's reconciler, as a restarted
// daemon's first pass would, and reports whether it defined or started slow.
func reconcileSource(t *testing.T, sc *stuckLiveDrain) bool {
	t.Helper()
	before := sc.srcOps("start") + sc.srcOps("define")
	health.NewReconciler(sc.src.Name, filepath.Join(sc.c.tmpRoot, sc.src.Name, "data"), sc.src.DB, sc.src.Virt).
		ReconcileOnce(context.Background())
	return sc.srcOps("start")+sc.srcOps("define") > before || sc.src.Virt.DomainExists("slow")
}

// The drain does not wait on the unanswered abort. Until libvirt ends the
// job: the row says migrating, the target's reservation is held, the VM is
// named in drain_move_timed_out, and a re-drain skips it at once. Once libvirt
// ends it, the background owner records where the guest is, releases the
// reservation, runs post_migrate naming that host, and a completed move
// leaves the condition.
//
// Mutations: wait on libvirt after the abort without a bound (red: still
// waiting). Leave the row running instead of migrating (red). Release the
// lease when the drain moves on (red: no reservation in the window). Skip
// post_migrate on a failed background move (red: hooks). Keep a completed
// move's VM in the condition (red). Drop the re-drain's skipped frame for a
// migrating VM (red: no frame).
func TestFleet_DrainLiveMoveWhoseAbortIsNotAnsweredIsFinishedInTheBackground(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete bool
	}{{"libvirt completes it", true}, {"libvirt fails it", false}} {
		t.Run(tc.name, func(t *testing.T) {
			sc := newStuckLiveDrain(t, false)
			ctx := context.Background()
			release := releaseOnCleanup(t)

			p, err := handOffDrain(t, sc, release, tc.complete)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "slow") {
				t.Fatalf("drain = %v; want FailedPrecondition, incomplete, naming slow", err)
			}
			if p == nil || p.Status != "failed" || !strings.Contains(p.Error, "background") {
				t.Fatalf("drain progress for slow = %+v; want failed, the move left to finish in the background", p)
			}
			row, _ := corrosion.GetVM(ctx, sc.src.DB, "slow")
			if row == nil || row.HostName != sc.src.Name || row.State != "migrating" {
				t.Fatalf("VM row in the background window = %+v; want migrating on %s", row, sc.src.Name)
			}
			if cpu, _, err := corrosion.HostReserved(ctx, sc.dst.DB, sc.dst.Name); err != nil || cpu < 1 {
				t.Fatalf("the target reserves %d vCPU (err %v) while the move can still land there; want the move's 1", cpu, err)
			}
			cond, ok, err := corrosion.GetHealthCondition(ctx, sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name)
			if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, "slow") {
				t.Fatalf("drain_move_timed_out = %+v ok=%v err=%v; want it raised naming slow", cond, ok, err)
			}

			// A re-drain does not wait on the VM's lock: it skips the VM.
			start := time.Now()
			frames, _ := drainAll(t, sc.c, sc.src)
			if time.Since(start) > 5*time.Second {
				t.Fatalf("a re-drain took %v while the move finishes in the background", time.Since(start))
			}
			i := slices.IndexFunc(frames, func(f *pb.DrainProgress) bool { return f.GetVmName() == "slow" })
			if i < 0 || frames[i].Status != "skipped" || !strings.Contains(frames[i].Error, "background") {
				t.Fatalf("re-drain frames = %+v; want slow skipped, its move finishing in the background", frames)
			}

			close(release)
			want := sc.src.Name
			if tc.complete {
				want = sc.dst.Name
			}
			waitRow(t, sc.src, want, "running")
			eventually(t, 10*time.Second, "the target's reservation to be released", func() bool {
				cpu, mem, err := corrosion.HostReserved(ctx, sc.dst.DB, sc.dst.Name)
				return err == nil && cpu == 0 && mem == 0
			})
			wantHooks := []string{"pre_migrate_" + sc.src.Name + "_running", "post_migrate_" + want + "_running"}
			eventually(t, 10*time.Second, "post_migrate to run once, naming where the VM ended", func() bool {
				return slices.Equal(sc.hooks(t), wantHooks)
			})
			if n := sc.srcOps("shutdown"); n != 0 {
				t.Fatalf("the VM was shut down %d time(s); a timed-out live move is never followed by a cold one", n)
			}
			cond, _, _ = corrosion.GetHealthCondition(ctx, sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name)
			if tc.complete {
				eventually(t, 10*time.Second, "the completed move to leave drain_move_timed_out", func() bool {
					c, _, _ := corrosion.GetHealthCondition(ctx, sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name)
					return c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, "slow")
				})
			} else if cond.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cond.Evidence, "slow") {
				t.Fatalf("drain_move_timed_out = %+v; a move that failed keeps the VM named", cond)
			}
		})
	}
}

// The daemon restarts while the move is in the background, so its owner is
// gone; libvirt's job completes on its own. The restarted source's reconciler
// finds no domain for a VM its row names — and must not start one: the guest
// runs on the target. The row says migrating, which the reconciler leaves.
//
// Mutation: leave the row running at the hand-off — the reconciler defines
// and starts slow on the source while it runs on the target, and goes red.
func TestFleet_DrainBackgroundMoveIsNotRestartedOnTheSourceAfterADaemonRestart(t *testing.T) {
	sc := newStuckLiveDrain(t, false)
	release := releaseOnCleanup(t) // never released while the test looks: the owner is "gone"
	if _, err := handOffDrain(t, sc, release, false); err == nil {
		t.Fatal("drain ended clean with a move left in the background")
	}
	// libvirt completed the job while the daemon was down.
	cutOver(t, sc)
	if reconcileSource(t, sc) {
		t.Fatalf("the source's reconciler started slow on %s while it runs on %s: two copies", sc.src.Name, sc.dst.Name)
	}
	row, _ := corrosion.GetVM(context.Background(), sc.src.DB, "slow")
	if row == nil || row.State != "migrating" {
		t.Fatalf("VM row = %+v; want it left migrating for an operator or the owner to settle", row)
	}
	// Let the (in this process, still living) owner finish before the
	// cluster stops: it writes the hook log under the test's directory.
	close(release)
	eventually(t, 10*time.Second, "the owner to finish", func() bool { return len(sc.hooks(t)) == 2 })
}

// The background move completes, but a disk row changed in the window, so
// the ownership commit declines. The fallback re-points the VM row to the
// target, where the guest runs, and the source does not restart it.
//
// Mutations: leave the row running at the hand-off — the re-point's guard
// (source, migrating) declines, the row stays on the source, and goes red.
// Run no post_migrate when the commit fails — the hooks go red.
func TestFleet_DrainBackgroundMoveWhoseCommitDeclinesIsRepointedToTheTarget(t *testing.T) {
	sc := newStuckLiveDrain(t, false)
	ctx := context.Background()
	release := releaseOnCleanup(t)
	if _, err := handOffDrain(t, sc, release, true); err == nil {
		t.Fatal("drain ended clean with a move left in the background")
	}
	if err := corrosion.UpdateVMDiskPath(ctx, sc.src.DB, "slow", "root",
		filepath.Join(sc.c.tmpRoot, "nfs", "slow-root-moved.qcow2")); err != nil {
		t.Fatalf("change the disk row: %v", err)
	}
	close(release)
	waitRow(t, sc.src, sc.dst.Name, "running")
	if reconcileSource(t, sc) {
		t.Fatalf("the source's reconciler started slow on %s while it runs on %s: two copies", sc.src.Name, sc.dst.Name)
	}
	// The commit failed, but libvirt reported the cut-over: the guest runs on
	// the target, and post_migrate says so (the one-pre/one-post pairing).
	wantHooks := []string{"pre_migrate_" + sc.src.Name + "_running", "post_migrate_" + sc.dst.Name + "_running"}
	eventually(t, 10*time.Second, "post_migrate to name the target after a failed commit", func() bool {
		return slices.Equal(sc.hooks(t), wantHooks)
	})
}

// The client goes away (Ctrl-C) before a VM's move times out. The drain's
// stream breaks when it reports the VM, and the condition still names it.
//
// Mutation: return on the failed send without judging — goes red.
func TestFleet_DrainTimedOutMoveIsNamedWhenTheDrainStreamBreaks(t *testing.T) {
	sc := newStuckLiveDrain(t, false)
	ctx := context.Background()
	cctx, cancel := context.WithCancel(ctx)
	st, err := sc.c.SelfClient(sc.src).DrainHost(cctx, &pb.DrainHostRequest{Name: sc.src.Name})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, err := st.Recv(); err != nil {
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	eventually(t, 15*time.Second, "drain_move_timed_out to name slow", func() bool {
		c, ok, _ := corrosion.GetHealthCondition(ctx, sc.src.DB, "drain", "drain_move_timed_out", "host", sc.src.Name)
		return ok && c.Lifecycle != corrosion.ConditionResolved && strings.Contains(c.Evidence, "slow")
	})
}

// lv migrate's own hand-off (its timeout ended the wait) keeps the target's
// reservation until libvirt ends the move.
//
// Mutation: release the lease when MigrateVM returns — no reservation in the
// window, red.
func TestFleet_MigrateAdoptedMoveKeepsTheTargetReservationUntilItEnds(t *testing.T) {
	sc := newStuckLiveDrain(t, false)
	ctx := context.Background()
	release := releaseOnCleanup(t)
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "slow" {
			return nil
		}
		<-release
		cutOver(t, sc)
		return nil
	}
	err := migrateAt(t, sc.c, sc.src, "slow", sc.dst.Name)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("migrate = %v; want DeadlineExceeded (its 1s timeout, the move adopted)", err)
	}
	if cpu, _, err := corrosion.HostReserved(ctx, sc.dst.DB, sc.dst.Name); err != nil || cpu < 1 {
		t.Fatalf("the target reserves %d vCPU (err %v) while the adopted move can still land there; want 1", cpu, err)
	}
	close(release)
	waitRow(t, sc.src, sc.dst.Name, "running")
	eventually(t, 10*time.Second, "the target's reservation to be released", func() bool {
		cpu, mem, err := corrosion.HostReserved(ctx, sc.dst.DB, sc.dst.Name)
		return err == nil && cpu == 0 && mem == 0
	})
}

// A background move that completes writes the drain record a watched one
// writes, so `lv host undrain` brings the VM back with the others.
//
// Mutation: skip the record in the background owner — goes red.
func TestFleet_DrainBackgroundMoveThatCompletesIsRecordedForFailback(t *testing.T) {
	f := newFB(t, 2, true)
	ctx := context.Background()
	a, b := f.a, f.b
	spec := `{"name":"bgfb","cpu":1,"memory_mib":256,"migrate":{"timeout_sec":1}}`
	disk := filepath.Join(f.c.tmpRoot, "nfs", "bgfb-root.qcow2")
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "bgfb", HostName: a.Name, State: "running", Spec: spec, CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "bgfb", DiskName: "root", HostName: a.Name, Path: disk, SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Virt.DefineDomain(`<domain type='kvm'><name>bgfb</name><uuid>` + uuid.NewSHA1(uuid.NameSpaceOID, []byte("bgfb")).String() +
		`</uuid><devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + disk + `'/><target dev='vda'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := a.Virt.StartDomain("bgfb"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)

	a.Server.SetDrainAbortGraceForTest(300 * time.Millisecond)
	release := make(chan struct{})
	a.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "bgfb" {
			return nil
		}
		<-release
		_ = a.Virt.UndefineDomain("bgfb", false)
		b.Virt.SetState("bgfb", "running")
		return nil
	}
	st, err := f.c.SelfClient(a).DrainHost(ctx, &pb.DrainHostRequest{Name: a.Name})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF || rerr != nil {
			break
		}
	}
	close(release)
	eventually(t, 15*time.Second, "the background move to commit and record its drain origin", func() bool {
		vm, _ := corrosion.GetVM(ctx, a.DB, "bgfb")
		_, ok, _ := corrosion.GetLiveDrainOrigin(ctx, a.DB, "bgfb")
		return vm != nil && vm.HostName == b.Name && ok
	})
}

// The client goes away (Ctrl-C) while a live move is in flight, and libvirt
// then completes it. The commit that follows the cut-over does not run on the
// drain's cancelled request: the row is owned by the target, where the only
// copy runs, the source starts nothing, and post_migrate names the target.
//
// Mutation: commit on the request's context — the commit fails, the row stays
// migrating on the source, and goes red.
func TestFleet_DrainCompletedLiveMoveIsCommittedWhenTheClientLeaves(t *testing.T) {
	sc := newStuckLiveDrain(t, false)
	ctx := context.Background()
	release := releaseOnCleanup(t)
	started := make(chan struct{})
	var once sync.Once
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "slow" {
			return nil
		}
		once.Do(func() { close(started) })
		<-release
		cutOver(t, sc)
		return nil
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := sc.c.SelfClient(sc.src).DrainHost(cctx, &pb.DrainHostRequest{Name: sc.src.Name})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, err := st.Recv(); err != nil {
				return
			}
		}
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the live move never started")
	}
	cancel()
	time.Sleep(150 * time.Millisecond) // the server sees the stream end
	close(release)                     // well inside the 1s timeout: no abort

	waitRow(t, sc.src, sc.dst.Name, "running")
	if reconcileSource(t, sc) {
		t.Fatalf("the source's reconciler started slow on %s while it runs on %s: two copies", sc.src.Name, sc.dst.Name)
	}
	wantHooks := []string{"pre_migrate_" + sc.src.Name + "_running", "post_migrate_" + sc.dst.Name + "_running"}
	eventually(t, 10*time.Second, "post_migrate to name the target", func() bool {
		return slices.Equal(sc.hooks(t), wantHooks)
	})
}

// addFBDrainVM adds a running VM on n with one shared disk and no migration
// timeout, whose live move blocks until release is closed and then completes.
func addFBDrainVM(t *testing.T, f *fbScenario, blocked map[string]fbBlock, name string, n, to *Node, started, release chan struct{}) {
	t.Helper()
	ctx := context.Background()
	disk := filepath.Join(f.c.tmpRoot, "nfs", name+"-root.qcow2")
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
		Name: name, HostName: n.Name, State: "running", Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256}`, CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: name, DiskName: "root", HostName: n.Name, Path: disk, SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.Virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>` + uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String() +
		`</uuid><devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + disk + `'/><target dev='vda'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := n.Virt.StartDomain(name); err != nil {
		t.Fatal(err)
	}
	blocked[name] = fbBlock{started: started, release: release, to: to}
}

type fbBlock struct {
	started, release chan struct{}
	to               *Node
}

// After the client leaves, a move that completes later still gets its drain
// record, as one that completed while it watched: undrain fails both back.
//
// Mutation: drop the records in the collector that runs after the stream
// breaks — the later move has none, red.
func TestFleet_DrainRecordsAMoveThatCompletesAfterTheClientLeft(t *testing.T) {
	f := newFB(t, 2, true)
	ctx := context.Background()
	a, b := f.a, f.b
	blocked := map[string]fbBlock{}
	startedA, releaseA := make(chan struct{}), make(chan struct{})
	startedB, releaseB := make(chan struct{}), make(chan struct{})
	addFBDrainVM(t, f, blocked, "fba", a, b, startedA, releaseA)
	addFBDrainVM(t, f, blocked, "fbb", a, b, startedB, releaseB)
	f.c.WaitConverged(t, convergeTimeout)
	var mu sync.Mutex
	startedOnce := map[string]bool{}
	a.Virt.FailMigrateToTarget = func(name, _ string) error {
		blk, ok := blocked[name]
		if !ok {
			return nil
		}
		mu.Lock()
		if !startedOnce[name] {
			startedOnce[name] = true
			close(blk.started)
		}
		mu.Unlock()
		<-blk.release
		_ = a.Virt.UndefineDomain(name, false)
		blk.to.Virt.SetState(name, "running")
		return nil
	}
	t.Cleanup(func() {
		for _, c := range []chan struct{}{releaseA, releaseB} {
			select {
			case <-c:
			default:
				close(c)
			}
		}
	})

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := f.c.SelfClient(a).DrainHost(cctx, &pb.DrainHostRequest{Name: a.Name, Parallel: 2})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, err := st.Recv(); err != nil {
				return
			}
		}
	}()
	for _, c := range []chan struct{}{startedA, startedB} {
		select {
		case <-c:
		case <-time.After(10 * time.Second):
			t.Fatal("a live move never started")
		}
	}
	cancel()
	time.Sleep(150 * time.Millisecond)
	close(releaseA) // its frame is the one whose send fails
	eventually(t, 15*time.Second, "fba to move", func() bool {
		vm, _ := corrosion.GetVM(ctx, a.DB, "fba")
		return vm != nil && vm.HostName == b.Name
	})
	time.Sleep(300 * time.Millisecond)
	close(releaseB) // completes after the drain's loop has returned
	eventually(t, 15*time.Second, "both moves to be recorded for failback", func() bool {
		_, okA, _ := corrosion.GetLiveDrainOrigin(ctx, a.DB, "fba")
		_, okB, _ := corrosion.GetLiveDrainOrigin(ctx, a.DB, "fbb")
		return okA && okB
	})
}
