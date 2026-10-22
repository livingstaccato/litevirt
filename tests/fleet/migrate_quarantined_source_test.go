// Fleet scenario: a move OUT of a host in write quarantine (termination-design
// VERIFY M2, test table row 5, S1).
//
// The ownership commit of a live move is a replicated write the SOURCE makes
// after libvirt's cut-over, and so is the `migrating` state written before it.
// A host in write quarantine (a rollback below a latched token, release
// probation) refuses both. The move went ahead anyway: the guest cut over to
// the target while every replica's row still named the source, `running`.
// Once the source then failed, failover recovered the VM from that row and
// started a second copy beside the target's.
//
// A write-quarantined source now refuses a move out up front, naming the
// quarantine, before anything is done on the target: the guest stays where
// its row says it runs, and failover of the source recovers exactly one copy.
// The target refuses too, at the move's first contact (ReserveHostCapacity),
// once the source says over Ping that it is quarantined: a source on a build
// without its own refusal (a rollback to an older binary) is stopped there.
package fleet

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const testQuarantine = "rolled back below latched token(s): test"

// quarantinedMoveFleet is three hosts with VM mv on src in state (running, or
// stopped with its domain shut off), its moves landing on dst as libvirt
// completes them (the guest running there, the source domain gone).
func quarantinedMoveFleet(t *testing.T, seed int64, state string) (c *Cluster, a, dst, src *Node) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, dst, src = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 32, 65536)
	}
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "mv", HostName: src.Name, Spec: `{"on_host_failure":"restart-any"}`, State: state,
		CPUActual: 1, MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM mv: %v", err)
	}
	if state == "running" {
		src.Virt.SetState("mv", libvirtfake.StateRunning)
	} else {
		src.Virt.SetState("mv", libvirtfake.StateShutdown)
	}
	c.WaitConverged(t, convergeTimeout)
	src.LandMigrationsOn(dst)
	land := src.Virt.OnMigrateToTarget
	src.Virt.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		src.Virt.VanishDomain(name)
		return nil
	}
	return c, a, dst, src
}

// countUnary counts every call n serves of method from now on, the real
// handler answering each.
func countUnary(n *Node, method string) *atomic.Int32 {
	var calls atomic.Int32
	var hook UnaryHook
	hook = func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		calls.Add(1)
		n.HookUnary(method, hook)
		return handler(ctx, req)
	}
	n.HookUnary(method, hook)
	return &calls
}

// migrateStrategyAt is migrateAt with the strategy given.
func migrateStrategyAt(t *testing.T, c *Cluster, at *Node, vmName, targetHost string, strategy pb.MigrateStrategy) error {
	t.Helper()
	st, err := c.SelfClient(at).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: vmName, TargetHost: targetHost, Strategy: strategy,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// requireOneCopyWhereTheRowSays checks mv runs on exactly one host and every
// replica's row names that host.
func requireOneCopyWhereTheRowSays(t *testing.T, c *Cluster, err error, nodes ...*Node) string {
	t.Helper()
	on := runningOn(c, "mv")
	if len(on) != 1 {
		t.Fatalf("after the move, mv runs on %v, want exactly one host (migrate err=%v)", on, err)
	}
	for _, n := range nodes {
		if got := vmOn(t, n, "mv").HostName; got != on[0] {
			t.Errorf("%s's row names %s while mv runs on %s (migrate err=%v): failover recovers from this row",
				n.Name, got, on[0], err)
		}
	}
	return on[0]
}

// Mutations: drop the refusal in migrateOwnedVM — red (the guest runs on dst
// while every row names src, and failover starts a second copy); move it
// after the destination lease — red (dst was asked to reserve).
func TestFleet_MigrateOutOfAWriteQuarantinedSourceKeepsOneCopy(t *testing.T) {
	c, a, dst, src := quarantinedMoveFleet(t, 5152, "running")
	reserves := countUnary(dst, "ReserveHostCapacity")
	src.DB.SetWriteQuarantine(func() string { return testQuarantine })
	err := migrateAt(t, c, src, "mv", dst.Name)

	requireOneCopyWhereTheRowSays(t, c, err, a, dst, src)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), testQuarantine) {
		t.Errorf("migrate out of a write-quarantined source: err=%v, want FailedPrecondition naming %q", err, testQuarantine)
	}
	if n := reserves.Load(); n != 0 {
		t.Errorf("dst was asked to reserve capacity %d time(s): the refusal came after a target-side effect", n)
	}

	// The source then fails. Recovery must leave exactly one running copy.
	c.Kill(src)
	c.SetLinkFaultBoth(a, dst, slowLink)
	clock := NewVirtualClock(time.Now().UTC())
	PublishHealth(t, a, src.Name, 5, clock.Now())
	PublishHealth(t, dst, src.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, dst)
	runRecovery(t, c, clock, false, a, dst)
	var survivors []string
	for _, h := range runningOn(c, "mv") {
		if h != src.Name {
			survivors = append(survivors, h)
		}
	}
	if len(survivors) != 1 {
		t.Fatalf("after failover of %s, mv runs on survivors %v, want exactly one", src.Name, survivors)
	}
	if got := vmOn(t, a, "mv").HostName; got != survivors[0] {
		t.Errorf("after failover mv's row names %s, but it runs on %s", got, survivors[0])
	}
}

// A cold move of a stopped VM is refused the same way, before the target is
// asked for anything (coldMigrateStoppedVM copies to the target before its
// own commit).
//
// Mutation: move the refusal after the destination lease — red.
func TestFleet_ColdMigrateOutOfAWriteQuarantinedSourceIsRefusedFirst(t *testing.T) {
	c, a, dst, src := quarantinedMoveFleet(t, 5154, "stopped")
	reserves := countUnary(dst, "ReserveHostCapacity")
	src.DB.SetWriteQuarantine(func() string { return testQuarantine })
	err := migrateStrategyAt(t, c, src, "mv", dst.Name, pb.MigrateStrategy_MIGRATE_COLD)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), testQuarantine) {
		t.Errorf("cold migrate out of a write-quarantined source: err=%v, want FailedPrecondition naming %q", err, testQuarantine)
	}
	if n := reserves.Load(); n != 0 {
		t.Errorf("dst was asked to reserve capacity %d time(s): the refusal came after a target-side effect", n)
	}
	if dst.Virt.DomainExists("mv") {
		t.Errorf("dst holds a domain of mv after a refused move")
	}
	for _, n := range []*Node{a, dst, src} {
		if got := vmOn(t, n, "mv").HostName; got != src.Name {
			t.Errorf("%s's row names %s, want %s", n.Name, got, src.Name)
		}
	}
}

// A source on a build without its own refusal (a rollback to an older
// binary), quarantined, is refused by the TARGET at ReserveHostCapacity: it
// asks the source over Ping. A source the target cannot ask is refused too,
// retryably (fail closed).
//
// Mutation: drop incomingMoveSourceRefusal from ReserveHostCapacity — the
// "quarantined" arm goes red (the guest cuts over and every row names src).
// Mutation: fail open on a Ping error — the "ping-fails" arm goes red.
func TestFleet_TargetRefusesAMoveFromAQuarantinedOlderSource(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pingFail bool
		want     codes.Code
		wantText string
	}{
		{name: "quarantined", want: codes.FailedPrecondition, wantText: "WAL quarantine"},
		{name: "ping-fails", pingFail: true, want: codes.Unavailable, wantText: "could not ask"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, a, dst, src := quarantinedMoveFleet(t, 5155, "running")
			src.Server.SetSourceMoveGuardOffForTest(true)
			src.DB.SetWriteQuarantine(func() string { return testQuarantine })
			src.Server.SetWALQuarantinedForTest(true)
			if tc.pingFail {
				defer src.RefuseRPCs("Ping")()
			}
			err := migrateAt(t, c, src, "mv", dst.Name)
			if host := requireOneCopyWhereTheRowSays(t, c, err, a, dst, src); host != src.Name {
				t.Errorf("mv runs on %s, want it left on %s", host, src.Name)
			}
			if status.Code(err) != tc.want || !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("migrate from a quarantined older source: err=%v, want %v naming %q", err, tc.want, tc.wantText)
			}
			for _, e := range src.Virt.EventLog() {
				if e.Domain == "mv" && e.Op == "migrate" {
					t.Errorf("libvirt was asked to migrate mv off the quarantined source")
				}
			}
		})
	}
}

// The control: the same move from a source that is not in write quarantine
// lands on dst, its row with it, with the source's own refusal off too — the
// refusals above are the quarantine's, not the scenario's.
func TestFleet_MigrateOutOfAnUnquarantinedSourceCommitsToTheTarget(t *testing.T) {
	c, a, dst, src := quarantinedMoveFleet(t, 5153, "running")
	src.Server.SetSourceMoveGuardOffForTest(true)
	if err := migrateAt(t, c, src, "mv", dst.Name); err != nil {
		t.Fatalf("migrate from a source not in quarantine: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if host := requireOneCopyWhereTheRowSays(t, c, nil, a, dst, src); host != dst.Name {
		t.Fatalf("mv runs on %s, want %s", host, dst.Name)
	}
}

// `lv ct migrate` off a write-quarantined host is refused before the target
// is prepared or asked to reserve, and before the container is stopped: its
// stop intent and its re-key are writes the quarantine refuses, so it used to
// stop the container, fail, and restart it best effort.
//
// Mutation: drop the refusal in MigrateContainer — red (the container is
// stopped, the target prepared and asked to reserve).
func TestFleet_ContainerMigrateOutOfAWriteQuarantinedSourceIsRefusedFirst(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 5156})
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-q"
	createContainer(t, c, src, name)
	if _, err := c.SelfClient(src).StartContainer(context.Background(), &pb.StartContainerRequest{
		HostName: src.Name, Name: name,
	}); err != nil {
		t.Fatalf("start container: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	startsBefore := len(src.CT.StartCalls())
	if st := src.CT.State(name); st != "running" {
		t.Fatalf("premise: %s is %q on %s, want running", name, st, src.Name)
	}
	reserves := countUnary(dst, "ReserveHostCapacity")
	prepares := countUnary(dst, "PrepareContainerTarget")
	src.DB.SetWriteQuarantine(func() string { return testQuarantine })

	err := runMigrate(t, c, src, dst, name, stagingRepo(t))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), testQuarantine) {
		t.Errorf("container migrate out of a write-quarantined source: err=%v, want FailedPrecondition naming %q", err, testQuarantine)
	}
	if stops := src.CT.StopCalls(); len(stops) != 0 {
		t.Errorf("the container was stopped (%v) for a move that could not be recorded", stops)
	}
	if st := src.CT.State(name); st != "running" {
		t.Errorf("%s is %q on %s after the refused move, want running", name, st, src.Name)
	}
	if starts := src.CT.StartCalls()[startsBefore:]; len(starts) != 0 {
		t.Errorf("the container was started again (%v) after a refused move", starts)
	}
	if n, p := reserves.Load(), prepares.Load(); n != 0 || p != 0 {
		t.Errorf("dst was asked to reserve %d and prepare %d time(s): the refusal came after a target-side effect", n, p)
	}
}

// `lv region migrate --with-storage` off a write-quarantined host is refused
// before any disk is replicated to the target pool: it used to copy every
// disk, then have its MigrateVM refused, leaving the copies behind.
//
// Mutation: drop the refusal in CrossRegionMigrate — red (a disk-copy frame
// is sent before the refusal).
func TestFleet_CrossRegionMigrateOutOfAWriteQuarantinedSourceCopiesNothing(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 5157, RegionByIndex: []string{"ny", "lon"}})
	src, dst := c.Nodes[0], c.Nodes[1]
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "mv", HostName: src.Name, Spec: `{}`, State: "running", CPUActual: 1, MemActual: 512,
	}, nil, []corrosion.DiskRecord{{
		VMName: "mv", DiskName: "root", HostName: src.Name, Path: "/var/lib/litevirt/disks/mv-root.qcow2",
		StorageType: "local", SizeBytes: 1 << 20,
	}}); err != nil {
		t.Fatalf("InsertVM mv: %v", err)
	}
	src.Virt.SetState("mv", libvirtfake.StateRunning)
	c.WaitConverged(t, convergeTimeout)
	src.DB.SetWriteQuarantine(func() string { return testQuarantine })

	st, err := c.SelfClient(src).CrossRegionMigrate(ctx, &pb.CrossRegionMigrateRequest{
		VmName: "mv", TargetHost: dst.Name, Live: true, IncludeDisks: true, TargetPool: "default",
	})
	copies := 0
	for err == nil {
		var p *pb.MigrateProgress
		if p, err = st.Recv(); err == nil && p.GetPhase() == pb.MigratePhase_MIGRATE_COPYING {
			copies++
		}
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), testQuarantine) {
		t.Errorf("cross-region migrate out of a write-quarantined source: err=%v, want FailedPrecondition naming %q", err, testQuarantine)
	}
	if copies != 0 {
		t.Errorf("%d disk-copy frame(s) were sent before the refusal: a disk was replicated for a move that cannot be recorded", copies)
	}
}
