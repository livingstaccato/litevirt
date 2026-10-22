// Fleet scenario: a live migration OUT of a host in write quarantine
// (termination-design VERIFY M2, test table row 5, S1).
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
// quarantine: the guest stays where its row says it runs, and failover of the
// source recovers exactly one copy.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Mutation: drop the quarantine refusal in migrateOwnedVM — red: the guest
// runs on dst while every row names src, and failover starts a second copy.
func TestFleet_MigrateOutOfAWriteQuarantinedSourceKeepsOneCopy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5152})
	a, dst, src := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	setHostCapacity(t, c, a.Name, 32, 65536)
	setHostCapacity(t, c, dst.Name, 32, 65536)
	setHostCapacity(t, c, src.Name, 32, 65536)
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "mv", HostName: src.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
		CPUActual: 1, MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM mv: %v", err)
	}
	src.Virt.SetState("mv", "running")
	c.WaitConverged(t, convergeTimeout)

	// A live move libvirt completes: the guest lands running on dst and the
	// source domain is gone, as with UNDEFINE_SOURCE.
	src.LandMigrationsOn(dst)
	land := src.Virt.OnMigrateToTarget
	src.Virt.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
		if err := land(name, uri, p); err != nil {
			return err
		}
		src.Virt.VanishDomain(name)
		return nil
	}

	const reason = "rolled back below latched token(s): test"
	src.DB.SetWriteQuarantine(func() string { return reason })
	err := migrateAt(t, c, src, "mv", dst.Name)

	// The invariant first: one running copy, and every replica's row names
	// the host that runs it.
	on := runningOn(c, "mv")
	if len(on) != 1 {
		t.Fatalf("after the move, mv runs on %v, want exactly one host (migrate err=%v)", on, err)
	}
	for _, n := range []*Node{a, dst, src} {
		if got := vmOn(t, n, "mv").HostName; got != on[0] {
			t.Errorf("%s's row names %s while mv runs on %s (migrate err=%v): failover recovers from this row",
				n.Name, got, on[0], err)
		}
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), reason) {
		t.Errorf("migrate out of a write-quarantined source: err=%v, want FailedPrecondition naming %q", err, reason)
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

// The control: the same move from a source that is not in write quarantine
// lands on dst, its row with it — the refusal above is the quarantine's, not
// the scenario's.
func TestFleet_MigrateOutOfAnUnquarantinedSourceCommitsToTheTarget(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 5153})
	dst, src := c.Nodes[0], c.Nodes[1]
	setHostCapacity(t, c, dst.Name, 32, 65536)
	setHostCapacity(t, c, src.Name, 32, 65536)
	if err := corrosion.InsertVM(ctx, dst.DB, corrosion.VMRecord{
		Name: "mv", HostName: src.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
		CPUActual: 1, MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM mv: %v", err)
	}
	src.Virt.SetState("mv", "running")
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
	if err := migrateAt(t, c, src, "mv", dst.Name); err != nil {
		t.Fatalf("migrate once the quarantine lifted: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if on := runningOn(c, "mv"); len(on) != 1 || on[0] != dst.Name {
		t.Fatalf("mv runs on %v, want only %s", on, dst.Name)
	}
	for _, n := range []*Node{dst, src} {
		if got := vmOn(t, n, "mv").HostName; got != dst.Name {
			t.Errorf("%s's row names %s, want %s", n.Name, got, dst.Name)
		}
	}
}
