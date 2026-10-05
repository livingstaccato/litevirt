// Fleet scenarios for a cold move racing a start of the VM on its source.
//
// A cold move copies the disks of a VM whose domain is shut off, and once the
// handoff commits it removes the source's copies. It checked the domain was
// shut off once, before the copy, and held only its in-memory VM lock. The
// restart policy (vmcheck) and the reconciler take the replicated per-VM start
// lease, not that lock, so a `restart: always` VM whose policy window elapsed
// mid-copy could be started on the source: the copy read a disk the guest was
// writing, the handoff committed the torn copy to the target, and the source's
// disk was unlinked under the running guest.
//
// The move now holds the start lease for its whole duration, and re-checks the
// domain is shut off immediately before the handoff and again before it
// touches the source.

package fleet

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/health"
)

// While the disks are being moved, no other start path can take the VM's
// start lease on the source.
//
// Mutation: do not take the start lease in coldMigrateStoppedVM — the
// restart policy's holder takes it mid-move and goes red.
func TestFleet_ColdMoveHoldsTheStartLease(t *testing.T) {
	sc := newColdStoppedScenario(t)
	var heldBy string
	var leaseErr error
	sc.dst.Virt.FailDefineDomain = func(string) error {
		// The disk has been copied; the handoff has not committed. This is
		// the restart policy's attempt at the lease, as vmcheck makes it.
		heldBy, leaseErr = health.TryVMStartLease(context.Background(), sc.src.DB,
			sc.src.Name+"/vmcheck", "os1", time.Now())
		return nil
	}
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("migrate --cold: %v", err)
	}
	if leaseErr != nil {
		t.Fatalf("TryVMStartLease mid-move: %v", leaseErr)
	}
	if heldBy == "" || heldBy == sc.src.Name+"/vmcheck" {
		t.Fatalf("the restart policy took os1's start lease (held by %q) while its disks were being moved", heldBy)
	}
	if got, _ := health.TryVMStartLease(context.Background(), sc.src.DB, "after/check", "os1", time.Now()); got != "after/check" {
		t.Errorf("the move did not give the start lease back (held by %q)", got)
	}
}

// A domain started on the source after the copy — here by hand, the case the
// lease cannot fence — stops the move before the handoff: the VM stays where
// it is, with its disk, and the target's copy is taken back.
//
// Mutation: drop the re-check before the handoff — the move commits a copy
// taken while the guest could write, and goes red.
func TestFleet_ColdMoveRefusesADomainStartedMidMove(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.dst.Virt.FailDefineDomain = func(string) error {
		if err := sc.src.Virt.StartDomain("os1"); err != nil {
			t.Errorf("start os1 on the source mid-move: %v", err)
		}
		return nil
	}
	err := sc.migrateCold(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "active") {
		t.Fatalf("migrate --cold with the domain started mid-move = %v, want FailedPrecondition naming the active domain", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.src.Name {
		t.Fatalf("os1 row names %s, want it left on %s", vm.HostName, sc.src.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.src, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Fatalf("the source's disk is not intact (err %v, %d bytes)", err, len(got))
	}
	if _, err := os.Stat(sc.file(sc.dst, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the refused move left its copy on %s (stat: %v)", sc.dst.Name, err)
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("the refused move left os1 defined on %s", sc.dst.Name)
	}
}

// A domain found active on the source after the handoff committed keeps
// everything the source has: its domain is not undefined and its disk is not
// removed, and the move reports it rather than succeeding.
//
// Mutation: drop the re-check after the handoff — the source's disk is
// unlinked under the running guest and goes red.
func TestFleet_ColdMoveKeepsTheSourceOfADomainActiveAfterTheHandoff(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.src.Server.SetColdMoveAfterHandoffForTest(func(vm string) {
		if err := sc.src.Virt.StartDomain(vm); err != nil {
			t.Errorf("start %s on the source after the handoff: %v", vm, err)
		}
	})
	err := sc.migrateCold(t)
	if err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("migrate --cold with the source domain active after the handoff = %v, want an error naming it", err)
	}
	if got, err := os.ReadFile(sc.file(sc.src, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Fatalf("the source's disk was removed under an active domain (err %v, %d bytes)", err, len(got))
	}
	if !sc.src.Virt.DomainExists("os1") {
		t.Errorf("the source's active domain was undefined")
	}
}
