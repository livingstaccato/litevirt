package health

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Publishing a VM as running is the moment its ownership generation becomes a
// claim other nodes act on. A row that says "running" while no marker names its
// generation is a workload nobody can prove, and that window is what the
// dual-run detector's newborn grace exists to tolerate — so closing it
// everywhere is what eventually makes that grace deletable.
//
// There are TWO orderings here, not one, because a running write is one of two
// kinds and a single ordering is wrong for one of them:
//
//   - NON-MINTING (UpdateVMState and friends): the generation is unchanged, so
//     the marker's value is already known and already committed. Mark first,
//     commit only if the markers landed. No window at all.
//   - MINTING (TransferVMOwner, CompleteVMStartProof): the statement sets
//     state='running' AND vm_owner_epoch = vm_owner_epoch + 1 together, so the
//     correct marker value does not EXIST until the commit lands. Commit, read
//     back, then mark. Marking first would stamp the generation the row is
//     about to leave, which is precisely the disagreement condition 7 reports.
//
// Do not unify them.

// DomainEpochSetter is the one libvirt method a marker write needs. Narrowed to
// a single method so *grpcapi.Server's backend, the Reconciler's interface,
// *libvirt.Client and libvirtfake all satisfy it without an adapter.
type DomainEpochSetter interface {
	SetDomainOwnerEpoch(name string, epoch int64, running bool) error
}

// usable reports whether a DomainEpochSetter can actually be called.
//
// A nil CONCRETE pointer boxed into this interface is NOT a nil interface: it
// passes `!= nil` and then dereferences nil on the first method call.
// VMChecker.virt is a *libvirt.Client that is nil in ~70 tests, so this is the
// ordinary case rather than a corner one. Checked here instead of at each call
// site because one missed caller is a panic inside a VM restart path.
func usable(virt DomainEpochSetter) bool {
	if virt == nil {
		return false
	}
	switch v := reflect.ValueOf(virt); v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return !v.IsNil()
	default:
		return true
	}
}

// writeBothMarkers stamps the runtime markers for a positive generation.
//
// An epoch below 1 writes nothing: a pre-epoch row has no generation to name,
// the backfill is what graduates it, and a marker against an epoch-0 row is the
// one mismatch convergeOwnerEpochMarker returns early on and never repairs.
func writeBothMarkers(virt DomainEpochSetter, dataDir, name string, epoch int64) error {
	if epoch < 1 {
		return nil
	}
	if usable(virt) {
		if err := virt.SetDomainOwnerEpoch(name, epoch, true); err != nil {
			return fmt.Errorf("owner-epoch domain marker for %q at generation %d: %w", name, epoch, err)
		}
	}
	// Skipped rather than written to a relative path: readVMMarker treats an
	// empty dataDir as MarkerMissing, so such a marker is one no reader resolves.
	if dataDir != "" {
		if err := WriteVMOwnerEpochMarker(dataDir, name, epoch); err != nil {
			return fmt.Errorf("owner-epoch file marker for %q at generation %d: %w", name, epoch, err)
		}
	}
	return nil
}

// PublishVMRunning publishes a NON-MINTING running transition: both markers
// first, and commit only if they landed.
//
// commit is the caller's own state write, passed as a callback because the
// layering is corrosion <- health <- grpcapi: health cannot name grpcapi's
// Server, and an interface both *Server and *Reconciler satisfy would be a
// wider change than the invariant needs. Each site keeps its SQL and its error
// handling.
//
// epoch must be a value the caller READ SUCCESSFULLY. A caller that cannot read
// the row must refuse its transition rather than pass 0: a successful read of 0
// is a pre-epoch row, a failed read is nothing at all, and treating them alike
// turns this into a no-op exactly when the store is unhealthy — under the
// conditions it exists for.
func PublishVMRunning(ctx context.Context, virt DomainEpochSetter, dataDir, name string, epoch int64, commit func(context.Context) error) error {
	if err := writeBothMarkers(virt, dataDir, name, epoch); err != nil {
		return err
	}
	return commit(ctx)
}

// PublishVMRunningMinted publishes a MINTING running transition: commit, read
// back the generation the commit produced, then mark that.
//
// A marker failure here is NOT returned as failure, which is the opposite of
// PublishVMRunning's contract and deliberate. The commit has landed and the
// guest is running, so refusing undoes nothing, and a positive epoch with a
// missing or stale marker is exactly convergeOwnerEpochMarker's repair case —
// whose call site fires for any confirmed-running VM regardless of the
// enforcement flag.
//
// A failed READ-BACK is returned, because then nothing is known about which
// generation to repair toward, and a caller that cannot learn it should surface
// that rather than leave a running row silently unmarked.
func PublishVMRunningMinted(ctx context.Context, virt DomainEpochSetter, db *corrosion.Client, dataDir, name string, commit func(context.Context) error) error {
	if err := commit(ctx); err != nil {
		return err
	}
	row, err := corrosion.GetVM(ctx, db, name)
	if err != nil {
		return fmt.Errorf("owner-epoch read-back for %q after a minting publish: %w", name, err)
	}
	if row == nil {
		return fmt.Errorf("owner-epoch read-back for %q after a minting publish: no row", name)
	}
	if merr := writeBothMarkers(virt, dataDir, name, row.OwnerEpoch); merr != nil {
		slog.Warn("publish: markers not written after a minting transition — convergence will repair",
			"vm", name, "epoch", row.OwnerEpoch, "error", merr)
	}
	return nil
}
