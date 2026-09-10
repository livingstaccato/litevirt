package health

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"time"

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
//
// Only ever called for a RUNNING publish, which is why the domain write takes
// running=true: LIVE|CONFIG needs a live domain, and LIVE against an inactive
// one is a libvirt error. PublishVMRunning's state gate is what guarantees that.
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
// state is the state being published, and markers are written ONLY for
// "running". Several call sites write a state that is dynamic at the call but
// provably never "running" (classifyStop's output, a drift heal toward
// libvirt), and one of them is genuinely either. Taking the state here makes a
// uniform wrap correct everywhere instead of making each caller prove its own
// branch — and it keeps SetDomainOwnerEpoch's LIVE flag off inactive domains,
// where libvirt rejects it.
//
// epoch must be a value the caller READ SUCCESSFULLY. A caller that cannot read
// the row must refuse its transition rather than pass 0: a successful read of 0
// is a pre-epoch row, a failed read is nothing at all, and treating them alike
// turns this into a no-op exactly when the store is unhealthy — under the
// conditions it exists for. A caller whose read is the only thing standing
// between a transient store error and a dropped write retries that read with
// the same policy as the write it guards.
func PublishVMRunning(ctx context.Context, virt DomainEpochSetter, dataDir, name, state string, epoch int64, commit func(context.Context) error) error {
	if state != "running" {
		return commit(ctx)
	}
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
//
// hostName is this host, and the read-back row must still name it. A second
// ownership transition landing between our commit and our read gives us the
// NEXT owner's generation, and stamping our own runtime with it would make a
// superseded runtime look current — the one direction of this race that is not
// fail-safe. (The other direction, a marker lagging the row, is exactly what
// runtimeSuperseded should see when ownership has genuinely moved.) When the
// row has moved on we write nothing: the new owner's convergence marks its own
// runtime, and ours is no longer the one the generation describes.
func PublishVMRunningMinted(ctx context.Context, virt DomainEpochSetter, db *corrosion.Client, dataDir, hostName, name string, commit func(context.Context) error) error {
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
	if hostName != "" && row.HostName != hostName {
		slog.Warn("publish: ownership moved during a minting transition — leaving the markers to the new owner",
			"vm", name, "epoch", row.OwnerEpoch, "owner", row.HostName, "self", hostName)
		return nil
	}
	if merr := writeBothMarkers(virt, dataDir, name, row.OwnerEpoch); merr != nil {
		slog.Warn("publish: markers not written after a minting transition — convergence will repair",
			"vm", name, "epoch", row.OwnerEpoch, "error", merr)
	}
	return nil
}

// EpochForPublish reads the generation a running publish will stamp, retried
// with the same 4-attempt/backoff policy the state writes it guards use.
//
// Retried because several callers only log a failed state write and continue:
// an unretried read in front of such a write turns one transient SQLITE_BUSY
// into a DROPPED transition, which the code being routed did not do.
//
// A read that SUCCEEDS and finds no row returns immediately — the row is gone,
// and retrying cannot conjure one. A read that never succeeds refuses the
// transition rather than falling back to 0: a successful read of 0 is a
// pre-epoch row, a failed read is nothing at all, and treating them alike makes
// the chokepoint a no-op exactly under the conditions it exists for.
func EpochForPublish(ctx context.Context, db *corrosion.Client, name string) (int64, error) {
	return epochForPublish(ctx, name, func(ctx context.Context) (*corrosion.VMRecord, error) {
		return corrosion.GetVM(ctx, db, name)
	})
}

// epochForPublish is EpochForPublish's policy over an injectable read, so the
// retry is testable without a fault hook on the shared corrosion client.
func epochForPublish(ctx context.Context, name string, read func(context.Context) (*corrosion.VMRecord, error)) (int64, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var row *corrosion.VMRecord
		if row, err = read(ctx); err == nil {
			if row == nil {
				return 0, fmt.Errorf("owner-epoch lookup before publishing %q running: no row", name)
			}
			return row.OwnerEpoch, nil
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return 0, fmt.Errorf("owner-epoch lookup before publishing %q running: %w", name, err)
}

// PublishRunningVia routes a NON-MINTING transition for a caller that holds its
// own virt/dataDir/db. A non-running state passes straight through, costing no
// row read and — more importantly — never gating a stop on a running-marker
// write it would fail.
func PublishRunningVia(ctx context.Context, virt DomainEpochSetter, db *corrosion.Client, dataDir, name, state string, commit func(context.Context) error) error {
	if state != "running" {
		return commit(ctx)
	}
	epoch, err := EpochForPublish(ctx, db, name)
	if err != nil {
		return err
	}
	return PublishVMRunning(ctx, virt, dataDir, name, state, epoch, commit)
}
