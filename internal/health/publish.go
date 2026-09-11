package health

import (
	"context"
	"errors"
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
// one is a libvirt error. PublishVMRunning's state gate guarantees that.
//
// Both writes are ALWAYS attempted, and the commit is refused only when the VM
// ends up with no marker at all. Neither half is a precondition for the other:
//
//   - Returning early on the domain write would skip the FILE marker, which is
//     the durable one — undefining a domain destroys its metadata with it, so a
//     metadata-only marker is unreadable exactly when it is needed. The
//     hand-rolled write-through this replaced warned on the domain write and
//     wrote the file marker anyway; short-circuiting would have left a VM with
//     NEITHER marker where the old code left the one that survives.
//   - Making either one individually fatal wedges the host. The file marker is a
//     real filesystem write — MkdirAll, CreateTemp, rename — so a full or
//     read-only data volume fails it PERSISTENTLY, and a refused publish leaves
//     the row "stopped" while the guest runs, with the self-heal that would fix
//     it routed through this same chokepoint and refusing for the same reason.
//     Unrecoverable, and visible only as one log line per attempt.
//
// So: one marker is enough to publish. A single failure is warned about and
// repaired by convergeOwnerEpochMarker, which fires for any confirmed-running VM
// regardless of the enforcement flag. Both failing means the VM genuinely cannot
// prove anything, and that is what mark-then-commit exists to refuse.
func writeBothMarkers(virt DomainEpochSetter, dataDir, name string, epoch int64) (partial error, fatal error) {
	if epoch < 1 {
		return nil, nil
	}
	var domErr, fileErr error
	domAttempted, fileAttempted := false, false

	if usable(virt) {
		domAttempted = true
		if err := virt.SetDomainOwnerEpoch(name, epoch, true); err != nil {
			domErr = fmt.Errorf("owner-epoch domain marker for %q at generation %d: %w", name, epoch, err)
		}
	}
	// Skipped rather than written to a relative path: readVMMarker treats an
	// empty dataDir as MarkerMissing, so such a marker is one no reader resolves.
	if dataDir != "" {
		fileAttempted = true
		if err := WriteVMOwnerEpochMarker(dataDir, name, epoch); err != nil {
			fileErr = fmt.Errorf("owner-epoch file marker for %q at generation %d: %w", name, epoch, err)
		}
	}

	landed := (domAttempted && domErr == nil) || (fileAttempted && fileErr == nil)
	if !landed && (domAttempted || fileAttempted) {
		return nil, errors.Join(domErr, fileErr)
	}
	return errors.Join(domErr, fileErr), nil
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
	partial, fatal := writeBothMarkers(virt, dataDir, name, epoch)
	if fatal != nil {
		return fatal
	}
	if partial != nil {
		slog.Warn("publish: one owner-epoch marker did not land before a running commit — "+
			"publishing on the strength of the other and leaving the gap to convergence, "+
			"because refusing would wedge this host's rows while its guests run",
			"vm", name, "epoch", epoch, "error", partial)
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
// A failed READ-BACK is likewise NOT returned. It happens AFTER the commit has
// landed, so there is nothing to undo and nothing the caller can retry — and
// three of the four call sites treat any error as "the write did not land" and
// abort the rest of their sequence. That cost a promotion its disk re-point, and
// repair-owner and owner-assert their audit records, for ownership changes that
// had actually succeeded. Convergence repairs an unmarked running VM; it cannot
// reconstruct the durable writes an aborted caller skipped.
func PublishVMRunningMinted(ctx context.Context, virt DomainEpochSetter, db *corrosion.Client, dataDir, hostName, name string, commit func(context.Context) error) error {
	if err := commit(ctx); err != nil {
		return err
	}
	row, err := corrosion.GetVM(ctx, db, name)
	if err != nil || row == nil {
		slog.Warn("publish: owner-epoch read-back failed after a minting transition — the commit "+
			"HAS landed, so this is reported as an unmarked VM for convergence to repair "+
			"rather than as a failed transition",
			"vm", name, "error", err)
		return nil
	}
	if hostName != "" && row.HostName != hostName {
		slog.Warn("publish: ownership moved during a minting transition — leaving the markers to the new owner",
			"vm", name, "epoch", row.OwnerEpoch, "owner", row.HostName, "self", hostName)
		return nil
	}
	if fileErr, fatal := writeBothMarkers(virt, dataDir, name, row.OwnerEpoch); fileErr != nil || fatal != nil {
		slog.Warn("publish: markers not written after a minting transition — convergence will repair",
			"vm", name, "epoch", row.OwnerEpoch, "file_error", fileErr, "error", fatal)
	}
	return nil
}

// RowForPublish reads the row a running publish will stamp a marker from,
// retried with the same 4-attempt/backoff policy as the state writes it guards.
//
// Retried because several callers only log a failed state write and continue:
// an unretried read in front of such a write turns one transient SQLITE_BUSY
// into a DROPPED transition, which the code being routed did not do.
//
// A read that SUCCEEDS and finds no row returns immediately — the row is gone,
// and retrying cannot conjure one. A read that never succeeds refuses the
// transition rather than falling back to epoch 0: a successful read of 0 is a
// pre-epoch row, a failed read is nothing at all, and treating them alike makes
// the chokepoint a no-op exactly under the conditions it exists for.
func RowForPublish(ctx context.Context, db *corrosion.Client, name string) (*corrosion.VMRecord, error) {
	return rowForPublish(ctx, name, func(ctx context.Context) (*corrosion.VMRecord, error) {
		return corrosion.GetVM(ctx, db, name)
	})
}

// rowForPublish is RowForPublish's policy over an injectable read, so the retry
// is testable without a fault hook on the shared corrosion client.
func rowForPublish(ctx context.Context, name string, read func(context.Context) (*corrosion.VMRecord, error)) (*corrosion.VMRecord, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var row *corrosion.VMRecord
		if row, err = read(ctx); err == nil {
			if row == nil {
				// Wrapped so the routed callers' concurrent-delete branches keep
				// working: they test errors.Is(err, corrosion.ErrNoRowsAffected)
				// to tell "the row vanished" from "the write faulted".
				return nil, fmt.Errorf("owner-epoch lookup before publishing %q running: no row: %w",
					name, corrosion.ErrNoRowsAffected)
			}
			return row, nil
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return nil, fmt.Errorf("owner-epoch lookup before publishing %q running: %w", name, err)
}

// ErrOwnershipMoved reports that the row a publish was about to mark names a
// different host. Callers treat it as "not mine to publish", not as a fault.
var ErrOwnershipMoved = errors.New("ownership moved to another host before the publish")

// PublishRunningVia routes a NON-MINTING transition for a caller that holds its
// own virt/dataDir/db. A non-running state passes straight through, costing no
// row read and — more importantly — never gating a stop on a running-marker
// write it would fail.
// The row must still name hostName. A publish reached from a list snapshot taken
// seconds earlier can find that ownership has already moved, and stamping the
// CURRENT epoch onto THIS host's runtime would then make a superseded runtime
// look current: runtimeSuperseded decides by `row.OwnerEpoch > marker`, so a
// marker equal to the row reads as up to date. That is the one direction of this
// race that is not fail-safe, and it defeats the marker comparison for exactly
// the split-ownership case it exists for. Publishing a row another host owns
// would also be a stale write in its own right, so the whole transition is
// refused rather than merely left unmarked.
func PublishRunningVia(ctx context.Context, virt DomainEpochSetter, db *corrosion.Client, dataDir, hostName, name, state string, commit func(context.Context) error) error {
	if state != "running" {
		return commit(ctx)
	}
	row, err := RowForPublish(ctx, db, name)
	if err != nil {
		return err
	}
	if hostName != "" && row.HostName != hostName {
		return fmt.Errorf("refusing to publish %q running on %q: %w (row names %q at generation %d)",
			name, hostName, ErrOwnershipMoved, row.HostName, row.OwnerEpoch)
	}
	return PublishVMRunning(ctx, virt, dataDir, name, state, row.OwnerEpoch, commit)
}
