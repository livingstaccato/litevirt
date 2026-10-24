package health

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ErrStartDeferred marks a start-preparation answer that is not a failure:
// the start has to wait — its storage did not answer (Ceph re-electing its
// monitors during the very event that caused a failover), or the walk has no
// time left to ask it. The hooks wired with SetHardwareStartPreparer and
// SetStartDeferral return an error that errors.Is this.
//
// A deferred start is never parked in error, whatever it is: a proof-less
// LOCAL recovery (onboot autostart, a running row whose domain is gone, an
// interrupted start) waits in "starting", which reconcile re-drives, and a
// failover keeps its proof in_progress, back in "pending"
// (deferPendingStart). The VM is walked first on the next pass.
var ErrStartDeferred = errors.New("start deferred")

// ErrStartStorageNotMounted marks a start-preparation refusal because a
// disk's NFS export is not mounted on this host (grpcapi's NFS start hook).
// It is a refusal, not a deferral; it is counted under
// ReasonStorageNotMounted.
var ErrStartStorageNotMounted = errors.New("a disk's storage is not mounted on this host")

// Why a start was deferred decides where it goes in the next walk
// (deferredFirst). A plain ErrStartDeferred is a deferral for TIME — the walk
// had too little left to ask the storage at all — and goes first: it never
// had its chance. The two below are deferrals because the storage did not
// answer; both errors.Is ErrStartDeferred too.
var (
	// ErrStartStorageDown: a probe of the same storage (another VM's) did
	// not answer within about the last pass, so this VM was deferred
	// without asking it again.
	ErrStartStorageDown error = &deferKind{"start deferred: its storage did not answer a probe", rankStorageDown}
	// ErrStartProbeFailed: this VM's own probe did not get an answer.
	ErrStartProbeFailed error = &deferKind{"start deferred: its storage did not answer its probe", rankProbeFailed}
	// ErrStartHostUnfit: this host cannot run the VM as it is set up now —
	// an access-VLAN NIC's bridge here does not filter VLANs — and an
	// operator's fix of the host is what it waits for. The start is tried
	// again every pass, after every VM that is not deferred, so it starts by
	// itself once the host is fixed and never spends the walk's budget
	// ahead of a VM that can start.
	ErrStartHostUnfit error = &deferKind{"start deferred: this host cannot run it until the host is fixed", rankHostUnfit}
)

// The walk order of deferred starts: for time, then storage down, then a VM
// whose own probe failed — last of the deferred, so a VM whose storage keeps
// failing never holds the head of the walk and spends the budget the VMs on
// healthy storage behind it need — and then every VM that was not deferred,
// and last a VM this host cannot run until it is fixed.
const (
	rankTime = iota
	rankStorageDown
	rankProbeFailed
	rankNotDeferred
	// rankHostUnfit goes after every VM not deferred (ErrStartHostUnfit).
	rankHostUnfit
)

type deferKind struct {
	msg  string
	rank int
}

func (k *deferKind) Error() string { return k.msg }

// Is makes every kind of deferral a deferral.
func (k *deferKind) Is(target error) bool { return target == ErrStartDeferred }

// deferralRank is where a start deferred with err goes in the next walk.
func deferralRank(err error) int {
	var k *deferKind
	if errors.As(err, &k) {
		return k.rank
	}
	return rankTime
}

// A reconcile pass's walk carries ONE probe turn (WithWalkProbeTurn): the
// first storage probe asked for in the walk may run however little time is
// left — bounded by it — so every pass makes progress on proving a key,
// even one whose walk starts late. Every later probe needs its full bound.
type walkProbeTurn struct{ spent atomic.Bool }

type walkProbeTurnKey struct{}

// WithWalkProbeTurn marks ctx as a reconcile walk's, with its one probe turn.
func WithWalkProbeTurn(ctx context.Context) context.Context {
	return context.WithValue(ctx, walkProbeTurnKey{}, &walkProbeTurn{})
}

// InReconcilerWalk reports whether ctx is a reconcile walk's: only there is
// a remembered storage failure a reason to defer a start without asking.
func InReconcilerWalk(ctx context.Context) bool {
	_, ok := ctx.Value(walkProbeTurnKey{}).(*walkProbeTurn)
	return ok
}

// WalkProbeTurnFree reports, without spending it, whether ctx's walk still
// has its probe turn.
func WalkProbeTurnFree(ctx context.Context) bool {
	t, ok := ctx.Value(walkProbeTurnKey{}).(*walkProbeTurn)
	return ok && !t.spent.Load()
}

// TakeWalkProbeTurn spends ctx's walk's probe turn; true if it was free.
// Outside a walk there is none.
func TakeWalkProbeTurn(ctx context.Context) bool {
	t, ok := ctx.Value(walkProbeTurnKey{}).(*walkProbeTurn)
	return ok && t.spent.CompareAndSwap(false, true)
}

// startDeferredSet is the VMs whose start was deferred since the last walk
// began, each with its rank (deferralRank): the next walk takes them first,
// in rank order, so the same VMs — late in the walk's fixed order, behind a
// slow one — are not deferred on every pass.
type startDeferredSet struct {
	mu sync.Mutex
	m  map[string]int
}

func (s *startDeferredSet) add(name string, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]int{}
	}
	s.m[name] = deferralRank(cause)
}

// take returns the set and empties it: a VM deferred again re-enters it.
func (s *startDeferredSet) take() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.m
	s.m = nil
	return m
}

// SetStartDeferral wires the check the reconciler makes BEFORE it does any
// work for a VM's start — its lock, a proof's claim, the define: an answer
// that errors.Is ErrStartDeferred leaves the VM exactly as it is, to be walked
// first on the next pass. The daemon wires the Server's CephStartDeferral (a
// VM whose ceph key must be proven, with less time left than that takes).
// nil — unwired — defers nothing.
func (r *Reconciler) SetStartDeferral(fn func(ctx context.Context, vm *corrosion.VMRecord) error) {
	r.startDeferral = fn
}

// deferredBeforeWork reports whether vm's start is deferred before any work
// for it, remembering it to walk first if so.
func (r *Reconciler) deferredBeforeWork(ctx context.Context, vm corrosion.VMRecord) bool {
	if r.startDeferral == nil {
		return false
	}
	err := r.startDeferral(ctx, &vm)
	if err == nil || !errors.Is(err, ErrStartDeferred) {
		return false
	}
	slog.Info("reconciler: start deferred to the next pass, where it goes first", "vm", vm.Name, "reason", err)
	r.startDeferred.add(vm.Name, err)
	return true
}

// deferStart records a start the preparation deferred (ErrStartDeferred):
// re-armed with deferPendingStart — "pending" with its proof, "starting"
// without — and walked first on the next pass. A proof-less transfer is
// remembered as one (deferredTransfers), as for an image still in transit.
func (r *Reconciler) deferStart(ctx context.Context, vmName, proofID string, transfer bool, cause error) {
	slog.Info("reconciler: start deferred; the next pass re-drives it first", "vm", vmName, "reason", cause)
	if transfer && proofID == "" {
		r.deferredTransfers.add(vmName)
	}
	r.startDeferred.add(vmName, cause)
	r.deferPendingStart(ctx, vmName, proofID, "start deferred: "+cause.Error())
}

// walkOrder is the order a reconcile pass walks this host's VMs in: the
// deferred starts first, by rank (deferredFirst), and within each group the
// highest compose migrate.priority first, ties by name. A failover lands its
// VMs here as "pending", so this is the order they start in on their new
// host, and the walk's time budget runs out on the lowest priority. It only
// orders the walk: every start still passes its own gates.
//
// Follow-up (predates priority ordering): a start reached after the budget
// has run out fails its lock and is NOT recorded in startDeferred, so a slow
// start that spends the budget every pass keeps starving the same tail —
// now the lowest priorities, before the replica's last-inserted rows.
// Recording it at rankTime when ctx is already done at startPendingVM's entry
// would rotate the starved set to the front of the next pass.
func walkOrder(vms []corrosion.VMRecord, deferred map[string]int) []corrosion.VMRecord {
	return deferredFirst(corrosion.SortVMsByMigratePriority(vms), deferred)
}

// deferredFirst orders a walk's VMs with the deferred ones first, by rank
// (for time, storage down, own probe failed), then the rest; each group in
// the walk's own order.
func deferredFirst(vms []corrosion.VMRecord, deferred map[string]int) []corrosion.VMRecord {
	if len(deferred) == 0 {
		return vms
	}
	rank := func(name string) int {
		if rk, ok := deferred[name]; ok {
			return rk
		}
		return rankNotDeferred
	}
	out := append([]corrosion.VMRecord(nil), vms...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Name) < rank(out[j].Name) })
	return out
}
