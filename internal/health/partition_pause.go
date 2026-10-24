package health

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Partition pause, the minority side (docs/design/partition-pause.md §3).
//
// A host that cannot see a majority of the voter set — the execution quorum,
// the one that may fence it and recover its workloads — for T_pause suspends
// every VM and freezes every container the majority would recover elsewhere.
// With partition_pause_v1 latched the majority waits PartitionPauseWait from
// its fence decision before it starts a replacement (internal/failover), and
// records the fence as self_paused rather than assumed. A host comes back
// paused and resumes only on a majority's confirmation that nothing moved its
// workloads; a copy a certified claim gave away is stopped by Layer 3
// (settle.go).

// Timing (docs/design/partition-pause.md §4.1). Constants, not config: the
// majority computes its wait from the same values the minority runs on, and a
// per-node knob would break that contract on the first node set differently.
// TestPartitionPauseWaitCoversTheMinority pins the inequality against them.
const (
	// PartitionPauseAfter is T_pause: how long the execution quorum must stay
	// lost, continuously, before this host pauses. It is the time the majority
	// needs to build its own fence verdict (FailuresToFence probes), so a loss
	// shorter than that would never have been fenced and pausing for it buys
	// nothing.
	PartitionPauseAfter = FailuresToFence * checkInterval
	// partitionPauseTick is the pauser's evaluation period.
	partitionPauseTick = time.Second
	// PartitionPauseExecBudget bounds executing every pause in one pass.
	PartitionPauseExecBudget = 5 * time.Second
	// partitionPauseCallTimeout bounds one suspend or freeze.
	partitionPauseCallTimeout = 2 * time.Second
	// markWaitBoundDefault: how long a clear waits for its own mark write,
	// well past libvirt's 30 s job wait.
	markWaitBoundDefault = 2 * time.Minute
	// partitionPauseSlack covers scheduling and monotonic-clock rate error.
	partitionPauseSlack = 2 * time.Second
	// PartitionResumeStepBound is R: the longest one step of a healed pass
	// (one pending-settle retry, one record's checks and settle, the majority
	// confirmation, or one resume) runs. The pass reads the quorum between
	// steps and after its last resume, so R is the longest a healed host goes
	// without a quorum reading; a step that does not finish in R is abandoned
	// and its workload stays paused for a later pass. The majority's wait
	// counts it (§4.1).
	PartitionResumeStepBound = 3 * time.Second
	// PartitionPauseMargin is what the majority adds to T_pause for a cluster
	// of up to probeConcurrency+1 hosts (one probe batch);
	// PartitionPauseMarginFor scales it.
	PartitionPauseMargin = max(0, (suspectThreshold+1)*max(checkInterval, checkTimeout)-(FailuresToFence-1)*checkInterval) +
		2*partitionPauseTick + PartitionResumeStepBound + PartitionPauseExecBudget + partitionPauseSlack
	// PartitionPauseWait is W for a cluster of up to probeConcurrency+1 hosts.
	PartitionPauseWait = PartitionPauseAfter + PartitionPauseMargin
	// partitionResumeRecheck spaces the majority confirmation while a resume
	// is held, so a host left fenced does not fan out to every voter each tick.
	partitionResumeRecheck = 5 * time.Second
)

// probeCycleFor is C(n): the longest one probe cycle takes with n probe
// targets while they time out. A cycle waits for its slowest probe, with at
// most probeConcurrency in flight, and starts no sooner than checkInterval
// after the last.
func probeCycleFor(targets int) time.Duration {
	batches := (targets + probeConcurrency - 1) / probeConcurrency
	if batches < 1 {
		batches = 1
	}
	return max(checkInterval, time.Duration(batches)*checkTimeout)
}

// minorityDetectBoundFor is D_M(n): from the moment a link to a quorum
// observer breaks, the longest until a host probing n targets no longer counts
// that observer healthy. The next cycle starts within one cycle and each later
// one within one more; the suspectThreshold-th failure completes by the end of
// its own cycle.
func minorityDetectBoundFor(targets int) time.Duration {
	return (suspectThreshold + 1) * probeCycleFor(targets)
}

// PartitionPauseMarginFor is what the majority adds to T_pause when the
// minority may be probing `targets` peers (docs/design/partition-pause.md
// §4.1, §4.4). The fence decision rests on quorum observers each with
// FailuresToFence consecutive failures, so every one of their links broke at
// least (FailuresToFence-1) probe intervals before it: only the part of the
// minority's detection beyond that head start remains, plus two tick
// quantisations, one resume step during which the minority takes no quorum
// reading (R), the pauses themselves and slack.
func PartitionPauseMarginFor(targets int) time.Duration {
	return max(0, minorityDetectBoundFor(targets)-(FailuresToFence-1)*checkInterval) +
		2*partitionPauseTick + PartitionResumeStepBound + PartitionPauseExecBudget + partitionPauseSlack
}

// PartitionPauseWaitFor is W(n): how long after its fence decision the majority
// waits before it starts a replacement for a host it relies on pausing, when
// that host may be probing `targets` peers. The coordinator passes
// max(adopted voter generation, newest generation, non-maintenance hosts) - 1.
func PartitionPauseWaitFor(targets int) time.Duration {
	return PartitionPauseAfter + PartitionPauseMarginFor(targets)
}

// PauseVMBackend is the slice of the libvirt client the pauser drives.
type PauseVMBackend interface {
	ListDomains() ([]string, error)
	DomainStateReason(name string) (lv.DomainStatus, error)
	// DumpXMLInactive gives the domain's UUID, recorded with the pause so a
	// record is trusted only for the very domain it paused.
	DumpXMLInactive(name string) (string, error)
	SuspendDomain(name string) error
	// ResumePartitionPaused resumes a guest this pauser paused, bound to
	// the domain uuid the pause recorded ("" when it recorded none). The
	// firmware move guard lets it through under a live firmware move's
	// marker only while that move is in progress before cutover; under any
	// parked marker, or from cutover on, it refuses, and the guest stays
	// paused until the move's own steps resume it (spec §5.1, §10).
	ResumePartitionPaused(name, uuid string) error
	// KillPartitionPaused SIGKILLs the domain's QEMU process directly, by
	// libvirt's pid file and the process's own command line (its -uuid, or
	// its guest name when uuid is ""), never through libvirt: it is the stop
	// for a domain whose resume is still out in a libvirt call that may never
	// return, and that must not land. nil when no such process runs any more.
	KillPartitionPaused(name, uuid string) error
	// MarkPartitionPaused puts a live-only mark carrying token on the
	// running domain, just before the pauser suspends it; the pauser resumes
	// only a paused domain that still carries its record's token, and
	// ClearPartitionPauseMark removes the mark before the resume.
	// PartitionPauseMark reads it (ok=false: no mark).
	MarkPartitionPaused(name, token string) error
	PartitionPauseMark(name string) (token string, ok bool, err error)
	ClearPartitionPauseMark(name string) error
}

// Read kinds the pauser's abandoned-call guard tracks (callGuard).
const (
	readListDomains = "ListDomains"
	readDomainState = "DomainStateReason"
	readDomainXML   = "DumpXMLInactive"
	readPauseMark   = "PartitionPauseMark"
)

// callGuard admits one call of each kind at a time. A libvirt call can hang
// (a wedged qemu monitor or libvirtd), and the majority's wait assumes the
// pause pass ends within PartitionPauseExecBudget, so guardedCall abandons a
// call that times out, still running in its own goroutine. Against a wedged
// libvirtd every later pass would abandon another, one per tick per domain,
// for as long as the partition lasts. Under the guard a kind whose last call
// has not returned fails at once instead, so a wedged libvirtd holds at most
// one goroutine per kind.
type callGuard struct {
	mu   sync.Mutex
	busy map[string]bool
}

func (g *callGuard) acquire(kind string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy[kind] {
		return false
	}
	if g.busy == nil {
		g.busy = map[string]bool{}
	}
	g.busy[kind] = true
	return true
}

func (g *callGuard) release(kind string) {
	g.mu.Lock()
	delete(g.busy, kind)
	g.mu.Unlock()
}

// guardedCall runs fn with a deadline under g: a call of kind is refused while
// an earlier one has not returned. A nil g guards nothing. A timeout of zero
// or less (no pass budget left) refuses the call outright.
func guardedCall[T any](g *callGuard, kind string, timeout time.Duration, fn func() (T, error)) (T, error) {
	var zero T
	if timeout <= 0 {
		return zero, errPassBudget
	}
	if g != nil && !g.acquire(kind) {
		return zero, fmt.Errorf("an earlier %s call has not returned yet", kind)
	}
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := fn()
		if g != nil {
			g.release(kind) // before the result: the caller's next call must find it free
		}
		ch <- res{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(timeout):
		return zero, fmt.Errorf("%w within %v", errCallTimeout, timeout)
	}
}

// errCallTimeout is a call abandoned at its deadline (guardedCall,
// callWithin).
var errCallTimeout = errors.New("did not return")

// errPassBudget is a read the pause pass had no budget left for.
var errPassBudget = errors.New("the pause pass ran out of its budget before this read")

// passBudget bounds the reads of one pause pass. Reads end by readsBy, so
// that the pause calls they lead to — each bounded by
// partitionPauseCallTimeout, all running at once — end within
// PartitionPauseExecBudget (E) of the pass's start, however many workloads
// there are and however slowly libvirt or LXC answers.
type passBudget struct{ readsBy time.Time }

func newPassBudget() passBudget {
	return passBudget{readsBy: time.Now().Add(PartitionPauseExecBudget - partitionPauseCallTimeout)}
}

// timeout is the bound for the next read: the per-call timeout, cut to what
// is left of the pass. Zero or less means no budget is left.
func (b passBudget) timeout() time.Duration {
	return min(partitionPauseCallTimeout, time.Until(b.readsBy))
}

// holdWait is how long a pause may wait on a memory snapshot capture
// (CaptureRegistry.Hold) before its suspend: captureWait, cut so that the
// suspend after it (bounded by partitionPauseCallTimeout) still ends within
// E. It is taken from the time left for reads, not added to the pass: a wait
// the budget cannot hold makes the pause count as failed instead of landing
// late and unreported.
func (b passBudget) holdWait() time.Duration {
	return max(0, min(captureWait, time.Until(b.readsBy)))
}

// recordBound is how long a pause waits for its record: min(2s, what is
// left of the pass), and never less than pauseRecordWriteFloor.
func (b passBudget) recordBound() time.Duration {
	return max(pauseRecordWriteFloor, min(pauseRecordWriteBound, b.timeout()))
}

// frozenStater is the optional container-runtime capability to tell a FROZEN
// container from a running one (lxc.Runtime.State folds frozen into running).
// Without it a container an operator froze is indistinguishable from one
// running, and is treated as running.
type frozenStater interface {
	IsFrozen(ctx context.Context, name string) (bool, error)
}

// ResumeVerdict is the majority's answer for one record.
type ResumeVerdict struct {
	OK     bool
	Reason string
}

// ResumeConfirmer asks the voter set whether each record may resume
// (docs/design/partition-pause.md §3.5 step 4). Keyed by PauseRecord.Key. A
// record missing from the result is not confirmed. Wired to
// grpcapi.Server.ConfirmPartitionResume.
type ResumeConfirmer func(ctx context.Context, recs []PauseRecord) map[string]ResumeVerdict

// VoterAnswer is one voter's reply to the resume check.
type VoterAnswer struct {
	Voter string
	// Err is set when the voter did not answer in full (unreachable, refused,
	// an older build). It is not an answer.
	Err error
	// HostDown: the voter's replica has the asking host fenced or offline.
	HostDown  bool
	HostState string
	// Accepted maps a record key to a description of a recovery-claim value
	// this voter has accepted for it at the recorded epoch and incarnation.
	Accepted map[string]string
	// Rows maps a record key to the voter's own row for the workload.
	Rows map[string]RowView
}

// RowView is one voter's row for a paused workload.
type RowView struct {
	Live        bool
	Host        string
	OwnerEpoch  int64
	Incarnation string
}

// DecideResume decides one record from the voters' answers: needOthers clean
// answers from voters other than this host, and no answer that says this host
// is down or that a claim to move the workload was accepted. Any two
// majorities of one voter set intersect (§3.5), so needOthers is the size that
// makes the answering set, with this host, a majority.
func DecideResume(rec PauseRecord, answers []VoterAnswer, needOthers int) ResumeVerdict {
	clean := 0
	var errs []string
	for _, a := range answers {
		if a.Err != nil {
			errs = append(errs, a.Voter+": "+a.Err.Error())
			continue
		}
		if a.HostDown {
			return ResumeVerdict{Reason: fmt.Sprintf("voter %s has %s %s", a.Voter, rec.Host, a.HostState)}
		}
		if dest, ok := a.Accepted[rec.Key()]; ok {
			return ResumeVerdict{Reason: fmt.Sprintf("voter %s accepted a recovery claim moving %s to %s at epoch %d",
				a.Voter, rec.Key(), dest, rec.OwnerEpoch)}
		}
		row, ok := a.Rows[rec.Key()]
		if !ok {
			errs = append(errs, a.Voter+": no row view")
			continue
		}
		switch {
		case !row.Live:
			return ResumeVerdict{Reason: fmt.Sprintf("voter %s has no live row for %s", a.Voter, rec.Key())}
		case row.Host != rec.Host || row.OwnerEpoch != rec.OwnerEpoch || row.Incarnation != rec.Incarnation:
			return ResumeVerdict{Reason: fmt.Sprintf("voter %s has %s on %s at epoch %d (incarnation %s); the pause recorded %s at epoch %d",
				a.Voter, rec.Key(), row.Host, row.OwnerEpoch, row.Incarnation, rec.Host, rec.OwnerEpoch)}
		}
		clean++
	}
	if clean < needOthers {
		why := fmt.Sprintf("only %d of the %d voter answers a majority needs", clean, needOthers)
		if len(errs) > 0 {
			why += " (" + strings.Join(errs, "; ") + ")"
		}
		return ResumeVerdict{Reason: why}
	}
	return ResumeVerdict{OK: true, Reason: fmt.Sprintf("majority regained; %d voters confirm %s owns %s at epoch %d",
		clean, rec.Host, rec.Key(), rec.OwnerEpoch)}
}

// PartitionPauser is the minority-side monitor.
type PartitionPauser struct {
	host    string
	db      *corrosion.Client
	store   pauseStore
	dataDir string
	// settleFault fails a settle record write (tests; settle_pending.go).
	settleFault    func(step string) error
	settleRecOnce  sync.Once
	settleRecorder *settleRecorder

	quorum  func(context.Context) (QuorumState, int, int)
	enabled func() bool
	vms     PauseVMBackend
	cts     lxc.Runtime
	// ctCapable reports whether this host has a container runtime at all. The
	// adapter is wired everywhere, so on a host without the lxc-* tooling every
	// list fails at the binary lookup — and that host has nothing to freeze.
	ctCapable func() bool
	confirm   ResumeConfirmer
	settle    SettleVerifier
	// peerRuntime asks a peer's own LXC runtime about a container
	// (grpcapi.Server.CheckPeerContainerRuntime), for container settle.
	peerRuntime func(ctx context.Context, host, name string) (string, error)
	// settleProofs replaces corrosion.CertifiedTransferProofs (tests).
	settleProofs func(ctx context.Context, c *corrosion.Client, kind, name string) ([]corrosion.ProofRecord, error)
	armed        func() bool
	selfFence    func()
	// recordMode is enforcement.partition_pause_record_failure: what a pause
	// whose record cannot be written does (partition_pause_reserve.go).
	recordMode string
	reserveWhy string // the last reserve error logged, "" once it exists
	keeping    bool   // a keepRecords run has not returned yet
	now        func() time.Time
	after      time.Duration
	tick       time.Duration
	// resumeCursor is the Key of the last record a resume pass took on; the
	// next pass starts after it (rotateAfter). resumeLoopCursor is the same
	// for the resumes themselves, so a resume that fails slowly on every pass
	// is not tried first on every pass. Only the pauser's own loop touches
	// them.
	resumeCursor     string
	resumeLoopCursor string
	progress         atomic.Uint64 // Progress

	mu sync.Mutex
	// samples are this pass's and earlier passes' quorum readings inside the
	// last 2·T_pause, on the local monotonic clock; yesSince is the first
	// reading of the current unbroken run of Yes readings, zero while the
	// last reading was not Yes. A restart re-earns both, deliberately.
	samples  []lossSample
	yesSince time.Time
	// sawYes / sawNo: whether this run has read the quorum as Yes, or as
	// No, at all. Unknown readings before the first Yes are the checker's
	// startup warmup unless a No came with them (§3.1).
	sawYes, sawNo bool
	// reads guards the abandoned libvirt reads, one call per kind (callGuard).
	reads callGuard
	// inflight marks the workloads whose pause, resume or settle stop call
	// has not returned yet (a timed-out call is abandoned, not cancelled): no
	// second call is issued. resuming marks those among them whose call is a
	// resume, which may yet land: a pause pass cannot promise a suspend of
	// such a workload comes after it, so it kills a VM's QEMU instead
	// (killInFlightResumes), and reports the pause failed when it cannot (a
	// container, or a kill that fails) until the call returns.
	inflight map[string]bool
	resuming map[string]bool
	// killed marks the VMs among resuming whose QEMU a pause pass has
	// killed (killInFlightResumes): the abandoned resume can no longer land,
	// so the VM counts as stopped until the call returns.
	killed     map[string]bool
	failed     map[string]string // key → error, this loss episode
	failedOpen bool
	pausedEvid string // evidence last written to partition_paused, "" when resolved
	pausedOpen bool
	// pausedSynced: this process has seen the replicated partition_paused
	// row resolved or absent, or resolved it itself. Until then a pass with
	// no record checks the row, since an earlier process may have left it
	// open (a restart, or a power cycle while paused).
	pausedSynced bool
	lastConfirm  time.Time
	heldWhy      map[string]string // key → last logged hold reason
	// notOurs: key → why, for a record whose VM something other than this
	// host's pause has paused (an operator, an I/O error). Held, and named
	// in partition_paused's evidence.
	notOurs map[string]string
	// markFailed: key → the token of this host's pause whose mark could not
	// be set, so its hold says so instead of blaming someone else.
	markFailed map[string]string
	// markPending: key → the token of this host's pause whose mark is still
	// being written (libvirt can be slow): not yet set, not failed.
	markPending map[string]string
	// markWritten: key/token → closed once that pause's mark write returns
	// (set or failed), for a clear of that token to wait on.
	markWritten map[string]chan struct{}
	// clearWanted: key/token of a mark whose clear gave up waiting for its
	// write; markPaused takes it off once the write returns.
	clearWanted map[string]bool
	// markWaitBound caps how long a clear waits for its own mark write
	// (markWaitBoundDefault; tests shorten it).
	markWaitBound time.Duration
	// clearing: name/token of each mark a background clear is taking off.
	clearing map[string]bool
	// markLocks serialise every mark write and clear of one VM, so a slow
	// clear can never land after, and erase, a newer pause's mark.
	markLocks map[string]*sync.Mutex
	exemptWhy string
	// captures is the host's memory snapshot registry: a VM being captured
	// is aborted out of its capture before it is paused, and no capture
	// resumes a VM this pauser holds (lv.CaptureRegistry).
	captures *lv.CaptureRegistry
}

// NewPartitionPauser builds the monitor for host, recording under dataDir.
func NewPartitionPauser(host, dataDir string, db *corrosion.Client) *PartitionPauser {
	return &PartitionPauser{
		host: host, db: db, store: newPauseStore(dataDir), dataDir: dataDir,
		now: time.Now, after: PartitionPauseAfter, tick: partitionPauseTick, ctCapable: lxc.Available,
		failed: map[string]string{}, heldWhy: map[string]string{}, inflight: map[string]bool{}, resuming: map[string]bool{},
		killed: map[string]bool{}, notOurs: map[string]string{},
		markFailed: map[string]string{}, markPending: map[string]string{}, clearing: map[string]bool{},
		markWritten: map[string]chan struct{}{}, clearWanted: map[string]bool{}, markWaitBound: markWaitBoundDefault,
		markLocks: map[string]*sync.Mutex{},
	}
}

// lossSample is one quorum reading.
type lossSample struct {
	at   time.Time
	lost bool
}

// lossCovered is how much of the samples' span the quorum was lost: each
// interval between two readings is attributed to the EARLIER one, so loss
// starts at the first reading that saw it. Attributing it to the later one
// charged the stretch before that reading — up to a tick during which the
// last reading was a Yes — and paused a blip short of T_pause (G6). §4.1's
// bound already allows a tick (Δ) for the first lost reading to come.
func lossCovered(samples []lossSample) time.Duration {
	var d time.Duration
	for i := 1; i < len(samples); i++ {
		if samples[i-1].lost {
			d += samples[i].at.Sub(samples[i-1].at)
		}
	}
	return d
}

// HealedForTests reports whether this pauser is in a healed state: its
// readings have been an unbroken Yes for at least T_pause, so its loss window
// is clear. G6 — a blip shorter than T_pause pauses nothing — holds from such
// a state, so a scenario that asserts the pause comes no sooner than T_pause
// after a split waits for it first (tests/fleet).
func (p *PartitionPauser) HealedForTests() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.yesSince.IsZero() && p.now().Sub(p.yesSince) >= p.after
}

// SetQuorum wires the execution quorum (Checker.ExecutionQuorum).
func (p *PartitionPauser) SetQuorum(fn func(context.Context) (QuorumState, int, int)) { p.quorum = fn }

// SetEnabled wires enforcement.partition_pause. Off pauses nothing; what an
// earlier run paused is still resumed.
func (p *PartitionPauser) SetEnabled(fn func() bool) { p.enabled = fn }

// SetVMBackend wires the libvirt client (nil: no VMs).
func (p *PartitionPauser) SetVMBackend(b PauseVMBackend) { p.vms = b }

// SetCaptureRegistry wires the host's memory snapshot capture registry,
// shared with the gRPC server (lv.CaptureRegistry).
func (p *PartitionPauser) SetCaptureRegistry(r *lv.CaptureRegistry) { p.captures = r }

// captureWait bounds how long a pause waits for an aborted memory snapshot's
// libvirt job to end before it suspends anyway: one pause call's budget, cut
// to what the pass has left (passBudget.holdWait).
const captureWait = partitionPauseCallTimeout

// removeRecord drops kind/name's pause record and, for a VM, the capture
// registry hold that went with it.
func (p *PartitionPauser) removeRecord(kind, name string) error {
	if err := p.store.remove(kind, name); err != nil {
		return err
	}
	if kind == PauseKindVM {
		p.captures.Release(name)
	}
	return nil
}

// SetContainerRuntime wires the LXC runtime (nil: no containers).
func (p *PartitionPauser) SetContainerRuntime(r lxc.Runtime) { p.cts = r }

// SetContainerCapable replaces the probe for whether this host has a container
// runtime at all (default lxc.Available, the probe behind the litevirt.lxc
// host label).
func (p *PartitionPauser) SetContainerCapable(fn func() bool) { p.ctCapable = fn }

// SetResumeConfirmer wires the majority check. nil confirms nothing.
func (p *PartitionPauser) SetResumeConfirmer(fn ResumeConfirmer) { p.confirm = fn }

// SetSettleVerifier wires Layer 3 for CONTAINERS (docs/design/partition-pause.md
// §6). A container relocation tombstones this host's row and writes one at the
// target, so the VM reconciler's settle, which reads the domain's row, has
// nothing to read; and a container carries no incarnation of its own, so only
// a container this host paused — whose record holds the incarnation and epoch
// — can be settled. nil settles nothing.
func (p *PartitionPauser) SetSettleVerifier(fn SettleVerifier) { p.settle = fn }

// SetPeerRuntimeChecker wires the peer runtime check container settle needs:
// the destination must itself report the container running before the local
// copy is stopped. nil settles nothing.
func (p *PartitionPauser) SetPeerRuntimeChecker(fn func(ctx context.Context, host, name string) (string, error)) {
	p.peerRuntime = fn
}

// SetSelfFence wires the watchdog backstop for a pause that fails: armed
// reports a VERIFIED hardware watchdog, fence trips it. Either nil disables it.
func (p *PartitionPauser) SetSelfFence(armed func() bool, fence func()) {
	p.armed, p.selfFence = armed, fence
}

// SetRecordFailure wires enforcement.partition_pause_record_failure: what a
// pause does when its record cannot be written (PauseRecordFailurePause, the
// default for ""; PauseRecordFailureReserve; PauseRecordFailureSelfFence).
func (p *PartitionPauser) SetRecordFailure(mode string) { p.recordMode = mode }

// SetRecordFaultForTests makes every record write to a layer
// (PauseRecordLayerDisk, PauseRecordLayerReserve) for this pauser's data dir
// fail with what fn returns, nil for success: a full disk, in tests. nil
// clears it.
func (p *PartitionPauser) SetRecordFaultForTests(fn func(layer string, rec PauseRecord) error) {
	if p.store.st == nil {
		return
	}
	p.store.st.mu.Lock()
	p.store.st.fault = fn
	p.store.st.mu.Unlock()
}

// SetClock replaces the monotonic clock (tests).
func (p *PartitionPauser) SetClock(now func() time.Time) { p.now = now }

// SetTimings replaces T_pause and the tick (fleet scenarios, which cannot wait
// production seconds). Production never calls it: the majority's wait is
// derived from PartitionPauseAfter.
func (p *PartitionPauser) SetTimings(after, tick time.Duration) {
	if after > 0 {
		p.after = after
	}
	if tick > 0 {
		p.tick = tick
	}
}

// Records lists the self-paused workloads.
func (p *PartitionPauser) Records() ([]PauseRecord, error) { return p.store.list() }

// Start runs the monitor until ctx ends.
func (p *PartitionPauser) Start(ctx context.Context) {
	p.noteProgress()
	t := time.NewTicker(p.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Evaluate(ctx)
			p.noteProgress()
		}
	}
}

// Progress counts the pauser's units of work: its start, every pass, and
// every record a pass handles. Zero before Start. The watchdog's liveness
// gate self-fences when it stands still too long (watchdog.Controller.
// SetPauserProgress): a pauser that is wedged can neither pause nor
// self-fence, so the hardware watchdog has to. A counter, not a timestamp, so
// a wall-clock step is not a wedge, and a long pass that moves is not one
// either.
func (p *PartitionPauser) Progress() uint64 { return p.progress.Load() }

func (p *PartitionPauser) noteProgress() { p.progress.Add(1) }

// partitionResumePassBudget bounds how long one healed pass goes on taking
// up steps: E, the pause pass's own budget. What it does not reach is left
// exactly as it was, still paused, and the next pass starts there
// (resumeCursor, resumeLoopCursor), so a record that is slow on every pass
// cannot starve the ones after it.
var partitionResumePassBudget = PartitionPauseExecBudget

// partitionResumeStepBound is R (PartitionResumeStepBound); tests shorten it.
var partitionResumeStepBound = PartitionResumeStepBound

// settleStopMin is the least time left in its step for a settle to start
// its stop: lxc-stop waits a second for the frozen container's SIGPWR before
// it kills it. With less, the settle waits for a later pass.
var settleStopMin = 1500 * time.Millisecond

// resumePass is one healed pass's budget, steps and outcome.
type resumePass struct {
	p     *PartitionPauser
	ctx   context.Context
	start time.Time
	end   time.Time // start + partitionResumePassBudget
	steps int
	// lost: a quorum reading between steps was not Yes, so the pass stopped.
	lost     bool
	deferred int
}

func (p *PartitionPauser) newResumePass(ctx context.Context) *resumePass {
	now := time.Now() // monotonic, unlike p.now
	return &resumePass{p: p, ctx: ctx, start: now, end: now.Add(partitionResumePassBudget)}
}

// passStep is one step's deadline. cut: the pass's end, not R, set it.
type passStep struct {
	deadline time.Time
	cut      bool
}

// ranOut reports whether a step cut short by the pass's end used all of
// it: the step did not finish for want of time, not for anything of its own,
// so the next pass starts with it.
func (s passStep) ranOut() bool { return s.cut && !time.Now().Before(s.deadline) }

// step reports whether the pass takes on one more step, and its deadline.
// The first step of each phase is always taken (first), with the whole of
// R, so every pass moves; any other only while the budget lasts, and never
// past its end. Before every step but the pass's first (which Evaluate's own
// reading just preceded) the quorum is read again: a step is at most R, so
// the pass never goes longer than R without a reading. A step taken counts
// as progress (Progress).
func (ps *resumePass) step(first bool) (passStep, bool) {
	if ps.lost {
		return passStep{}, false
	}
	now := time.Now()
	if !first && !now.Before(ps.end) {
		ps.deferred++
		return passStep{}, false
	}
	if ps.steps > 0 && ps.p.majorityLost(ps.ctx) {
		ps.lost = true
		return passStep{}, false
	}
	ps.steps++
	ps.p.noteProgress()
	st := passStep{deadline: now.Add(partitionResumeStepBound)}
	if !first && ps.end.Before(st.deadline) {
		st = passStep{deadline: ps.end, cut: true}
	}
	return st, true
}

// majorityLost re-reads the quorum between the steps of a resume pass. A
// pass takes time, and the partition can come back during it (a flap, the
// ordinary case just after a heal): the pass must not go on resuming behind
// a majority that is gone again. A reading that is not Yes is recorded like
// Evaluate's own: it counts toward the loss window and breaks the run of Yes
// readings, so the next resume needs a full heal again (§4.1).
func (p *PartitionPauser) majorityLost(ctx context.Context) bool {
	st, _, _ := p.quorum(ctx)
	if st == QuorumYes {
		return false
	}
	now := p.now()
	p.mu.Lock()
	p.samples = append(p.samples, lossSample{at: now, lost: true})
	p.yesSince = time.Time{}
	if st == QuorumNo {
		p.sawNo = true
	}
	p.mu.Unlock()
	// As Evaluate's own No reading does: no memory snapshot starts on a host
	// that lost the voter majority (CaptureRegistry.RefuseCaptures).
	if st == QuorumNo && p.enabled != nil && p.enabled() {
		p.captures.RefuseCaptures("this host lost the voter majority; its partition pause may pause the VM")
	}
	return true
}

// callWithin runs fn for the workload key, waiting at most timeout. A call
// that does not return in time is abandoned, not cancelled: it holds key in
// inflight until it returns, so no second call for the workload is issued
// meanwhile (and a pause of it fails). A resume (resume) also marks it in
// resuming, and should one land after it was abandoned, landed runs at once,
// with key still held: the pass reported the workload still paused, so
// landed either lets it stand (lateResume) or pauses it again.
func (p *PartitionPauser) callWithin(key string, timeout time.Duration, resume bool, fn func() error, landed func()) error {
	_, err := p.callWithinThen(key, timeout, resume, fn, landed, nil)
	return err
}

// callWithinThen is callWithin, and then, when fn was started (started),
// runs after in the call's own goroutine once fn and any landed have
// returned, however long after the deadline that is. By then the call no
// longer holds key (inflight, resuming, killed) and its result has been
// handed back: after is not part of the call, so a slow after neither keeps
// the workload counted as a resume that may yet land (killInFlightResumes)
// nor holds the step. When fn was not started (no time left, or an earlier
// call still out) after is not run: the caller still owns what after would
// release.
func (p *PartitionPauser) callWithinThen(key string, timeout time.Duration, resume bool, fn func() error, landed, after func()) (started bool, err error) {
	if timeout <= 0 {
		return false, errPassBudget
	}
	p.mu.Lock()
	if p.inflight[key] {
		p.mu.Unlock()
		return false, fmt.Errorf("an earlier call on %s has not returned yet", key)
	}
	p.inflight[key] = true
	if resume {
		p.resuming[key] = true
	}
	p.mu.Unlock()
	const (
		running = iota
		returned
		abandoned
	)
	var state atomic.Int32
	done := make(chan error, 1)
	go func() {
		err := fn()
		if !state.CompareAndSwap(running, returned) && err == nil && landed != nil {
			landed()
		}
		p.mu.Lock()
		delete(p.inflight, key)
		delete(p.resuming, key)
		delete(p.killed, key)
		p.mu.Unlock()
		done <- err
		if after != nil {
			after()
		}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return true, err
	case <-t.C:
		if state.CompareAndSwap(running, abandoned) {
			return true, fmt.Errorf("%w within %v", errCallTimeout, timeout)
		}
		return true, <-done
	}
}

// timedOutErr: err is a call abandoned at, or refused for, its deadline.
func timedOutErr(err error) bool {
	return errors.Is(err, errCallTimeout) || errors.Is(err, errPassBudget)
}

// resumeInFlight reports whether an abandoned resume of key has not returned.
func (p *PartitionPauser) resumeInFlight(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resuming[key]
}

// lateResume decides a resume that landed after its step abandoned it, with
// its key still held. It stands only when it is as safe as a resume that
// landed on time: the run of Yes readings the step started under (yesAt, the
// yesSince it read) is still unbroken, so no reading since — the pass's, or
// any later tick's — saw the majority gone; a fresh quorum reading is Yes;
// and the voter majority confirms again, now, that this host still owns the
// workload at the recorded epoch and incarnation. The record is then dropped
// and the workload is an ordinary running one, which the next loss pauses on
// the ordinary path. Otherwise it is paused again at once (undo). A pause
// pass that killed the domain meanwhile (killed) wins: the call cannot have
// landed on the killed process.
func (p *PartitionPauser) lateResume(rec PauseRecord, yesAt time.Time, undo func() error) {
	key := rec.Key()
	if p.lateResumeStands(rec, yesAt) {
		// removeRecord: a VM's capture hold goes with its record, as on an
		// on-time resume.
		if err := p.removeRecord(rec.Kind, rec.Name); err != nil {
			slog.Warn("partition-pause: a late resume stands, but could not drop the record", "kind", rec.Kind, "name", rec.Name, "error", err)
		}
		p.mu.Lock()
		delete(p.heldWhy, key)
		delete(p.notOurs, key)
		delete(p.markFailed, key)
		p.mu.Unlock()
		slog.Warn("partition-pause: an abandoned resume landed late with the voter majority there throughout and confirming again; it stands",
			"kind", rec.Kind, "name", rec.Name, "host", p.host)
		return
	}
	if err := undo(); err != nil {
		slog.Error("partition-pause: an abandoned resume landed late and could not be paused again",
			"kind", rec.Kind, "name", rec.Name, "host", p.host, "error", err)
		return
	}
	slog.Warn("partition-pause: an abandoned resume landed late; paused again", "kind", rec.Kind, "name", rec.Name, "host", p.host)
}

// lateResumeStands is lateResume's test. When it holds, rec's key leaves
// resuming under the same lock that saw the run unbroken, so a pause pass
// from then on treats the workload as an ordinary running one.
func (p *PartitionPauser) lateResumeStands(rec PauseRecord, yesAt time.Time) bool {
	key := rec.Key()
	unbroken := func() bool { return !yesAt.IsZero() && p.yesSince.Equal(yesAt) && !p.killed[key] }
	p.mu.Lock()
	ok := unbroken()
	p.mu.Unlock()
	if !ok || p.quorum == nil || p.confirm == nil {
		return false
	}
	qctx, cancel := context.WithTimeout(context.Background(), partitionPauseCallTimeout)
	st, _, _ := p.quorum(qctx)
	cancel()
	if st != QuorumYes {
		return false
	}
	cctx, cancel := context.WithTimeout(context.Background(), partitionResumeStepBound)
	v, ok := p.confirm(cctx, []PauseRecord{rec})[key]
	cancel()
	if !ok || !v.OK {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !unbroken() {
		return false
	}
	delete(p.resuming, key)
	return true
}

// killInFlightResumes kills the QEMU of every VM whose abandoned resume is
// still out, for a pause pass: such a call may land at any moment, and a
// suspend cannot be promised to come after it, so the only stop it cannot
// undo is the process's end (KillPartitionPaused). Each kill runs in its own
// goroutine under partitionPauseCallTimeout. It reports, by key, each one
// that did not succeed; a VM killed under the same call before is not
// killed again.
func (p *PartitionPauser) killInFlightResumes() map[string]string {
	p.mu.Lock()
	var keys []string
	for key := range p.resuming {
		if strings.HasPrefix(key, PauseKindVM+"/") && !p.killed[key] {
			keys = append(keys, key)
		}
	}
	p.mu.Unlock()
	sort.Strings(keys)
	failures := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, key := range keys {
		name := strings.TrimPrefix(key, PauseKindVM+"/")
		uuid := ""
		if rec, ok, err := p.store.get(PauseKindVM, name); err == nil && ok {
			uuid = rec.DomainUUID
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := guardedCall(&p.reads, "KillPartitionPaused/"+name, partitionPauseCallTimeout, func() (struct{}, error) {
				return struct{}{}, p.vms.KillPartitionPaused(name, uuid)
			})
			if err != nil {
				mu.Lock()
				failures[key] = whyResumeInFlight + "; killing its QEMU failed: " + err.Error()
				mu.Unlock()
				return
			}
			p.mu.Lock()
			if p.resuming[key] {
				p.killed[key] = true
			}
			p.mu.Unlock()
			slog.Error("partition-pause: killed the QEMU of a VM whose abandoned resume was still out under a lost majority; it cannot land now",
				"name", name, "host", p.host)
		}()
	}
	wg.Wait()
	return failures
}

// rotateAfter is recs (sorted by Key) starting at the first record after
// cursor, wrapping around: where the last pass stopped.
func rotateAfter(recs []PauseRecord, cursor string) []PauseRecord {
	if cursor == "" {
		return recs
	}
	i := sort.Search(len(recs), func(i int) bool { return recs[i].Key() > cursor })
	return append(append([]PauseRecord{}, recs[i:]...), recs[:i]...)
}

// repause pauses again, at once, the workloads this pass resumed, when the
// majority went away again before the pass ended. They were resumed on the
// majority's word a moment ago; with it gone, the majority's own wait may be
// running, and a copy resumed here could run beside its replacement.
//
// The pauses run at once, each in its own goroutine under
// partitionPauseCallTimeout, as a pause pass's do, and the whole re-pause
// returns within partitionRepauseBound (E) however many there are and
// however they hang: it runs on the pauser's own loop, which takes no quorum
// reading and pauses nothing else until it returns, and the workloads
// earlier passes resumed are paused on that ordinary path (§4.1).
//
// A re-pause is a pause like the pass's: no memory snapshot capture starts
// while it runs (PausePass), and a VM's suspend comes after the capture
// registry's hold (Hold), so a capture that began once the resume released
// its hold cannot resume the guest after this pause. A hold that does not
// settle within the re-pause's own budget counts the pause failed, as in
// pauseVMs.
func (p *PartitionPauser) repause(recs []PauseRecord) {
	failures := map[string]string{}
	var mu sync.Mutex
	pending := map[string]bool{}
	var wg sync.WaitGroup
	budget := newPassBudget()
	defer p.captures.PausePass()()
	for _, rec := range recs {
		rec.PausedAt = p.now().UTC().Format(time.RFC3339)
		rec.Reason = "the voter majority was lost again while this host was resuming"
		var pause func() error
		var paused func()
		switch rec.Kind {
		case PauseKindVM:
			if p.vms == nil {
				continue
			}
			// A pause of its own, marked as the pass's are: its mark went
			// before the resume, and the record is written again.
			rec.Token = newPauseToken()
			pause = func() error { return p.suspendPendingMark(rec) }
			paused = func() { p.markPaused(rec) }
		case PauseKindContainer:
			if p.cts == nil {
				continue
			}
			name := rec.Name
			pause = func() error {
				cctx, cancel := context.WithTimeout(context.Background(), partitionPauseCallTimeout)
				defer cancel()
				return p.cts.Freeze(cctx, name)
			}
		default:
			continue
		}
		mu.Lock()
		pending[rec.Key()] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			settled := true
			if rec.Kind == PauseKindVM {
				_, settled = p.captures.Hold(rec.Name, budget.holdWait())
			}
			err := p.pauseOne(rec, budget.recordBound(), pause, paused)
			if err == nil && !settled {
				err = errors.New("a memory snapshot of the guest did not let go within the re-pause's budget" +
					"; libvirt or the capture may resume the guest after this pause")
			}
			mu.Lock()
			delete(pending, rec.Key())
			if err != nil {
				failures[rec.Key()] = err.Error()
			}
			mu.Unlock()
			if err != nil {
				slog.Error("partition-pause: could not pause again a workload resumed just before the majority was lost",
					"kind", rec.Kind, "name", rec.Name, "host", p.host, "error", err)
				return
			}
			slog.Warn("partition-pause: paused again a workload resumed just before the majority was lost",
				"kind", rec.Kind, "name", rec.Name, "host", p.host)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(partitionRepauseBound):
	}
	// A pause still running past the bound may yet report; copy what is
	// known now.
	mu.Lock()
	out := make(map[string]string, len(failures)+len(pending))
	for key, why := range failures {
		out[key] = why
	}
	for key := range pending {
		out[key] = fmt.Sprintf("pausing it again did not finish within %v", partitionRepauseBound)
	}
	mu.Unlock()
	if len(out) > 0 {
		p.raiseFailed(context.Background(), out)
	}
}

// partitionRepauseBound bounds repause as a whole: E. §4.1 counts it inside
// T_pause (TestPartitionPauseWaitCoversTheMinority).
var partitionRepauseBound = PartitionPauseExecBudget

// Evaluate is one pass. The quorum readings of the last 2·T_pause are kept,
// and this host pauses once the quorum was lost for at least T_pause of that
// window — accumulated, not continuous, so a lossy link whose occasional Yes
// would reset a continuous clock still pauses while the voters, which need
// only five consecutive failures each, fence it (docs/design/partition-pause.md
// §4.1). Only an unbroken run of Yes readings lasting T_pause (FailuresToFence
// probe intervals, the time a fence verdict takes to build) counts as the
// majority being back: it clears the window and runs the resume checks. A
// shorter run could clear the window inside the very stretch the voters are
// building a verdict from, and the pause would then never come.
func (p *PartitionPauser) Evaluate(ctx context.Context) {
	if p.quorum == nil {
		return
	}
	// After the pass, so a disk that hangs cannot delay a pause.
	defer p.keepRecords()
	state, live, needed := p.quorum(ctx)
	now := p.now()
	lost := state != QuorumYes

	p.mu.Lock()
	hadLoss := false
	for _, s := range p.samples {
		if s.lost {
			hadLoss = true
			break
		}
	}
	p.samples = append(p.samples, lossSample{at: now, lost: lost})
	cut := now.Add(-2 * p.after)
	for len(p.samples) > 1 && p.samples[0].at.Before(cut) {
		p.samples = p.samples[1:]
	}
	if state == QuorumNo {
		p.sawNo = true
	}
	if !lost && !p.sawYes {
		p.sawYes = true
		if !p.sawNo {
			// Only warmup's Unknowns precede this first Yes: they were never
			// a loss, and must not shorten the next one. A restart inside a
			// partition reads No, never Yes, and keeps its readings.
			p.samples = []lossSample{{at: now}}
		}
	}
	if lost {
		p.yesSince = time.Time{}
	} else if p.yesSince.IsZero() {
		p.yesSince = now
	}
	regained := !lost && now.Sub(p.yesSince) >= p.after
	if regained {
		if hadLoss {
			p.lastConfirm = time.Time{} // first resume check after a heal runs at once
		}
		p.samples = []lossSample{{at: now}}
	}
	covered := lossCovered(p.samples)
	p.mu.Unlock()

	// No memory snapshot starts on a host that lost the voter majority: a
	// capture begun there could meet a pause pass after the pass's
	// start-of-pass preemption (CaptureRegistry.RefuseCaptures).
	if state == QuorumNo && p.enabled != nil && p.enabled() {
		p.captures.RefuseCaptures("this host lost the voter majority; its partition pause may pause the VM")
	} else {
		p.captures.RefuseCaptures("")
	}

	if regained {
		p.resolveFailed(ctx, "the voter majority is back")
		p.tryResume(ctx, now)
		return
	}
	if !lost {
		// A Yes, but not yet a sustained one: neither pause nor resume. A
		// recorded VM that runs again (an operator resumed it) loses its
		// mark now, so a later suspend by anyone else never matches it.
		p.clearMarksOfRunning(ctx)
		return
	}
	// Unknown (warmup, an unreadable voter set) counts as loss, but is not
	// reported as one: every daemon start passes through it.
	// With the flag off nothing is paused (docs/design/partition-pause.md §5),
	// so the line must not say otherwise.
	if !hadLoss && state == QuorumNo {
		if p.enabled != nil && p.enabled() {
			slog.Info("partition-pause: lost the voter majority; pausing recoverable workloads if it does not return",
				"host", p.host, "live", live, "needed", needed, "after", p.after)
		} else {
			slog.Info("partition-pause: lost the voter majority; enforcement.partition_pause is off, so this host pauses nothing",
				"host", p.host, "live", live, "needed", needed)
		}
	}
	if covered < p.after {
		return
	}
	if p.enabled == nil || !p.enabled() {
		return
	}
	if why := p.exempt(ctx); why != "" {
		p.noteExempt(why)
		return
	}
	p.noteExempt("")
	reason := fmt.Sprintf("lost the voter majority for %s of the last %s (%d of %d needed live)",
		covered.Round(time.Second), (2 * p.after).Round(time.Second), live, needed)
	p.pauseAll(ctx, now, reason)
}

// keepRecords makes the reserve while the disk has room (every mode but
// self_fence, with the flag on), and moves any record held in the reserve or
// in memory to the record directory once a write there succeeds. It runs in
// the background and the pass waits for it at most one call timeout: a disk
// that hangs stalls the run, never the pauser, and while it is stalled later
// passes start none.
func (p *PartitionPauser) keepRecords() {
	p.mu.Lock()
	if p.keeping {
		p.mu.Unlock()
		return
	}
	p.keeping = true
	p.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer func() {
			p.mu.Lock()
			p.keeping = false
			p.mu.Unlock()
			close(done)
		}()
		p.keepRecordsNow()
	}()
	select {
	case <-done:
	case <-time.After(partitionPauseCallTimeout):
		slog.Warn("partition-pause: writing the held pause records has not returned; it goes on in the background", "host", p.host)
	}
}

func (p *PartitionPauser) keepRecordsNow() {
	p.store.flush()
	if p.recordMode == PauseRecordFailureSelfFence || p.enabled == nil || !p.enabled() || p.store.dir == "" {
		return
	}
	why := ""
	if err := p.store.ensureReserve(); err != nil {
		why = err.Error()
	}
	p.mu.Lock()
	changed := why != p.reserveWhy
	p.reserveWhy = why
	p.mu.Unlock()
	if changed && why != "" {
		slog.Warn("partition-pause: cannot make the pause-record reserve; a pause whose record cannot be written falls back as enforcement.partition_pause_record_failure says",
			"host", p.host, "mode", p.recordModeName(), "error", why)
	}
}

// verifiedWatchdog reports whether a failed pause can self-fence: a verified
// watchdog is armed and the fence is wired.
func (p *PartitionPauser) verifiedWatchdog() bool {
	return p.armed != nil && p.armed() && p.selfFence != nil
}

func (p *PartitionPauser) recordModeName() string {
	if p.recordMode == "" {
		return PauseRecordFailurePause
	}
	return p.recordMode
}

// exempt reports why this host must not pause, or "".
func (p *PartitionPauser) exempt(ctx context.Context) string {
	voters, err := corrosion.VoterSet(ctx, p.db)
	if err == nil && len(voters) <= 1 && (len(voters) == 0 || voters[p.host]) {
		return "single-node cluster: nothing could recover its workloads elsewhere"
	}
	self, err := corrosion.GetHost(ctx, p.db, p.host)
	if err != nil || self == nil {
		return "this host's own row is unreadable, so no coordinator can fence it by it either"
	}
	if self.State == "maintenance" {
		return "host in maintenance: the coordinator never fences it, so nothing would recover its workloads"
	}
	if self.IsWitness() {
		return "witness: runs no workloads"
	}
	return ""
}

func (p *PartitionPauser) noteExempt(why string) {
	p.mu.Lock()
	changed := why != p.exemptWhy
	p.exemptWhy = why
	p.mu.Unlock()
	if changed && why != "" {
		slog.Info("partition-pause: majority lost, but this host does not pause", "host", p.host, "reason", why)
	}
}

// pauseAll pauses every recoverable workload still running here.
func (p *PartitionPauser) pauseAll(ctx context.Context, now time.Time, reason string) {
	deadline := now.Add(PartitionPauseExecBudget)
	budget := newPassBudget()
	// No capture starts while the pass runs, so the captures it can meet are
	// the ones its start-of-pass preemption sees (§3.3).
	defer p.captures.PausePass()()
	// VMs and containers at once, each under the same read budget, so the
	// pass as a whole ends within E rather than each half of it.
	vmFail, ctFail := map[string]string{}, map[string]string{}
	var wg sync.WaitGroup
	if p.vms != nil {
		wg.Add(1)
		go func() { defer wg.Done(); p.pauseVMs(ctx, budget, reason, vmFail) }()
	}
	if p.cts != nil {
		wg.Add(1)
		go func() { defer wg.Done(); p.pauseContainers(ctx, budget, reason, ctFail) }()
	}
	wg.Wait()
	failures := vmFail
	for k, v := range ctFail {
		failures[k] = v
	}
	if over := p.now().Sub(deadline); over > 0 {
		slog.Warn("partition-pause: pausing took longer than its budget; the majority's wait assumes it does not",
			"host", p.host, "over", over.Round(time.Millisecond), "budget", PartitionPauseExecBudget)
	}
	if len(failures) > 0 {
		p.raiseFailed(ctx, failures)
		if p.armed != nil && p.armed() && p.selfFence != nil {
			slog.Error("partition-pause: a pause FAILED under lost majority — self-fencing (verified watchdog) so the majority's recovery cannot run beside it",
				"host", p.host, "failures", failures)
			p.selfFence()
		} else {
			slog.Error("partition-pause: a pause FAILED under lost majority and no verified watchdog can self-fence; retrying every tick",
				"host", p.host, "failures", failures)
		}
	} else {
		p.resolveFailed(ctx, "every recoverable workload is paused")
	}
	p.syncPausedCondition(ctx, reason)
}

// domainPaused reports a paused domain, whatever its paused reason. It is
// deliberately "paused, any reason": a memory snapshot holds its guest paused
// with reason user (the paused variant's suspend) or snapshot (libvirt's own,
// or a suspend during the job), and a guest QEMU paused on an I/O error during
// a capture is as much the pauser's as a running one. A finer paused reason
// (DomainStatus.PausedReason, fix/pause-never-resumes-ioerror) must not
// narrow it; only a domain that is not paused at all (shut off, crashed,
// pmsuspended, shutting down) is skipped.
func domainPaused(st lv.DomainStatus) bool { return st.Reason == "paused" }

// preemptCaptures is the pass's first act: every memory snapshot capture in
// flight on a VM the pass is about to pause is told not to start its libvirt
// job, and its job is aborted in the background (CaptureRegistry.Preempt).
// libvirt's cleanup then runs while the pass reads the other VMs, so the
// VM's Hold, however late it comes in the pass and however little of the
// budget is left for it, finds the job ended and settles; a capture alone
// never fails a pause a plain suspend would have made. Only the registry and
// this host's own rows are read here, no libvirt: a VM whose row says the
// pass will not pause it (another host's, a migration source, not
// recoverable) keeps its capture.
func (p *PartitionPauser) preemptCaptures(ctx context.Context, names []string, enrolled *map[string]bool) {
	if p.captures == nil {
		return
	}
	for _, name := range names {
		if !p.captures.InFlight(name) {
			continue
		}
		vm, err := corrosion.GetVM(ctx, p.db, name)
		if err != nil || vm == nil || vm.HostName != p.host || vm.State == "migrating" {
			continue
		}
		if *enrolled == nil {
			if *enrolled, err = corrosion.AutoPromoteEnrolled(ctx, p.db); err != nil {
				*enrolled = map[string]bool{}
			}
		}
		if !corrosion.VMRecoverableOnHostFailure(*vm, (*enrolled)[vm.Name]) {
			continue
		}
		p.captures.Preempt(name)
	}
}

func (p *PartitionPauser) pauseVMs(ctx context.Context, budget passBudget, reason string, failures map[string]string) {
	var mu sync.Mutex
	fail := func(key, why string) { mu.Lock(); failures[key] = why; mu.Unlock() }
	// A VM whose abandoned resume is still out may be resumed by it at any
	// moment, and no suspend is sure to come after that: its QEMU is killed
	// instead, alongside the rest of the pass, not through libvirt (whose
	// call is what hangs). It is listed or not, readable or not.
	kills := make(chan map[string]string, 1)
	go func() { kills <- p.killInFlightResumes() }()
	defer func() {
		for k, v := range <-kills {
			fail(k, v)
		}
	}()
	names, err := guardedCall(&p.reads, readListDomains, budget.timeout(), p.vms.ListDomains)
	if err != nil {
		fail("vm/*", "list domains: "+err.Error())
		return
	}
	sort.Strings(names)
	var enrolled map[string]bool
	// Read before any state: a capture that ends between a VM's state read
	// (paused, by the capture) and the check below has resumed it, and is
	// still the pass's to pause.
	sawCapture := p.captures.InFlightNow()
	p.preemptCaptures(ctx, names, &enrolled)
	var wg sync.WaitGroup
	for _, name := range names {
		key := PauseKindVM + "/" + name
		if p.resumeInFlight(key) {
			// Its abandoned resume is still out: killInFlightResumes stops
			// it (or did, on an earlier pass), and reports it if it cannot.
			continue
		}
		st, err := guardedCall(&p.reads, readDomainState, budget.timeout(), func() (lv.DomainStatus, error) { return p.vms.DomainStateReason(name) })
		if err != nil {
			// Not knowing whether it runs is not knowing it is stopped.
			fail(key, "domain state unreadable: "+err.Error())
			continue
		}
		// A memory snapshot in flight holds its guest paused, and resumes it
		// when it ends: that guest is this pauser's to pause (the registry
		// hold below stops the resume). Any other paused domain is not ours.
		if st.State != RuntimeRunning && !(domainPaused(st) && (sawCapture[name] || p.captures.InFlight(name))) {
			continue // not executing: nothing to stop, and a paused one is not ours
		}
		vm, err := corrosion.GetVM(ctx, p.db, name)
		if err != nil {
			fail(key, "row unreadable: "+err.Error())
			continue
		}
		if vm == nil || vm.HostName != p.host {
			continue
		}
		if vm.State == "migrating" {
			// A live migration's source: its target takes over, and a suspend
			// here would stall the migration it is part of.
			continue
		}
		if enrolled == nil {
			if enrolled, err = corrosion.AutoPromoteEnrolled(ctx, p.db); err != nil {
				enrolled = map[string]bool{}
			}
		}
		if !corrosion.VMRecoverableOnHostFailure(*vm, enrolled[vm.Name]) {
			continue
		}
		xml, _ := guardedCall(&p.reads, readDomainXML, budget.timeout(), func() (string, error) { return p.vms.DumpXMLInactive(name) })
		rec := PauseRecord{Kind: PauseKindVM, Name: name, Host: p.host, OwnerEpoch: vm.OwnerEpoch,
			Incarnation: corrosion.IncarnationOf(vm.CreatedAt), DomainUUID: lv.UUIDFromXML(xml),
			Token:    newPauseToken(),
			PausedAt: p.now().UTC().Format(time.RFC3339), Reason: reason}
		// Every pause in its own goroutine: the pass ends within one call
		// timeout of its last read, however many workloads there are.
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The partition pause wins over a memory snapshot: the hold aborts
			// one in flight and waits out libvirt's cleanup (which resumes a
			// guest that was running) before the suspend, and keeps any
			// capture from resuming the guest after it.
			_, settled := p.captures.Hold(name, budget.holdWait())
			if err := p.pauseOne(rec, budget.recordBound(), func() error { return p.suspendPendingMark(rec) }, func() { p.markPaused(rec) }); err != nil {
				fail(rec.Key(), err.Error())
			} else if !settled {
				// The capture's job outlived the wait: libvirt resumes a guest
				// that was running when the job began, at the job's end. The
				// capture re-suspends it, but this pause cannot be guaranteed,
				// so it counts as failed (§3.4: self-fence when armed).
				fail(rec.Key(), "a memory snapshot of the guest did not let go within the pass's budget"+
					"; libvirt or the capture may resume the guest after this pause")
			}
		}()
	}
	wg.Wait()
}

func (p *PartitionPauser) pauseContainers(ctx context.Context, budget passBudget, reason string, failures map[string]string) {
	if budget.timeout() <= 0 {
		failures["ct/*"] = "list containers: " + errPassBudget.Error()
		return
	}
	lctx, cancel := context.WithTimeout(ctx, budget.timeout())
	names, err := p.cts.List(lctx)
	cancel()
	if err != nil {
		// A host with no container runtime runs no containers: nothing to
		// freeze is success, not a failed pause. Asked only after a failed
		// list, so a listing that works is always acted on.
		if capable := p.ctCapable; capable != nil && !capable() {
			return
		}
		failures["ct/*"] = "list containers: " + err.Error()
		return
	}
	rows, err := corrosion.ListContainers(ctx, p.db, p.host)
	if err != nil {
		failures["ct/*"] = "read container rows: " + err.Error()
		return
	}
	byName := make(map[string]corrosion.ContainerRecord, len(rows))
	for _, r := range rows {
		byName[r.Name] = r
	}
	fs, _ := p.cts.(frozenStater)
	sort.Strings(names)
	var mu sync.Mutex
	fail := func(key, why string) { mu.Lock(); failures[key] = why; mu.Unlock() }
	var wg sync.WaitGroup
	for _, name := range names {
		key := PauseKindContainer + "/" + name
		row, ok := byName[name]
		if !ok || !corrosion.ContainerRecoverableOnHostFailure(row) {
			continue
		}
		if p.resumeInFlight(key) {
			fail(key, whyResumeInFlight)
			continue
		}
		if budget.timeout() <= 0 {
			fail(key, "container state unreadable: "+errPassBudget.Error())
			continue
		}
		sctx, scancel := context.WithTimeout(ctx, budget.timeout())
		st, err := p.cts.State(sctx, name)
		scancel()
		if err != nil {
			fail(key, "container state unreadable: "+err.Error())
			continue
		}
		if st != lxc.StateRunning {
			continue
		}
		// lxc.Runtime.State folds FROZEN into running. With IsFrozen a frozen
		// container is skipped — ours already, or someone else's, and never ours
		// to resume. Without it a container we recorded is assumed frozen (a
		// second freeze is at best a no-op), and one we did not is frozen.
		_, recorded, _ := p.store.get(PauseKindContainer, name)
		if fs != nil && budget.timeout() > 0 {
			fctx, fcancel := context.WithTimeout(ctx, budget.timeout())
			frozen, ferr := fs.IsFrozen(fctx, name)
			fcancel()
			if ferr == nil && frozen {
				continue
			}
		} else if recorded {
			continue
		}
		rec := PauseRecord{Kind: PauseKindContainer, Name: name, Host: p.host, OwnerEpoch: row.OwnerEpoch,
			Incarnation: corrosion.IncarnationOf(row.CreatedAt), PausedAt: p.now().UTC().Format(time.RFC3339), Reason: reason}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.pauseOne(rec, budget.recordBound(), func() error {
				cctx, cancel := context.WithTimeout(ctx, partitionPauseCallTimeout)
				defer cancel()
				return p.cts.Freeze(cctx, name)
			}, nil); err != nil {
				fail(rec.Key(), err.Error())
			}
		}()
	}
	wg.Wait()
}

// whyResumeInFlight is a pause failure for a workload whose abandoned resume
// has not returned (a container, or a VM whose QEMU could not be killed).
const whyResumeInFlight = "a resume abandoned at the end of its step has not returned and may yet land"

// pauseOne records rec, waiting at most recordBound for the write, then runs
// pause, bounded by partitionPauseCallTimeout. Once pause has returned
// success, however late, paused runs in its own goroutine: nothing it does
// counts toward the pause or delays it.
// A pause that fails cleanly drops the record (the workload is not paused);
// one that times out keeps it, since it may still land, and a paused workload
// with no record is never resumed. A call that has not returned blocks any
// second call for the same workload (inflight), so a wedged suspend is never
// issued twice; it is reported as a failure until it returns.
func (p *PartitionPauser) pauseOne(rec PauseRecord, recordBound time.Duration, pause func() error, paused func()) error {
	p.mu.Lock()
	if p.inflight[rec.Key()] {
		p.mu.Unlock()
		return fmt.Errorf("an earlier pause of %s has not returned yet", rec.Key())
	}
	p.inflight[rec.Key()] = true
	p.mu.Unlock()
	// reserve and self_fence trade the pause for a self-fence; with no
	// verified watchdog to make one, a failed pause would leave the copy
	// running beside the majority's replacement, so they pause as pause does.
	mode := p.recordModeName()
	memOK := mode == PauseRecordFailurePause || !p.verifiedWatchdog()
	where, err := p.store.record(rec, p.recordMode, memOK, recordBound)
	if err != nil {
		p.mu.Lock()
		delete(p.inflight, rec.Key())
		p.mu.Unlock()
		if rec.Kind == PauseKindVM {
			p.captures.Release(rec.Name) // nothing paused, nothing recorded
		}
		return fmt.Errorf("record the pause durably: %w", err)
	}
	if where != PauseRecordLayerDisk {
		// What the majority relies on is the pause, not the record
		// (partition_pause_reserve.go): pause, and write the record to the
		// directory once it can be.
		args := []any{"kind", rec.Kind, "name", rec.Name, "host", p.host, "mode", mode}
		if where == PauseRecordLayerMemory && mode != PauseRecordFailurePause {
			args = append(args, "fallback", "no_verified_watchdog")
		}
		slog.Error("partition-pause: cannot write the pause record to the record directory; pausing with it held in "+where, args...)
	}
	done := make(chan error, 1)
	go func() {
		err := pause()
		p.mu.Lock()
		delete(p.inflight, rec.Key())
		p.mu.Unlock()
		if err == nil && paused != nil {
			go paused()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			if rerr := p.removeRecord(rec.Kind, rec.Name); rerr != nil {
				slog.Warn("partition-pause: could not drop the record of a pause that failed", "kind", rec.Kind, "name", rec.Name, "error", rerr)
			}
			return err
		}
	case <-time.After(partitionPauseCallTimeout):
		return fmt.Errorf("pause did not return within %v", partitionPauseCallTimeout)
	}
	slog.Warn("partition-pause: paused workload", "kind", rec.Kind, "name", rec.Name,
		"host", p.host, "owner_epoch", rec.OwnerEpoch, "reason", rec.Reason)
	return nil
}

// newPauseToken is a fresh token for one pause's mark.
func newPauseToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	return hex.EncodeToString(b)
}

// suspendPendingMark suspends rec's domain and, once it is suspended, notes
// its mark as pending before markPaused is even started: a clear for the same
// token waits for the mark to be written, so it never runs first and leaves
// the mark behind.
func (p *PartitionPauser) suspendPendingMark(rec PauseRecord) error {
	if err := p.vms.SuspendDomain(rec.Name); err != nil {
		return err
	}
	p.mu.Lock()
	p.markPending[rec.Key()] = rec.Token
	p.markWritten[rec.Key()+"/"+rec.Token] = make(chan struct{})
	p.mu.Unlock()
	return nil
}

// markPaused puts the mark carrying rec.Token on rec's domain, after the
// suspend and outside its timed window: libvirt can hold the metadata write
// behind a running job for up to 30 s, and the majority relies on the
// suspend alone. A mark that is late holds the VM at the heal until it lands;
// one that never lands holds it for good, which says so. A mark whose clear
// gave up waiting for it (clearWanted) is taken off as soon as it lands,
// still under the mark lock: its record may be gone, and nothing else would.
func (p *PartitionPauser) markPaused(rec PauseRecord) {
	l := p.markLock(rec.Name)
	l.Lock()
	defer l.Unlock()
	err := p.vms.MarkPartitionPaused(rec.Name, rec.Token)
	wk := rec.Key() + "/" + rec.Token
	p.mu.Lock()
	if p.markPending[rec.Key()] == rec.Token {
		delete(p.markPending, rec.Key())
	}
	// In the same critical section as the close, so a clear that gives up
	// either sees the channel closed or leaves its flag for this read.
	wanted := p.clearWanted[wk]
	delete(p.clearWanted, wk)
	if ch := p.markWritten[wk]; ch != nil {
		close(ch)
		delete(p.markWritten, wk)
	}
	if err != nil {
		p.markFailed[rec.Key()] = rec.Token
	} else if p.markFailed[rec.Key()] == rec.Token {
		delete(p.markFailed, rec.Key())
	}
	p.mu.Unlock()
	if err != nil {
		slog.Warn("partition-pause: cannot mark the paused domain as paused by this host; it stays paused after the heal until an operator resumes it",
			"name", rec.Name, "host", p.host, "error", err)
		return
	}
	if wanted {
		if cerr := p.clearMarkLocked(rec.Name, rec.Token); cerr != nil && !lv.IsNotFound(cerr) {
			slog.Warn("partition-pause: could not take a late mark off a running domain", "name", rec.Name, "error", cerr)
		}
	}
}

// markLock is name's mark lock (markLocks).
func (p *PartitionPauser) markLock(name string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.markLocks[name]
	if l == nil {
		l = &sync.Mutex{}
		p.markLocks[name] = l
	}
	return l
}

// clearMarkLocked takes name's mark off only while it is token's: a mark a
// newer pause wrote is never cleared. The caller holds name's mark lock.
func (p *PartitionPauser) clearMarkLocked(name, token string) error {
	cur, ok, err := p.vms.PartitionPauseMark(name)
	if err != nil {
		return err
	}
	if !ok || cur != token {
		return nil
	}
	return p.vms.ClearPartitionPauseMark(name)
}

// clearMarkWithin takes rec's mark off, as clearMarkLocked, for a resume
// step: the caller holds the mark lock, and the clear is abandoned at
// deadline (errCallTimeout), as every call of a resume step is. owned: the
// clear was abandoned and its goroutine now owns the lock; once the clear
// returns it puts the mark back if the clear took it off (the resume was not
// issued, and the VM is still this host's pause), then runs unlock. When not
// owned the caller still holds the lock.
func (p *PartitionPauser) clearMarkWithin(rec PauseRecord, deadline time.Time, unlock func()) (owned bool, err error) {
	timeout := min(partitionPauseCallTimeout, time.Until(deadline))
	if timeout <= 0 {
		return false, errPassBudget
	}
	const (
		running = iota
		returned
		abandoned
	)
	var state atomic.Int32
	done := make(chan error, 1)
	go func() {
		err := p.clearMarkLocked(rec.Name, rec.Token)
		if !state.CompareAndSwap(running, returned) {
			if err == nil {
				p.putMarkBack(rec)
			}
			unlock()
		}
		done <- err
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return false, err
	case <-t.C:
		if state.CompareAndSwap(running, abandoned) {
			return true, fmt.Errorf("%w within %v", errCallTimeout, timeout)
		}
		return false, <-done
	}
}

// remark puts rec's mark back on its domain, which this host's pause still
// holds paused (a resume that failed, was not issued, or was undone). The
// caller holds the mark lock.
func (p *PartitionPauser) remark(rec PauseRecord) {
	if err := p.vms.MarkPartitionPaused(rec.Name, rec.Token); err != nil {
		slog.Warn("partition-pause: could not put the mark back after a failed resume; the VM stays held until an operator resumes it",
			"name", rec.Name, "host", p.host, "error", err)
	}
}

// putMarkBack is remark for a mark the resume path took off: while the write
// is out the mark reads as still being written (markPending), so a pass that
// meets the VM meanwhile holds it as this host's pause, not someone else's.
// The caller holds the mark lock.
func (p *PartitionPauser) putMarkBack(rec PauseRecord) {
	p.mu.Lock()
	p.markPending[rec.Key()] = rec.Token
	p.mu.Unlock()
	p.remark(rec)
	p.mu.Lock()
	if p.markPending[rec.Key()] == rec.Token {
		delete(p.markPending, rec.Key())
	}
	p.mu.Unlock()
}

// forgetMark drops what this process remembers about key's mark, once its
// record is gone.
func (p *PartitionPauser) forgetMark(key string) {
	p.mu.Lock()
	delete(p.markFailed, key)
	p.mu.Unlock()
}

// clearMarkBackground takes token's mark off name in the background, one
// clear per VM at a time: a running VM must never carry a mark, and a clear
// can wait behind a libvirt job. It runs under name's mark lock and clears
// only token's mark, so a later pause's mark survives it.
//
// A clear first waits for token's own mark write, so it never runs before
// that mark lands and leaves it behind. The wait ends with ctx (the
// pauser's lifetime) or after markWaitBound, since libvirt's metadata write
// has no timeout: the clear then hands the mark to its write (clearWanted),
// and markPaused takes it off once it lands. Giving up resumes nothing; a
// resume of the VM is held while its mark write is in flight.
func (p *PartitionPauser) clearMarkBackground(ctx context.Context, name, token string) {
	ck := name + "/" + token // one clear per mark: a newer token's clear is never dropped
	p.mu.Lock()
	if p.clearing[ck] {
		p.mu.Unlock()
		return
	}
	p.clearing[ck] = true
	p.mu.Unlock()
	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.clearing, ck)
			p.mu.Unlock()
		}()
		// The mark this clear is for may still be being written: wait for it.
		p.mu.Lock()
		written := p.markWritten[PauseKindVM+"/"+ck]
		bound := p.markWaitBound
		p.mu.Unlock()
		if written != nil {
			t := time.NewTimer(bound)
			select {
			case <-written:
				t.Stop()
			case <-ctx.Done():
				t.Stop()
				if p.handMarkToWrite(ck, written) {
					return
				}
			case <-t.C:
				if p.handMarkToWrite(ck, written) {
					slog.Warn("partition-pause: this host's pause mark is still being written; it is taken off once the write returns",
						"name", name, "host", p.host, "waited", bound)
					return
				}
			}
		}
		l := p.markLock(name)
		l.Lock()
		err := p.clearMarkLocked(name, token)
		l.Unlock()
		if err != nil && !lv.IsNotFound(err) {
			slog.Warn("partition-pause: could not take the mark off a running domain", "name", name, "error", err)
		}
	}()
}

// handMarkToWrite asks the still-running write of ck's mark (written open)
// to take the mark off once it lands, and reports whether it did; false: the
// write has returned meanwhile, and the caller clears it itself.
func (p *PartitionPauser) handMarkToWrite(ck string, written chan struct{}) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-written:
		return false
	default:
	}
	p.clearWanted[PauseKindVM+"/"+ck] = true
	return true
}

// clearMarksOfRunning takes the mark off every recorded VM that runs.
func (p *PartitionPauser) clearMarksOfRunning(ctx context.Context) {
	if p.vms == nil {
		return
	}
	recs, err := p.store.list()
	if err != nil {
		return
	}
	for _, rec := range recs {
		if rec.Kind != PauseKindVM || rec.Token == "" {
			continue
		}
		st, err := guardedCall(&p.reads, readDomainState, partitionPauseCallTimeout, func() (lv.DomainStatus, error) { return p.vms.DomainStateReason(rec.Name) })
		if err == nil && st.State == RuntimeRunning {
			p.clearMarkBackground(ctx, rec.Name, rec.Token)
		}
	}
}

// pauseNotOurs is why rec's paused VM, whose state st is, is not paused by
// this host's pause, "" when it is. foreign=false when the answer is not
// known yet (the mark is unreadable): held, and asked again next pass.
//
// Only a suspend pauses with libvirt's paused reason "user": an I/O error, a
// migration, a save or a snapshot is never this host's pause. And this
// host's pause marks the live domain with the record's token once it has
// suspended it, and removes the mark before it resumes, and from any
// recorded VM it sees running, so a record a crash
// left behind beside a VM that ran again (or a late write's) never matches a
// later pause someone else made. A record without a token comes from a build
// without the mark, and the reason alone decides it.
func (p *PartitionPauser) pauseNotOurs(rec PauseRecord, st lv.DomainStatus, deadline time.Time) (why string, foreign bool) {
	if rec.Kind != PauseKindVM {
		return "", false
	}
	if st.PausedReason != "user" {
		r := st.PausedReason
		if r == "" {
			r = "unknown"
		}
		if r == lv.PausedReasonIOError {
			return "the domain is paused on a disk I/O error, not by this host's partition pause", true
		}
		return "the domain is paused for reason " + r + ", not by this host's partition pause", true
	}
	if rec.Token == "" {
		return "", false
	}
	type mark struct {
		token string
		ok    bool
	}
	m, err := guardedCall(&p.reads, readPauseMark, min(partitionPauseCallTimeout, time.Until(deadline)), func() (mark, error) {
		t, ok, err := p.vms.PartitionPauseMark(rec.Name)
		return mark{t, ok}, err
	})
	switch {
	case err != nil:
		return "the domain's partition-pause mark is unreadable: " + err.Error(), false
	case !m.ok || m.token != rec.Token:
		p.mu.Lock()
		unmarked := p.markFailed[rec.Key()] == rec.Token
		pending := p.markPending[rec.Key()] == rec.Token
		p.mu.Unlock()
		if pending && !m.ok {
			return "this host's pause mark is still being written (libvirt is slow); the VM is held until it lands", false
		}
		if unmarked && !m.ok {
			return "this host's pause could not mark the domain, so it cannot be told from a pause someone else made", true
		}
		return "the domain does not carry this pause's mark: someone else paused it (an operator?), or the mark was never written (a daemon restart while writing it)", true
	}
	return "", false
}

// heldNotOurs holds rec when its VM is not paused by this host's pause, or
// that cannot be told yet, and reports whether it did. One that something
// else paused is named in partition_paused; the record stays until the
// domain is no longer paused (stillPausedByUs drops it then).
func (p *PartitionPauser) heldNotOurs(rec PauseRecord, deadline time.Time) bool {
	if rec.Kind != PauseKindVM || p.vms == nil {
		return false
	}
	st, err := guardedCall(&p.reads, readDomainState, min(partitionPauseCallTimeout, time.Until(deadline)), func() (lv.DomainStatus, error) { return p.vms.DomainStateReason(rec.Name) })
	if err != nil {
		p.hold(rec, "domain state unreadable: "+err.Error())
		return true
	}
	if st.Reason != "paused" {
		return false // resume touches only a paused domain
	}
	why, foreign := p.pauseNotOurs(rec, st, deadline)
	p.mu.Lock()
	if foreign {
		p.notOurs[rec.Key()] = why
	} else {
		delete(p.notOurs, rec.Key())
	}
	p.mu.Unlock()
	if why == "" {
		return false
	}
	if foreign {
		why += "; it is left paused, and its record is dropped once it is not"
	}
	p.hold(rec, why)
	return true
}

// stillPausedByUs reports whether rec's VM is still the domain this host
// paused: present, paused, and (when both are known) the same domain UUID. A
// record failing it describes nothing any more and is dropped.
func (p *PartitionPauser) stillPausedByUs(rec PauseRecord, deadline time.Time) (bool, string) {
	if rec.Kind != PauseKindVM || p.vms == nil {
		return true, ""
	}
	st, err := guardedCall(&p.reads, readDomainState, min(partitionPauseCallTimeout, time.Until(deadline)), func() (lv.DomainStatus, error) { return p.vms.DomainStateReason(rec.Name) })
	if lv.IsNotFound(err) {
		// Undefined since: there is nothing left to resume, and a kept record
		// would hold partition_paused open for good.
		return false, "the domain is no longer defined"
	}
	if err != nil {
		return true, "" // unreadable now: keep the record, decide next pass
	}
	if st.Reason != "paused" {
		return false, "the domain is " + st.State + "/" + st.Reason + ", no longer paused"
	}
	if rec.DomainUUID != "" {
		if xml, err := guardedCall(&p.reads, readDomainXML, min(partitionPauseCallTimeout, time.Until(deadline)), func() (string, error) { return p.vms.DumpXMLInactive(rec.Name) }); err == nil {
			if u := lv.UUIDFromXML(xml); u != "" && u != rec.DomainUUID {
				return false, "the domain is another one (uuid " + u + ")"
			}
		}
	}
	return true, ""
}

// tryResume runs the resume checks over every record (§3.5), as one bounded
// pass of steps (resumePass): the pending-settle retries, each record's
// checks and settle, the majority confirmation, and each resume. Every step
// runs under its own deadline, at most R; the quorum is read between steps
// and after the last resume, and a pass that finds it lost stops and pauses
// again what it resumed (§4.1).
func (p *PartitionPauser) tryResume(ctx context.Context, now time.Time) {
	pass := p.newResumePass(ctx)
	// First, the record of any container settle not yet fully written: it
	// may drop the pause record of the copy it settled.
	p.retryPendingSettles(ctx, pass)
	recs, err := p.store.list()
	if err != nil {
		slog.Error("partition-pause: cannot read the pause records; nothing is resumed", "host", p.host, "error", err)
		return
	}
	if len(recs) == 0 {
		p.syncPausedCondition(ctx, "")
		return
	}
	var candidates []PauseRecord
	handled, spent := 0, false
	for _, rec := range rotateAfter(recs, p.resumeCursor) {
		if pass.lost {
			break
		}
		if spent {
			pass.deferred++
			continue
		}
		st, ok := pass.step(handled == 0)
		if !ok {
			spent = true
			continue
		}
		handled++
		prev := p.resumeCursor
		p.resumeCursor = rec.Key()
		sctx, cancel := context.WithDeadline(ctx, st.deadline)
		ok, short := p.checkRecord(ctx, sctx, rec, st.deadline)
		cancel()
		if short || st.ranOut() {
			// Cut short by the pass's end, not slow of its own: the next
			// pass starts with it, with the whole of R.
			p.resumeCursor = prev
			spent = true
			pass.deferred++
			continue
		}
		if ok {
			candidates = append(candidates, rec)
		}
	}
	if len(candidates) > 0 && !pass.lost {
		p.mu.Lock()
		due := p.lastConfirm.IsZero() || now.Sub(p.lastConfirm) >= partitionResumeRecheck
		p.mu.Unlock()
		if due {
			p.resumeConfirmed(ctx, pass, now, candidates)
		}
	}
	if pass.lost {
		slog.Warn("partition-pause: the voter majority was lost again during a resume pass; it stopped, and what it resumed is paused again",
			"host", p.host)
	}
	if pass.deferred > 0 {
		slog.Info("partition-pause: this pass spent its budget; the rest stay paused for the next pass",
			"host", p.host, "deferred", pass.deferred, "budget", partitionResumePassBudget)
	}
	p.syncPausedCondition(ctx, "")
}

// checkRecord is §3.5 steps 1 to 3 for one record, and Layer 3 for a
// container: it reports whether rec is a candidate for the majority's
// confirmation, and whether a settle could not start its stop for want of
// time (short). ctx is the step's; life, the pauser's own (a mark's
// background clear outlives the step).
func (p *PartitionPauser) checkRecord(life, ctx context.Context, rec PauseRecord, deadline time.Time) (candidate, short bool) {
	if ok, why := p.stillPausedByUs(rec, deadline); !ok {
		// Resumed or stopped by someone else, gone, or replaced: the record
		// would only keep partition_paused open and offer a stale epoch.
		if rec.Kind == PauseKindVM && rec.Token != "" && p.vms != nil {
			p.clearMarkBackground(life, rec.Name, rec.Token) // runs again, or is gone: no mark may stay
		}
		p.forgetMark(rec.Key())
		if err := p.removeRecord(rec.Kind, rec.Name); err == nil {
			p.mu.Lock()
			delete(p.notOurs, rec.Key())
			p.mu.Unlock()
			slog.Info("partition-pause: dropped a pause record that no longer describes a paused workload",
				"kind", rec.Kind, "name", rec.Name, "host", p.host, "reason", why)
		}
		return false, false
	}
	if p.heldNotOurs(rec, deadline) {
		return false, false
	}
	why := p.localRowMatches(ctx, rec)
	if why == "" {
		return true, false
	}
	if why == whyNoLocalContainerRow {
		if gone, gwhy := p.containerGone(ctx, rec.Name); gone {
			p.dropGoneContainer(rec, gwhy)
			return false, false
		}
	}
	if rec.Kind == PauseKindContainer {
		settled, swhy, sshort := p.settleContainer(ctx, rec, deadline)
		if settled {
			return false, false
		}
		if swhy != "" {
			why += "; " + swhy
		}
		short = sshort
	}
	p.hold(rec, why)
	return false, short
}

// resumeConfirmed asks the voter set about the candidates (one step), then
// resumes those it confirms, one step each, starting after the last resume
// the previous pass attempted (resumeLoopCursor): a resume that fails slowly
// takes its step and its turn like any other, and does not come first on
// every pass. The quorum is read before every resume and once more after
// the last; once it is lost, what this pass resumed is paused again.
func (p *PartitionPauser) resumeConfirmed(ctx context.Context, pass *resumePass, now time.Time, candidates []PauseRecord) {
	st, ok := pass.step(true)
	if !ok {
		return
	}
	p.mu.Lock()
	p.lastConfirm = now
	p.mu.Unlock()
	var verdicts map[string]ResumeVerdict
	if p.confirm != nil {
		cctx, cancel := context.WithDeadline(ctx, st.deadline)
		verdicts = p.confirm(cctx, candidates)
		cancel()
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Key() < candidates[j].Key() })
	var resumed []PauseRecord
	attempted := 0
	for _, rec := range rotateAfter(candidates, p.resumeLoopCursor) {
		if pass.lost {
			break
		}
		v, ok := verdicts[rec.Key()]
		switch {
		case p.confirm == nil:
			p.hold(rec, "no majority confirmation is wired on this host")
			continue
		case !ok:
			p.hold(rec, "the voter set returned no verdict")
			continue
		case !v.OK:
			p.hold(rec, v.Reason)
			continue
		}
		st, ok := pass.step(attempted == 0)
		if !ok {
			continue
		}
		attempted++
		prev := p.resumeLoopCursor
		p.resumeLoopCursor = rec.Key()
		sctx, cancel := context.WithDeadline(ctx, st.deadline)
		done, timedOut := p.resume(sctx, rec, v.Reason, st.deadline)
		cancel()
		if done {
			resumed = append(resumed, rec)
		} else if timedOut && st.cut {
			p.resumeLoopCursor = prev
		}
	}
	if len(resumed) > 0 && !pass.lost && p.majorityLost(ctx) {
		pass.lost = true
	}
	if pass.lost {
		p.repause(resumed)
	}
}

// localRowMatches is §3.5 step 3: the row in this host's replica still names
// this host, at the recorded epoch and incarnation. "" when it does.
func (p *PartitionPauser) localRowMatches(ctx context.Context, rec PauseRecord) string {
	var host, inc string
	var epoch int64
	switch rec.Kind {
	case PauseKindVM:
		vm, err := corrosion.GetVM(ctx, p.db, rec.Name)
		if err != nil {
			return "row unreadable: " + err.Error()
		}
		if vm == nil {
			return "no live row"
		}
		host, epoch, inc = vm.HostName, vm.OwnerEpoch, corrosion.IncarnationOf(vm.CreatedAt)
	case PauseKindContainer:
		ct, err := corrosion.GetContainer(ctx, p.db, p.host, rec.Name)
		if err != nil {
			return "row unreadable: " + err.Error()
		}
		if ct == nil {
			return whyNoLocalContainerRow
		}
		host, epoch, inc = ct.HostName, ct.OwnerEpoch, corrosion.IncarnationOf(ct.CreatedAt)
	default:
		return "unknown kind"
	}
	switch {
	case host != p.host:
		return "the row now names " + host
	case epoch != rec.OwnerEpoch:
		return fmt.Sprintf("the row is at owner epoch %d, the pause recorded %d", epoch, rec.OwnerEpoch)
	case inc != rec.Incarnation:
		return "the row is another incarnation (created_at " + inc + ")"
	}
	return ""
}

// whyNoLocalContainerRow is localRowMatches for a container with no live row
// on this host.
const whyNoLocalContainerRow = "no live row on this host (relocated?)"

// containerGone reports whether container name no longer exists on this host:
// the runtime lists it no more and its on-disk dir is absent. Anything it
// cannot read counts as present, so a record is kept until both say gone.
func (p *PartitionPauser) containerGone(ctx context.Context, name string) (bool, string) {
	if p.cts == nil {
		return false, ""
	}
	lctx, cancel := context.WithTimeout(ctx, partitionPauseCallTimeout)
	names, err := p.cts.List(lctx)
	cancel()
	if err != nil {
		return false, ""
	}
	for _, n := range names {
		if n == name {
			return false, ""
		}
	}
	if exists, err := p.cts.ContainerExists(name); err != nil || exists {
		return false, ""
	}
	return true, "the container no longer exists on this host and has no live row here"
}

// dropGoneContainer drops the record of a container that no longer exists:
// there is nothing left to resume, and a kept record would hold
// partition_paused open for good.
func (p *PartitionPauser) dropGoneContainer(rec PauseRecord, why string) {
	if err := p.store.remove(rec.Kind, rec.Name); err != nil {
		slog.Warn("partition-pause: could not drop the record of a container that no longer exists",
			"kind", rec.Kind, "name", rec.Name, "host", p.host, "error", err)
		return
	}
	p.mu.Lock()
	delete(p.heldWhy, rec.Key())
	p.mu.Unlock()
	slog.Warn("partition-pause: dropped a pause record that no longer describes a paused workload",
		"kind", rec.Kind, "name", rec.Name, "host", p.host, "reason", why)
}

func (p *PartitionPauser) hold(rec PauseRecord, why string) {
	p.mu.Lock()
	first := p.heldWhy[rec.Key()] != why
	p.heldWhy[rec.Key()] = why
	p.mu.Unlock()
	if first {
		slog.Warn("partition-pause: workload stays paused", "kind", rec.Kind, "name", rec.Name,
			"host", p.host, "reason", why)
	}
}

// resume continues rec's workload and drops its record, every call bounded
// by deadline. It reports whether the workload runs again, and whether a
// call was abandoned at the deadline (callWithin): the workload keeps its
// record and stays paused, and a resume that lands late is undone.
func (p *PartitionPauser) resume(ctx context.Context, rec PauseRecord, why string, deadline time.Time) (resumed, timedOut bool) {
	// The run of Yes readings this step started under: a resume that lands
	// late stands only while it is unbroken (lateResume).
	p.mu.Lock()
	yesAt := p.yesSince
	p.mu.Unlock()
	switch rec.Kind {
	case PauseKindVM:
		if p.vms == nil {
			p.hold(rec, "no libvirt backend on this host")
			return false, false
		}
		st, err := guardedCall(&p.reads, readDomainState, min(partitionPauseCallTimeout, time.Until(deadline)),
			func() (lv.DomainStatus, error) { return p.vms.DomainStateReason(rec.Name) })
		switch {
		case err != nil && !lv.IsNotFound(err):
			// Unreadable: dropping the record here would leave a paused
			// guest no pass ever resumes.
			p.hold(rec, "domain state unreadable: "+err.Error())
			return false, timedOutErr(err)
		case err == nil && st.Reason == "paused":
			// Asked again at the resume itself: the voters' answer took time.
			if why, _ := p.pauseNotOurs(rec, st, deadline); why != "" {
				p.hold(rec, why)
				return false, !time.Now().Before(deadline)
			}
			name, uuid := rec.Name, rec.DomainUUID
			// The mark goes first, so no crash can leave it beside a running
			// VM for a later pause someone else makes to match. Under the
			// mark lock, never waiting on it: a mark write or clear in flight
			// holds the resume to a later pass. The lock is held until every
			// mark call and the resume itself have returned, past the step's
			// deadline when one is abandoned (callWithin), so the mark a late
			// failure or a late landing's undo puts back is ordered with
			// every other mark write and clear of the VM. A record without a
			// token (from a build before the mark) has no mark to clear, but
			// its resume takes the lock all the same: settle destroys a paused
			// copy under it (SettleDestroy), and no resume may land between
			// settle's re-check and its destroy.
			var unlock func()
			l := p.markLock(name)
			if !l.TryLock() {
				p.hold(rec, "a write of the partition-pause mark, or a settle of the VM, is in flight")
				return false, false
			}
			var once sync.Once
			unlock = func() { once.Do(l.Unlock) }
			if rec.Token != "" {
				if owned, err := p.clearMarkWithin(rec, deadline, unlock); err != nil {
					if !owned {
						unlock()
					}
					p.hold(rec, "cannot take the partition-pause mark off before the resume: "+err.Error())
					return false, timedOutErr(err)
				}
			}
			// A resume that failed, or a late landing that was undone, leaves
			// the VM paused by this host's pause: its mark goes back on
			// (putBack). Not inside the call: the metadata write has no
			// timeout, and while the call holds the VM's key a pause pass
			// counts it as a resume that may yet land and kills its QEMU. It
			// runs in after, once the call has let go of the key, still
			// under the mark lock.
			var putBack atomic.Bool
			resumeVM := func() error {
				err := p.vms.ResumePartitionPaused(name, uuid)
				if err != nil {
					putBack.Store(true)
				}
				return err
			}
			undo := func() error {
				if err := p.vms.SuspendDomain(name); err != nil {
					return err
				}
				putBack.Store(true) // paused again by this host: its mark again
				return nil
			}
			after := func() {
				if putBack.Load() && rec.Token != "" {
					p.putMarkBack(rec)
				}
				unlock()
			}
			started, err := p.callWithinThen(rec.Key(), time.Until(deadline), true, resumeVM,
				func() { p.lateResume(rec, yesAt, undo) }, after)
			if !started {
				// The resume was never issued, and the mark is off: put it
				// back, off the step (the write has no timeout), still under
				// the lock. A tokenless record has no mark to put back.
				go func() {
					if rec.Token != "" {
						p.putMarkBack(rec)
					}
					unlock()
				}()
			}
			if err != nil {
				p.hold(rec, "resume failed: "+err.Error())
				return false, timedOutErr(err)
			}
		}
	case PauseKindContainer:
		if p.cts == nil {
			p.hold(rec, "no container runtime on this host")
			return false, false
		}
		name := rec.Name
		err := p.callWithin(rec.Key(), time.Until(deadline), true,
			func() error { return p.cts.Unfreeze(ctx, name) },
			func() {
				p.lateResume(rec, yesAt, func() error {
					fctx, cancel := context.WithTimeout(context.Background(), partitionPauseCallTimeout)
					defer cancel()
					return p.cts.Freeze(fctx, name)
				})
			})
		if err != nil {
			if timedOutErr(err) {
				p.hold(rec, "unfreeze failed: "+err.Error())
				return false, true
			}
			if fs, ok := p.cts.(frozenStater); !ok {
				p.hold(rec, "unfreeze failed: "+err.Error())
				return false, false
			} else if frozen, ferr := fs.IsFrozen(ctx, rec.Name); ferr != nil || frozen {
				p.hold(rec, "unfreeze failed: "+err.Error())
				return false, false
			}
		}
	}
	if err := p.removeRecord(rec.Kind, rec.Name); err != nil {
		slog.Warn("partition-pause: resumed, but could not drop the record", "kind", rec.Kind, "name", rec.Name, "error", err)
	}
	p.mu.Lock()
	delete(p.heldWhy, rec.Key())
	delete(p.notOurs, rec.Key())
	delete(p.markFailed, rec.Key())
	p.mu.Unlock()
	slog.Warn("partition-pause: resumed workload", "kind", rec.Kind, "name", rec.Name,
		"host", p.host, "reason", why)
	return true, false
}

// ── conditions ──────────────────────────────────────────────────────────────

type pausedEvidence struct {
	Paused []string `json:"paused"`
	Reason string   `json:"reason,omitempty"`
	Detail string   `json:"detail"`
	// NotPausedByThisHost names, with why, the recorded workloads that
	// something other than this host's pause has paused: held, never resumed
	// by the pauser.
	NotPausedByThisHost map[string]string `json:"not_paused_by_this_host,omitempty"`
}

// syncPausedCondition keeps partition_paused open exactly while a record
// exists. reason is the loss that caused the pause, when known this pass.
func (p *PartitionPauser) syncPausedCondition(ctx context.Context, reason string) {
	recs, err := p.store.list()
	if err != nil {
		return
	}
	keys := make([]string, 0, len(recs))
	var notOurs map[string]string
	p.mu.Lock()
	for _, r := range recs {
		keys = append(keys, r.Key())
		if reason == "" {
			reason = r.Reason
		}
		if why, ok := p.notOurs[r.Key()]; ok {
			if notOurs == nil {
				notOurs = map[string]string{}
			}
			notOurs[r.Key()] = why
		}
	}
	prevOpen, prevEvid, synced := p.pausedOpen, p.pausedEvid, p.pausedSynced
	p.mu.Unlock()
	if len(keys) == 0 {
		// No record: nothing on this host is paused by it, so the condition
		// describes a pause that has ended. The in-memory flag knows only
		// what THIS process opened; one a previous process opened is resolved
		// from the row itself.
		if !prevOpen && synced {
			return
		}
		if p.writeCondition(ctx, corrosion.CondPartitionPaused, corrosion.SeverityWarning, "", true) {
			p.mu.Lock()
			p.pausedOpen, p.pausedEvid, p.pausedSynced = false, "", true
			p.mu.Unlock()
		}
		return
	}
	b, _ := json.Marshal(pausedEvidence{Paused: keys, Reason: reason, NotPausedByThisHost: notOurs,
		Detail: "this host lost the voter majority and paused these workloads itself; each resumes once a majority of voters confirms nothing moved it"})
	if prevOpen && string(b) == prevEvid {
		return
	}
	if p.writeCondition(ctx, corrosion.CondPartitionPaused, corrosion.SeverityWarning, string(b), false) {
		p.mu.Lock()
		p.pausedOpen, p.pausedEvid = true, string(b)
		p.mu.Unlock()
	}
}

func (p *PartitionPauser) raiseFailed(ctx context.Context, failures map[string]string) {
	p.mu.Lock()
	for k, v := range failures {
		p.failed[k] = v
	}
	all := make(map[string]string, len(p.failed))
	for k, v := range p.failed {
		all[k] = v
	}
	p.mu.Unlock()
	b, _ := json.Marshal(struct {
		Failures map[string]string `json:"failures"`
		Detail   string            `json:"detail"`
	}{all, "this host lost the voter majority and could not pause these workloads; the majority does not rely on its pause while this is open"})
	if p.writeCondition(ctx, corrosion.CondPartitionPauseFailed, corrosion.SeverityCritical, string(b), false) {
		p.mu.Lock()
		p.failedOpen = true
		p.mu.Unlock()
	}
}

func (p *PartitionPauser) resolveFailed(ctx context.Context, why string) {
	p.mu.Lock()
	open := p.failedOpen || len(p.failed) > 0
	p.mu.Unlock()
	if !open {
		// An earlier process may have left it open.
		if failed, err := corrosion.HostPartitionPauseFailed(ctx, p.db, p.host); err != nil || !failed {
			return
		}
	}
	if p.writeCondition(ctx, corrosion.CondPartitionPauseFailed, corrosion.SeverityCritical, "", true) {
		p.mu.Lock()
		p.failedOpen = false
		p.failed = map[string]string{}
		p.mu.Unlock()
		slog.Info("partition-pause: pause failure resolved", "host", p.host, "reason", why)
	}
}

// writeCondition upserts one of this host's partition_pause conditions; it
// reports whether the write landed.
func (p *PartitionPauser) writeCondition(ctx context.Context, code, severity, evidence string, resolve bool) bool {
	ts := p.now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, p.db, corrosion.PartitionPauseEvaluator, code, "host", p.host)
	if err != nil {
		return false
	}
	if !ok {
		if resolve {
			return true
		}
		row = corrosion.HealthCondition{Evaluator: corrosion.PartitionPauseEvaluator, Code: code,
			SubjectKind: "host", SubjectID: p.host, FirstSeen: ts}
	}
	if resolve {
		if row.Lifecycle == corrosion.ConditionResolved {
			return true
		}
		row.Lifecycle, row.ResolvedAt, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, ts, 0, 1
	} else {
		if row.Lifecycle == corrosion.ConditionResolved {
			row.FirstSeen, row.ConfirmedAt, row.ObserveCount = ts, "", 0
		}
		row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
		if row.ConfirmedAt == "" {
			row.ConfirmedAt = ts
		}
		row.ObserveCount++
		row.Evidence = evidence
	}
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = severity, []string{p.host}, ts, p.host
	if err := corrosion.UpsertHealthCondition(ctx, p.db, row); err != nil {
		slog.Warn("partition-pause: could not record a condition (retried next pass)", "code", code, "error", err)
		return false
	}
	return true
}
