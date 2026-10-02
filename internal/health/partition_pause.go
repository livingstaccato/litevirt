package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
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
	// partitionPauseSlack covers scheduling and monotonic-clock rate error.
	partitionPauseSlack = 2 * time.Second
	// PartitionPauseMargin is what the majority adds to T_pause for a cluster
	// of up to probeConcurrency+1 hosts (one probe batch);
	// PartitionPauseMarginFor scales it.
	PartitionPauseMargin = max(0, (suspectThreshold+1)*max(checkInterval, checkTimeout)-(FailuresToFence-1)*checkInterval) +
		2*partitionPauseTick + PartitionPauseExecBudget + partitionPauseSlack
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
// quantisations, the pauses themselves and slack.
func PartitionPauseMarginFor(targets int) time.Duration {
	return max(0, minorityDetectBoundFor(targets)-(FailuresToFence-1)*checkInterval) +
		2*partitionPauseTick + PartitionPauseExecBudget + partitionPauseSlack
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
	SuspendDomain(name string) error
	ResumeDomain(name string) error
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
// (docs/design/partition-pause.md §3.5 step 3). Keyed by PauseRecord.Key. A
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
	host  string
	db    *corrosion.Client
	store pauseStore

	quorum    func(context.Context) (QuorumState, int, int)
	enabled   func() bool
	vms       PauseVMBackend
	cts       lxc.Runtime
	confirm   ResumeConfirmer
	armed     func() bool
	selfFence func()
	now       func() time.Time
	after     time.Duration
	tick      time.Duration

	mu sync.Mutex
	// lostAt is the local monotonic instant the current loss began; zero while
	// the quorum is held. A restart re-earns it, deliberately.
	lostAt      time.Time
	lostLive    int
	lostNeeded  int
	failed      map[string]string // key → error, this loss episode
	failedOpen  bool
	pausedEvid  string // evidence last written to partition_paused, "" when resolved
	pausedOpen  bool
	lastConfirm time.Time
	heldWhy     map[string]string // key → last logged hold reason
	exemptWhy   string
}

// NewPartitionPauser builds the monitor for host, recording under dataDir.
func NewPartitionPauser(host, dataDir string, db *corrosion.Client) *PartitionPauser {
	return &PartitionPauser{
		host: host, db: db, store: newPauseStore(dataDir),
		now: time.Now, after: PartitionPauseAfter, tick: partitionPauseTick,
		failed: map[string]string{}, heldWhy: map[string]string{},
	}
}

// SetQuorum wires the execution quorum (Checker.ExecutionQuorum).
func (p *PartitionPauser) SetQuorum(fn func(context.Context) (QuorumState, int, int)) { p.quorum = fn }

// SetEnabled wires enforcement.partition_pause. Off pauses nothing; what an
// earlier run paused is still resumed.
func (p *PartitionPauser) SetEnabled(fn func() bool) { p.enabled = fn }

// SetVMBackend wires the libvirt client (nil: no VMs).
func (p *PartitionPauser) SetVMBackend(b PauseVMBackend) { p.vms = b }

// SetContainerRuntime wires the LXC runtime (nil: no containers).
func (p *PartitionPauser) SetContainerRuntime(r lxc.Runtime) { p.cts = r }

// SetResumeConfirmer wires the majority check. nil confirms nothing.
func (p *PartitionPauser) SetResumeConfirmer(fn ResumeConfirmer) { p.confirm = fn }

// SetSelfFence wires the watchdog backstop for a pause that fails: armed
// reports a VERIFIED hardware watchdog, fence trips it. Either nil disables it.
func (p *PartitionPauser) SetSelfFence(armed func() bool, fence func()) {
	p.armed, p.selfFence = armed, fence
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
	t := time.NewTicker(p.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Evaluate(ctx)
		}
	}
}

// Evaluate is one pass: track the loss clock, pause once it has run T_pause,
// resume what the majority confirms once the quorum is back.
func (p *PartitionPauser) Evaluate(ctx context.Context) {
	if p.quorum == nil {
		return
	}
	state, live, needed := p.quorum(ctx)
	now := p.now()

	p.mu.Lock()
	if state == QuorumYes {
		wasLost := !p.lostAt.IsZero()
		p.lostAt = time.Time{}
		if wasLost {
			p.lastConfirm = time.Time{} // first resume check after a heal runs at once
		}
		p.mu.Unlock()
		p.resolveFailed(ctx, "the voter majority is back")
		p.tryResume(ctx, now)
		return
	}
	if p.lostAt.IsZero() {
		p.lostAt = now
		p.lostLive, p.lostNeeded = live, needed
		p.mu.Unlock()
		slog.Info("partition-pause: lost the voter majority; pausing recoverable workloads if it does not return",
			"host", p.host, "live", live, "needed", needed, "after", p.after)
		return
	}
	lostFor := now.Sub(p.lostAt)
	p.mu.Unlock()
	if lostFor < p.after {
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
	reason := fmt.Sprintf("lost the voter majority for %s (%d of %d needed live)",
		lostFor.Round(time.Second), live, needed)
	p.pauseAll(ctx, now, reason)
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
	failures := map[string]string{}
	if p.vms != nil {
		p.pauseVMs(ctx, reason, failures)
	}
	if p.cts != nil {
		p.pauseContainers(ctx, reason, failures)
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

func (p *PartitionPauser) pauseVMs(ctx context.Context, reason string, failures map[string]string) {
	names, err := p.vms.ListDomains()
	if err != nil {
		failures["vm/*"] = "list domains: " + err.Error()
		return
	}
	sort.Strings(names)
	var enrolled map[string]bool
	for _, name := range names {
		st, err := p.vms.DomainStateReason(name)
		if err != nil || st.State != RuntimeRunning {
			continue // not executing (or unreadable): nothing to stop, and a paused one is not ours
		}
		vm, err := corrosion.GetVM(ctx, p.db, name)
		if err != nil || vm == nil || vm.HostName != p.host {
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
		rec := PauseRecord{Kind: PauseKindVM, Name: name, Host: p.host, OwnerEpoch: vm.OwnerEpoch,
			Incarnation: corrosion.IncarnationOf(vm.CreatedAt), PausedAt: p.now().UTC().Format(time.RFC3339), Reason: reason}
		if err := p.pauseOne(rec, func() error { return p.vms.SuspendDomain(name) }); err != nil {
			failures[rec.Key()] = err.Error()
		}
	}
}

func (p *PartitionPauser) pauseContainers(ctx context.Context, reason string, failures map[string]string) {
	names, err := p.cts.List(ctx)
	if err != nil {
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
	for _, name := range names {
		row, ok := byName[name]
		if !ok || !corrosion.ContainerRecoverableOnHostFailure(row) {
			continue
		}
		st, err := p.cts.State(ctx, name)
		if err != nil || st != lxc.StateRunning {
			continue
		}
		// lxc.Runtime.State folds FROZEN into running. With IsFrozen a frozen
		// container is skipped — ours already, or someone else's, and never ours
		// to resume. Without it a container we recorded is assumed frozen (a
		// second freeze is at best a no-op), and one we did not is frozen.
		_, recorded, _ := p.store.get(PauseKindContainer, name)
		if fs != nil {
			if frozen, ferr := fs.IsFrozen(ctx, name); ferr == nil && frozen {
				continue
			}
		} else if recorded {
			continue
		}
		rec := PauseRecord{Kind: PauseKindContainer, Name: name, Host: p.host, OwnerEpoch: row.OwnerEpoch,
			Incarnation: corrosion.IncarnationOf(row.CreatedAt), PausedAt: p.now().UTC().Format(time.RFC3339), Reason: reason}
		if err := p.pauseOne(rec, func() error {
			cctx, cancel := context.WithTimeout(ctx, partitionPauseCallTimeout)
			defer cancel()
			return p.cts.Freeze(cctx, name)
		}); err != nil {
			failures[rec.Key()] = err.Error()
		}
	}
}

// pauseOne records rec, then runs pause. A pause that fails cleanly drops the
// record (the workload is not paused); one that times out keeps it, since it
// may still land, and a paused workload with no record is never resumed.
func (p *PartitionPauser) pauseOne(rec PauseRecord, pause func() error) error {
	if err := p.store.put(rec); err != nil {
		return fmt.Errorf("record the pause durably: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- pause() }()
	select {
	case err := <-done:
		if err != nil {
			if rerr := p.store.remove(rec.Kind, rec.Name); rerr != nil {
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

// tryResume runs the resume checks over every record (§3.5).
func (p *PartitionPauser) tryResume(ctx context.Context, now time.Time) {
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
	for _, rec := range recs {
		if why := p.localRowMatches(ctx, rec); why != "" {
			p.hold(rec, why)
			continue
		}
		candidates = append(candidates, rec)
	}
	if len(candidates) > 0 {
		p.mu.Lock()
		due := p.lastConfirm.IsZero() || now.Sub(p.lastConfirm) >= partitionResumeRecheck
		if due {
			p.lastConfirm = now
		}
		p.mu.Unlock()
		if due {
			var verdicts map[string]ResumeVerdict
			if p.confirm != nil {
				verdicts = p.confirm(ctx, candidates)
			}
			for _, rec := range candidates {
				v, ok := verdicts[rec.Key()]
				switch {
				case p.confirm == nil:
					p.hold(rec, "no majority confirmation is wired on this host")
				case !ok:
					p.hold(rec, "the voter set returned no verdict")
				case !v.OK:
					p.hold(rec, v.Reason)
				default:
					p.resume(ctx, rec, v.Reason)
				}
			}
		}
	}
	p.syncPausedCondition(ctx, "")
}

// localRowMatches is §3.5 step 2: the row in this host's replica still names
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
			return "no live row on this host (relocated?)"
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

// resume continues rec's workload and drops its record.
func (p *PartitionPauser) resume(ctx context.Context, rec PauseRecord, why string) {
	switch rec.Kind {
	case PauseKindVM:
		if p.vms == nil {
			p.hold(rec, "no libvirt backend on this host")
			return
		}
		st, err := p.vms.DomainStateReason(rec.Name)
		if err == nil && st.Reason == "paused" {
			if err := p.vms.ResumeDomain(rec.Name); err != nil {
				p.hold(rec, "resume failed: "+err.Error())
				return
			}
		}
	case PauseKindContainer:
		if p.cts == nil {
			p.hold(rec, "no container runtime on this host")
			return
		}
		cctx, cancel := context.WithTimeout(ctx, partitionPauseCallTimeout)
		err := p.cts.Unfreeze(cctx, rec.Name)
		cancel()
		if err != nil {
			if fs, ok := p.cts.(frozenStater); !ok {
				p.hold(rec, "unfreeze failed: "+err.Error())
				return
			} else if frozen, ferr := fs.IsFrozen(ctx, rec.Name); ferr != nil || frozen {
				p.hold(rec, "unfreeze failed: "+err.Error())
				return
			}
		}
	}
	if err := p.store.remove(rec.Kind, rec.Name); err != nil {
		slog.Warn("partition-pause: resumed, but could not drop the record", "kind", rec.Kind, "name", rec.Name, "error", err)
	}
	p.mu.Lock()
	delete(p.heldWhy, rec.Key())
	p.mu.Unlock()
	slog.Warn("partition-pause: resumed workload", "kind", rec.Kind, "name", rec.Name,
		"host", p.host, "reason", why)
}

// ── conditions ──────────────────────────────────────────────────────────────

type pausedEvidence struct {
	Paused []string `json:"paused"`
	Reason string   `json:"reason,omitempty"`
	Detail string   `json:"detail"`
}

// syncPausedCondition keeps partition_paused open exactly while a record
// exists. reason is the loss that caused the pause, when known this pass.
func (p *PartitionPauser) syncPausedCondition(ctx context.Context, reason string) {
	recs, err := p.store.list()
	if err != nil {
		return
	}
	keys := make([]string, 0, len(recs))
	for _, r := range recs {
		keys = append(keys, r.Key())
		if reason == "" {
			reason = r.Reason
		}
	}
	p.mu.Lock()
	prevOpen, prevEvid := p.pausedOpen, p.pausedEvid
	p.mu.Unlock()
	if len(keys) == 0 {
		if !prevOpen {
			return
		}
		if p.writeCondition(ctx, corrosion.CondPartitionPaused, corrosion.SeverityWarning, "", true) {
			p.mu.Lock()
			p.pausedOpen, p.pausedEvid = false, ""
			p.mu.Unlock()
		}
		return
	}
	b, _ := json.Marshal(pausedEvidence{Paused: keys, Reason: reason,
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
