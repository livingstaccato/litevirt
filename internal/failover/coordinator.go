// Package failover implements the fast failover coordinator for litevirt.
// When a host is detected as offline (consecutive health failures ≥ threshold),
// the coordinator fences it and reschedules its VMs onto healthy hosts.
package failover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/obs"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/randid"
)

const (
	// pollInterval is how often the coordinator checks for offline hosts.
	pollInterval = 5 * time.Second
	// offlineThreshold is the number of consecutive failures before a host
	// is considered offline by the coordinator. It is defined in package
	// health because the stall guard's grace window is derived from it.
	offlineThreshold = health.FailuresToFence
	// leaseDuration is the TTL for the failover-leader lease. It has to clear
	// minFenceLease with room to spare: holdLeaseAtLeast requires STRICTLY more
	// than the floor, so a lease whose full term only just reaches it could
	// never authorise a fence at all.
	//
	// Raising it past the old 30 s costs takeover latency — a leader that dies
	// holds its row for up to this long before anyone else can act. That is the
	// deliberate trade: a delayed takeover is recoverable, a fence cut off
	// mid-verification is reported as a failure and strands the VMs it was
	// supposed to move.
	leaseDuration = 45 * time.Second
	// leaseRenewBefore is how much head-room the leader has to renew before
	// the lease expires. Failover renews when remaining time drops below this.
	// It must stay below minFenceLease, or holdLease and holdLeaseAtLeast would
	// disagree about when a lease is healthy enough to act on.
	leaseRenewBefore = 10 * time.Second
	// minFenceLease is the lease head-room required before a fence may START.
	//
	// It must cover the whole call it gates, not part of it. An IPMI fence
	// spends up to fence.ipmitoolPerCallTimeout (8 s) sending the power-off and
	// then up to fence.PowerOffVerifyTimeout (15 s) confirming the chassis is
	// actually down — 23 s, which fence.WorstCasePowerOff() states once so this
	// floor and that budget cannot drift apart.
	//
	// Two failures sit either side of this number. Too low and the deadline
	// derived from it (minFenceLease - leaseFenceMargin) cuts a slow but
	// SUCCESSFUL power-off off part-way through verification: fenceIPMI
	// correctly refuses to call an unconfirmed power-off confirmed, the
	// coordinator logs "partial", and a host that is genuinely off keeps its
	// VMs stopped. Too low in the other direction — below the call's length —
	// and the fence outlives the lease that authorised it, a second coordinator
	// takes the row mid-call, and two nodes fence and reschedule the same host.
	//
	// This is a floor, not a budget: the actual deadline comes from the lease
	// time this node really holds, which is usually the full leaseDuration.
	// TestFailover_AFreshLeaseSatisfiesTheFenceFloor pins the arithmetic.
	minFenceLease = 30 * time.Second
	// leaseFenceMargin is withheld from the fence deadline so the call returns
	// while this node is still demonstrably the leader, leaving room for the
	// post-fence re-check to read the lease row before it expires.
	leaseFenceMargin = 5 * time.Second
	// failoverLeaseKey is this coordinator's row in leader_election. Named once
	// so the acquire and the three read sites cannot drift apart; it used to be
	// a bare 'failover' literal repeated in each of them.
	//
	// It aliases corrosion.LeaseKeyFailover rather than re-spelling the string,
	// so an enforcement path outside this package and this coordinator can never
	// disagree about which ledger the failover lease lives in.
	failoverLeaseKey = corrosion.LeaseKeyFailover
	// healthFreshness is the maximum age of a host_health row that may count
	// toward fencing quorum. Stale rows from dead observers must not fence
	// hosts they last saw failing days ago.
	healthFreshness = 30 * time.Second
	// recentFenceWindow gates re-fencing of a host for which the fencing_log
	// already shows a successful fence in the recent past.
	recentFenceWindow = 5 * time.Minute
	// upgradingTimeout bounds how long a host may sit in the 'upgrading' state
	// (set by `lv host upgrade` or by a daemon on graceful SIGTERM restart)
	// before the coordinator treats it as a genuine failure. Long enough for a
	// binary stream + restart, short enough that a host that died mid-upgrade
	// still fails over instead of stranding its VMs forever.
	upgradingTimeout = hostboot.UpgradingTimeout
	// defaultRelocateRestoreTimeout is the fallback for Coordinator.RelocateRestoreTimeout
	// (config container_restore_timeout_sec): how long a relocate-restore marker is
	// treated as in-flight before the coordinator gives up and image-recreates.
	defaultRelocateRestoreTimeout = 10 * time.Minute
)

// Fencer abstracts fence.Execute so tests can inject a stub. Production code
// uses fence.Execute directly via the default value.
type Fencer func(ctx context.Context, h fence.HostConfig) fence.Result

// ReplicaPromoter promotes a VM's freshest replica onto a healthy host. The
// grpcapi server implements it; the coordinator calls it during failover for
// VMs whose replication schedule opted into auto_promote, so a VM on the fenced
// host's local storage can resume from its replica instead of failing to start
// for want of a disk. Optional — nil disables auto-promotion.
type ReplicaPromoter interface {
	// fenceEpoch binds the promote proof to the specific proof-grade fence of the
	// old owner that authorizes this cross-host transfer (see proofGradeFenceRef);
	// "" when no proof-grade fence exists (a best-effort/SSH fence), which the
	// executor treats as fail-closed for a shared-disk VM.
	AutoPromoteReplica(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64) error
}

// ContainerRestorer restores a container onto a survivor host from its latest
// valid backup. The grpcapi server implements it; the coordinator calls it
// during host-loss relocation to prefer a faithful restore-from-backup
// (networking + non-image state) over a bare image-recreate. Optional — nil
// disables tier-2 and the coordinator always image-recreates.
type ContainerRestorer interface {
	// RestoreContainerFromBackup drives the restore on targetHost and classifies
	// the result (corrosion.RestoreOutcome): the signal is the TARGET's, so the
	// coordinator needn't read its own (replication-lagged) replica. Landed ⇒
	// complete; NotAttempted/FailedBeforeRow ⇒ fall back; Unknown ⇒ defer (the row
	// may have landed but the confirmation was lost).
	RestoreContainerFromBackup(ctx context.Context, ctName, targetHost, token string) (corrosion.RestoreOutcome, error)
}

// Coordinator watches for host failures and triggers failover.
type Coordinator struct {
	hostName string
	db       *corrosion.Client
	fencer   Fencer
	// FenceSSH decides how an ssh or best-effort fence from this node
	// reaches its target (fencessh.Agent.FenceConfig): managed, pinned, or
	// refused. Nil is the legacy path, unpinned.
	FenceSSH func(ctx context.Context, target string) fence.SSHFence
	// capacity is the cluster-wide capacity policy; see placement.Request.Capacity.
	capacity corrosion.CapacityPolicy
	// nicGuardPlacement: SetNICGuardPlacement.
	nicGuardPlacement func(ctx context.Context, vm string) bool
	// leaseTerm is the fencing term of the lease incarnation this coordinator
	// currently holds, 0 when it holds none. Recorded here in Phase 1 and read by
	// the Phase-2 enforcement path; nothing enforces on it yet.
	//
	// Atomic because Phase 2 adds readers outside the poll loop. Today every
	// access is on the single poll goroutine (acquireLease is reached only from
	// the poll cycle and from holdLease within it), so the atomic is
	// future-proofing rather than a fix for a live race — unlike the
	// rebalancer's, which has two concurrent callers.
	leaseTerm atomic.Int64
	// leaseGap is set when another node holds or claims the lease (loseLease),
	// and when this one takes it as a new tenure (acquireLeaseTenure): another
	// node may have led in between. A read error or a stand-down alone does
	// not set it (dropLeaseTerm). The next cycle that holds the lease then
	// forgets every host's outage (forgetEpisodes) and re-derives it from the
	// replicated records, as a successor would.
	leaseGap atomic.Bool
	// tenureTerm is the term of the last lease incarnation this coordinator
	// held, kept across a drop (leaseTerm is cleared by one), and everHeld
	// whether it has held one at all. Together with the lease row as it stands
	// before a re-take (ownTenureLive) they tell a lease this node never
	// stopped holding from a new tenure (acquireLeaseTenure).
	tenureTerm atomic.Int64
	everHeld   atomic.Bool
	// unshownSince is when this coordinator last stopped being able to show
	// it holds the lease (dropLeaseTerm), on the monotonic clock (c.mono), so
	// a wall-clock step cannot shorten a stand-down; nil while it holds it.
	// Before lease terms are minted it bounds how long a stand-down may last
	// and still continue the tenure (acquireLeaseTenure).
	unshownSince atomic.Pointer[time.Time]
	// cyclePolicy is the failover scope and voter regions read once for the
	// cycle in progress (run), nil outside one. Only the poll goroutine
	// touches it.
	cyclePolicy *health.DecisionPolicy
	// leaseQuorumLost is whether the last lease attempt stood down because this
	// node had lost every quorum it could decide on, so the change is logged
	// once rather than every poll.
	leaseQuorumLost atomic.Bool
	// recoverOnly limits every recovery of a host to the workloads listed for
	// it ("kind/name", health.PauseKindVM or health.PauseKindContainer): a
	// self-paused host answering through a bridge is recovered only for what
	// it reported pausing (selfPauseStillStands). It lasts for the
	// down-episode (limitRecovery, unlimitRecovery). No entry recovers
	// everything.
	recoverOnly map[string]map[string]bool
	// unpausedHeld names, per host, the workloads a limited recovery has left
	// on it, so the stall alert keeps naming them whatever newer hold reason
	// is recorded. It lasts as recoverOnly does.
	unpausedHeld map[string]map[string]bool
	// Promoter, when set, lets failover promote replicas for auto_promote VMs.
	Promoter ReplicaPromoter
	// Restorer, when set, lets host-loss relocation restore a container from its
	// latest backup before falling back to image-recreate. nil → image-recreate only.
	Restorer ContainerRestorer
	// RelocateRestoreTimeout bounds how long a relocate-restore marker is treated
	// as in-flight before the coordinator gives up on the restore and falls back
	// to image-recreate. 0 → defaultRelocateRestoreTimeout.
	RelocateRestoreTimeout time.Duration
	// fencing tracks hosts that have already been fenced in this session
	// to avoid double-fencing on repeated poll cycles.
	fenced map[string]bool
	// handledAt is, per host in fenced, when its recorded state was written
	// as it was marked handled (markHandled, upgradingSinceHandled).
	handledAt map[string]handledMark
	// fenceRelocated records, for hosts THIS coordinator fenced, whether the
	// fence actually relocated any VMs. Presence of a key means "fenced by me
	// this session"; the value is "did VMs move". A spuriously-fenced host that
	// relocated nothing (value=false) can auto-recover to active once healthy;
	// one that moved VMs (value=true) must wait for a manual `undrain` to avoid
	// split-brain. Absent key ⇒ we can't prove it's safe ⇒ stays manual.
	fenceRelocated map[string]bool
	// skipAudited is the failover.skip state last audited per host and
	// workload (auditSkip).
	skipAudited map[string]string
	// fencedOn records, per host in c.fenced, the fencing_log id of the fence
	// this coordinator's recovery acted on ("" when it acted on none). A
	// successful fence recorded since is news the cached host must not hide
	// (fenceAuthorityChanged, lab drill S5).
	fencedOn map[string]string
	// lastFenceAt is, per host, when this coordinator last ran a fence of it,
	// on its own clock; the failed-fence retry counts its backoff from it
	// when that is later than the row (fenceRetryDue).
	lastFenceAt map[string]time.Time
	// retrying is the plan of the failed-fence retry failover is running, or
	// nil for any other fence; it decides whether the fence notifies
	// (fenceNotifies).
	retrying *fenceRetry
	// retryNotified is, per host, when a failed retry last notified.
	retryNotified map[string]time.Time
	// retryRefusedLogged is, per host, the failed attempt and reason of the
	// last refused retry logged at Warn (logRetryRefused).
	retryRefusedLogged map[string]string
	// cycleCandidates is the set of fence candidates of the current cycle,
	// for the stall alert's default reason.
	cycleCandidates map[string]bool
	// upgradingLives is, per host, the last span this holder saw it recorded
	// 'upgrading' (noteUpgradingLives, upgradingLifeGrace).
	upgradingLives map[string]UpgradingLife
	// holdReason is, per host, why its recovery last did not proceed; the
	// stall alert names it (alertStalledRecoveries).
	holdReason map[string]string
	// holdBase is, per host, the hold reason last noted (noteHold) before any
	// stale operator confirmation was appended to it (noteConfirmationStale),
	// so that note, repeated every cycle, is appended to the hold rather than
	// replacing it.
	holdBase map[string]string
	// lastStale is, per host, the newest note of an operator confirmation
	// that does not stand (noteConfirmationStale), and unprovenRaised the
	// reason ha.recovery.unproven_fence was last raised with: the settle
	// sweep re-raises with both, so the condition's detail stays current.
	lastStale      map[string]string
	unprovenRaised map[string]unprovenRaise
	// restsOnTrust names the hosts whose recovery went ahead on a trusted SSH
	// power-off, for an owed claim retry to re-judge (retryClaims).
	restsOnTrust map[string]bool
	// lastFenceFailure is, per host, the method and detail of the newest
	// fence this coordinator saw fail, for the retry hold (retryHold).
	lastFenceFailure map[string]string
	// stallSince and stallAlerted are the stall alert's clock and its last
	// alert, per host (alertStalledRecoveries).
	stallSince   map[string]time.Time
	stallAlerted map[string]time.Time
	// stallUnfenced names the hosts whose stall clock started while an HA
	// hold kept them from being fenced (heldBeforeFence); their fence, once
	// HA is armed, starts the clock again from its record.
	stallUnfenced map[string]bool
	// OnRecoveryStalled, when set, is invoked when a fenced or offline host's
	// recoverable workloads are still on it recoveryStallAfter after its fence
	// record, and again at most every recoveryStallRepeat, so the daemon can
	// emit an operator notification. Also for a quorum-down host an HA hold
	// keeps from being fenced, recoveryStallAfter after the hold was first
	// seen. Best-effort; must not block.
	OnRecoveryStalled func(host, coordinator, reason string, pending int, since time.Time)
	// confirmResumed records, per host, the operator confirmation a recovery
	// was already resumed from in this process, so one confirmation resumes one
	// recovery rather than one per cycle. Losing it on restart costs at most one
	// repeat, which recoverWorkloads tolerates: it re-derives its work from the
	// rows still pointing at the host.
	confirmResumed map[string]string
	// afreshConfirm records, per host, the operator confirmation this
	// coordinator sent the host down the fence path on (confirmationFencesAfresh),
	// until the next fence decision for the host. The fence it ran then is its
	// own act on that confirmation, not a sign the host ran since it
	// (newestProofGradeFenceWhy).
	afreshConfirm map[string]string
	// staleTermHeld is, per VM, the step at which sweepStaleTermProofs last
	// recorded the VM held (noteStaleTermHeld), so a step retried every cycle
	// is recorded once.
	staleTermHeld map[string]string
	// LocalStall reports whether THIS node stopped running within the last
	// health.StallGrace (implemented by *health.Checker.InStallGrace). While it
	// is true the coordinator decides no new fence: a node that was suspended,
	// swapped out or starved a moment ago has not been watching, and the view it
	// resumes with — its own probe results, and the replicated rows it has not
	// yet caught up on — is the least trustworthy it will ever hold. Recovery
	// resumed from an already-recorded fence is not a new judgement and is not
	// held back. nil (a hand-built coordinator) never defers.
	LocalStall func() bool
	// Now is the time source for lease TTL / fencing-log timestamps.
	// Defaults to time.Now; the fleet harness overrides it with a
	// virtual clock so scenarios can advance time deterministically
	// past the recentFenceWindow / lease expiry without sleeping.
	Now func() time.Time
	// UpgradingTimeout, when set, replaces upgradingTimeout: how long a host
	// recorded 'upgrading' is skipped before it is treated as failed. For
	// fleet scenarios, which cannot wait out two minutes.
	UpgradingTimeout time.Duration
	// OnFence, when set, is invoked after a fence is recorded so the daemon can
	// emit an operator notification (#5). Best-effort; must not block.
	OnFence func(host, method, result, detail string)
	// OnDiskStranded, when set, is invoked after a reschedule leaves a VM's
	// host-local disks on the failed host (stranded_disk.go), so the daemon
	// can raise the vm.disk.stranded notification.
	OnDiskStranded func(vm, host, detail string)
	// OnRootfsStranded, when set, is invoked after a container relocation
	// leaves the container's own rootfs on the failed host.
	OnRootfsStranded func(ct, host, detail string)
	// Events, when set, carries the coordinator's workload events (a stopped
	// workload left on a failed host, skip_stopped.go) to this host's live
	// event stream. Optional; a VM's event is also kept in vm_events.
	Events *events.Bus
	// Metrics, when set, counts failover decisions/outcomes/errors by
	// phase+result+error_class (U9). Optional + nil-safe (see metrics.go).
	Metrics Metrics
	// Gate is the split-brain safety gate (Phase 1), implemented by *health.Checker.
	// When set AND split_brain_gate_v1 is cluster-wide, the reschedule decide site
	// requires DecisionGate and writes a durable, single-use runtime_action_proofs
	// row linked to the VM's pending transition. nil / pre-activation → legacy path.
	Gate FailoverGate
	// SafeFenceEnforce is the per-node kill-switch for the safe-fence-default policy
	// (config.Enforcement.SafeFenceDefault). Enforcement is this flag AND the
	// SafeFenceDefaultV1 capability latch; the zero value (false) preserves the
	// legacy proceed-anyway behavior, so a hand-built Coordinator / test is unaffected
	// until explicitly enabled. Wired by the daemon.
	SafeFenceEnforce bool
	// SharedStorageFenceEnforce is the per-node kill-switch for the shared-disk
	// ownership-transfer fence gate (config.Enforcement.SharedStorageFence).
	// Enforcement is this flag AND the SharedStorageFenceV1 capability latch. When
	// enforced, the coordinator refuses to CREATE a cross-host transfer of a VM with
	// a writable shared disk unless it has a proof-grade fence of the old owner
	// (a non-empty fence_epoch) — failing closed at the SOURCE so a config-skewed or
	// regressed target can never receive an unfenced shared-disk transfer. Wired by
	// the daemon.
	SharedStorageFenceEnforce bool
	// LeaseTermEnforce is the per-node kill-switch for leader-lease term
	// enforcement (config.Enforcement.LeaseTerm). Enforcement is this flag AND the
	// LeaseTermV1 capability latch, matching the executor's own predicate
	// (grpcapi's leaseTermEnforced) — the two halves of one decision, and they
	// must agree. When enforced, the coordinator refuses to stamp a proof whose
	// term has been superseded. It is a precheck, not the guarantee: the
	// executor's quorum barrier is, because a stale coordinator can skip this and
	// nothing can skip that. Wired by the daemon.
	//
	// It does NOT run "before any destructive work", and must not be described
	// that way. Every stamp site is reached AFTER the host has been fenced —
	// c.fenced is set and the fencer has run long before, and the host row is
	// already persisted offline — so a refusal here abandons a workload whose host
	// is already powered off. A fenced host is processed only once (see the
	// auto-promote fallback comment in failover), so nothing revisits it: that is
	// why the threshold read below fails OPEN, and why a refusal on this path is a
	// last resort rather than a cheap safety net.
	LeaseTermEnforce bool
	// onGateRefused observes gate refusals at decide sites (nil-safe; daemon wires
	// it to litevirt_runtime_action_refused_total).
	onGateRefused func(action, reason string)
	// fenceHeldDecided is a test seam (SetFenceHeldDecidedForTest).
	fenceHeldDecided func(host string)
	// scope is this cycle's quorum rule — the failover_scope policy and the
	// voter set with every host's region — read once at the top of run. The
	// zero value is the cluster-wide rule, so a path reached outside run (a
	// hand-built test) behaves exactly as before region scoping existed.
	scope quorumView
	// regionDeclined records, per host, the class under which region scoping
	// last declined to fence it, so the explanation is logged once per change
	// rather than once per poll. See noteRegionDeclined.
	regionDeclined map[string]string
	// resumeDeclined records, per host, the fence ID resumeActionFor last found
	// no longer standing, so the explanation is logged once per fence rather
	// than once per poll. See noteResumeDeclined.
	resumeDeclined map[string]string
	// confirmStale records, per host, the operator confirmation last found no
	// longer standing, so the refusal is logged once per confirmation rather
	// than once per poll. See noteConfirmationStale.
	confirmStale map[string]string
	// notRelying records, per host, why relyOnPartitionPause last declined to
	// rely on its pause, so the reason is logged once per change rather than
	// once per poll. See noteNotRelying.
	notRelying map[string]string
	// SelfFenced reports whether THIS node has self-fenced (tripped the watchdog) and is
	// waiting to reboot. A doomed node must not drive ANY failover decision during that
	// window, even if quorum transiently returns first. Wired by the daemon from the
	// watchdog controller; nil → never fenced.
	SelfFenced func() bool
	// VoterGenesis, when set, runs once per tick in which this coordinator
	// holds the leader lease, with the lease term (the ballot round seed). It
	// is automatic voter genesis (grpcapi.Server.VoterGenesisTick,
	// docs/design/recovery-claims.md §4.2): the lease keeps usually one
	// proposer active, and genesis being a claim makes two lease holders decide
	// one value. It returns at once on a cluster that already has a voter
	// generation. nil (a hand-built coordinator) never proposes.
	VoterGenesis func(ctx context.Context, leaseTerm int64)
	// ClaimHealth, when set, runs once per tick in which this coordinator
	// holds the lease: the recovery-claim health conditions
	// (grpcapi.Server.RecoveryClaimHealthTick — ha.claim.stranded,
	// ha.voter.unavailable). nil never evaluates them.
	ClaimHealth func(ctx context.Context)
	// PressureHealth, when set, runs once per tick in which this coordinator
	// holds the lease: the host.pressure conditions, written from each
	// host's latest readiness-probe answer (grpcapi.Server.PressureHealthTick),
	// so a host that cannot write is still described. It only reports. nil
	// never evaluates them.
	PressureHealth func(ctx context.Context)
	// Claimer decides recovery claims (docs/design/recovery-claims.md §3.13):
	// *grpcapi.Server, whose proposer reaches every member of the adopted
	// voter generation. Consulted only while RecoveryClaimEnforced says so.
	Claimer RecoveryClaimer
	// RecoveryClaimEnforced is the enforcement predicate — the flag AND the
	// recovery_claim_v1 latch AND an adopted voter generation — wired to
	// grpcapi.Server.RecoveryClaimEnforced so this coordinator and the
	// executors on its node read one answer. nil (a hand-built coordinator)
	// never claims.
	RecoveryClaimEnforced func(ctx context.Context) bool
	// SettleMigratingRows decides the VMs whose rows say `migrating` on
	// source, a host being recovered, in one call per pass: it asks each
	// migration's target once whether the guest runs there, and re-points a
	// row to a target that runs it (grpcapi.Server.SettleFailedSourceMigrations).
	// A VM it gives no decision, or a nil hook (a hand-built coordinator),
	// is held (migrating_row.go).
	// askBy is the poll's one deadline for every ask of a target, across all
	// the hosts it recovers (migratingAskBy).
	SettleMigratingRows func(ctx context.Context, source string, vms []corrosion.VMRecord, askBy time.Time) map[string]MigratingDecision
	// migratingAskBy is this poll's deadline for SettleMigratingRows' asks,
	// set once at the start of each run.
	migratingAskBy time.Time
	// askNow replaces the real clock migratingAskBy is read on (unit tests).
	askNow func() time.Time
	// claimRetry records hosts whose recovery had a claim refused, so the next
	// tick re-runs it; a fenced host is otherwise processed once (claims.go).
	claimRetry map[string]bool
	// claimRetryAt records, per host, the moment its last recovery went
	// ahead (its fence's, its partition-pause deadline's wait start, or an
	// operator confirmation's), on this coordinator's clock: the authority a
	// claim retry owed to that recovery acts on (claimRetryOutageOver).
	claimRetryAt map[string]time.Time
	// claimRetryMono is claimRetryAt on this node's monotonic clock, the one
	// LastContact reports on: a healthy probe of the host by this node after
	// it ends the outage the retry is owed to (claimRetryOutageOver).
	claimRetryMono map[string]time.Time
	// claimRetryHeld records, per host, the state in which an owed claim
	// retry was last held for not being fenced or offline, so the hold is
	// logged once per state (claimRetryOutageOver).
	claimRetryHeld map[string]string
	// relocDeferred records, per proof ID, when this coordinator first saw a
	// container relocation decided for ANOTHER coordinator that it has not
	// seen carried out. It completes that relocation itself only once the
	// decision has stood unexecuted for RelocateRestoreTimeout (claimed
	// container relocations, coordinator.go).
	relocDeferred map[string]time.Time
	// skipRetried records, per container on a removed host, the target its
	// relocate-skipped retry last tried with no image to re-pull
	// (relocate_skipped_retry.go).
	skipRetried map[string]string
	// claimRetryProposals holds, per claim key, the proposal the voters last
	// refused because the recorded owner was still reachable (or its settled
	// row named another). The next tick re-proposes THAT value — same proof
	// ID, same token — so it can retry at the same round: nothing was
	// contending, so nothing should have to outrank it (§3.13 step 6).
	claimRetryProposals map[corrosion.ClaimKey]claimRetryProposal
	// PartitionPauseEnforced is the majority's reliance predicate for partition
	// pause (docs/design/partition-pause.md §4.3): enforcement.partition_pause
	// on this node AND partition_pause_v1 latched. When it holds, an assumed
	// best-effort fence is recorded as self-pause and recovery waits out
	// PartitionPauseWaitFor. nil (a hand-built coordinator) never relies.
	PartitionPauseEnforced func(ctx context.Context) bool
	// PeerPausesOnLoss reports whether a host's latest answer to this node's
	// health probe said it pauses on losing the majority
	// (grpcapi.Server.PeerPausesOnLoss). The coordinator relies on a host's
	// partition pause only if that HOST said so, not merely because the
	// cluster latched it: a host whose flag went off after the latch says
	// otherwise on its next probe. nil never relies.
	PeerPausesOnLoss func(peer string) bool
	// PeerHAState returns a peer's latest answer to this node's health probe
	// about the cluster HA policy, and false when there is none
	// (grpcapi.Server.PeerHAAnswer). nil: no peer veto (ha_disarm.go).
	PeerHAState func(peer string) (PeerHAAnswer, bool)
	// LiveVoters is the set of voters this node's quorum counts live
	// (health.Checker.LiveVoters): the voters the peer veto reads. With
	// PeerHAState wired and this nil, every decision is vetoed no_quorum.
	LiveVoters func(voters, uncounted map[string]bool) map[string]bool
	// HAPeerVetoGauge, when set, is litevirt_ha_peer_veto.
	HAPeerVetoGauge func(on bool)
	// AnswerWindow replaces PeerAnswerWindow (fleet scenarios, which shorten
	// the HA handler's matching wait). 0 in production.
	AnswerWindow time.Duration
	// ha is the HA-disarm memory (ha_disarm.go).
	ha haDisarmState
	// PeerRecoveryExclusions says which peers must not be a VM recovery
	// target while pit_overlay is in use, and why: one whose own Ping says it
	// is WAL-quarantined (rolled back below a latched token), and one that
	// does not answer. All are asked at once under one short deadline
	// (grpcapi.Server.PeerRecoveryExclusions). pitOverlaySafeTargets applies
	// it, even before the HA monitor records such a host isolated. Nil: only
	// recorded isolation counts.
	PeerRecoveryExclusions func(ctx context.Context, peers []string) map[string]string
	// PauseWaitFor replaces health.PartitionPauseWaitFor (fleet scenarios,
	// which cannot wait production seconds). nil in production.
	PauseWaitFor func(probeTargets int) time.Duration
	// Mono is the monotonic clock the pause deadline is measured on (default
	// time.Now). Never Now, which the fleet harness makes virtual.
	Mono func() time.Time
	// QuorumRegain reports, for a quorum scope (health.QuorumScopeCluster or
	// health.RegionQuorumScope), whether that quorum is lost now or was
	// regained within health.QuorumRegainGrace
	// (health.Checker.InQuorumRegainGraceFor). While it does, no new fence
	// that rests on that quorum is decided. nil never defers.
	QuorumRegain func(ctx context.Context, scope string) bool
	// LastContact reports this node's last successful probe of a host
	// (health.Checker.LastContact), the second anchor of the pause deadline.
	// nil anchors on the decision alone.
	LastContact func(host string) (time.Time, bool)
	// PeerClockSkew reports a peer's clock skew from this node as this run
	// last measured it (health.Checker.MeasuredClockSkew). nil, or a peer it
	// has not measured, leaves the skew unknown (observerSkews).
	PeerClockSkew func(peer string) (time.Duration, bool)
	// PeerVoterGeneration reports the highest voter generation peer said it
	// had adopted in a Ping this node received before `before`
	// (grpcapi.Server.PeerVoterGeneration). nil, or no such report, is no
	// evidence (regainCandidates).
	PeerVoterGeneration func(peer string, before time.Time) (int64, bool)
	// pauseWaits holds recoveries waiting out a host's partition pause, or
	// re-checking a deadline that refused (partition_pause.go). In memory: a successor re-derives the wait from
	// the self-pause fence record, anchored at its own first sight of it.
	pauseWaits map[string]pauseWait

	// RelayConfig is the replicator's relay configuration; its BaseRelays is
	// the floor below which relay health never demotes (relay_health.go).
	// Zero is corrosion.RelayConfig's default.
	RelayConfig corrosion.RelayConfig
	// relay is the lease holder's relay-health hysteresis (relay_health.go).
	relay relayHealthState
	// oneWay records the hosts partition_one_way is raised for.
	oneWay map[string]bool
}

// FailoverGate is the subset of *health.Checker the coordinator consults at
// decide sites. Kept as an interface so the coordinator stays testable and the
// gate is optional.
type FailoverGate interface {
	DecisionGate(ctx context.Context) health.GateResult
	QuorumProof(ctx context.Context) (health.QuorumState, int, int)
	// Enforced is the LATCHED enforcement decision (partition → fail closed).
	Enforced(ctx context.Context, token string) bool
	// PeerSupportsFresh fresh-Pings peer (UNcached) and reports whether it advertises
	// token — used to confirm a destination can honor a proof BEFORE stamping one.
	// Uncached so a target that regressed within the cache TTL is caught immediately.
	PeerSupportsFresh(ctx context.Context, peer, token string) bool
}

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (c *Coordinator) SetGateRefusedObserver(fn func(action, reason string)) { c.onGateRefused = fn }

func (c *Coordinator) noteGateRefused(action, reason string) {
	if c.onGateRefused != nil {
		c.onGateRefused(action, reason)
	}
}

// gateEnforced reports whether the split-brain gate is active cluster-wide, so
// the coordinator must write proof-linked pending transitions. Fail-open
// (returns false) until every enforcement-relevant member advertises the token —
// so a mid-roll cluster keeps failing over via the legacy path.
func (c *Coordinator) gateEnforced(ctx context.Context) bool {
	if c.Gate == nil {
		return false
	}
	return c.Gate.Enforced(ctx, capabilities.SplitBrainGateV1)
}

// destAdvertisesGate fresh-Pings dest to confirm it advertises split_brain_gate_v1
// BEFORE the coordinator stamps a proof-bearing action there. A latched-enforcement
// coordinator must never stamp a proof a REGRESSED/replaced target (no longer
// advertising, e.g. downgraded) can't honor — the target would be required to
// validate a proof it doesn't understand, or silently take the legacy path. Fail
// closed: unconfirmed support → false → the mint site refuses.
func (c *Coordinator) destAdvertisesGate(ctx context.Context, dest string) bool {
	if c.Gate == nil {
		return false
	}
	if dest == c.hostName {
		// A self-fenced node advertises nothing split-brain-related (it de-advertises to
		// peers via advertisedCapabilities); mirror that locally so it never stamps a
		// self-targeted proof. run() already hard-gates a fenced coordinator, so this is
		// defense-in-depth against any self-dest mint path.
		return !c.selfFenced() && capabilities.Has(capabilities.Supported(), capabilities.SplitBrainGateV1)
	}
	return c.Gate.PeerSupportsFresh(ctx, dest, capabilities.SplitBrainGateV1)
}

// selfFenced reports whether THIS node has self-fenced (nil predicate → false).
func (c *Coordinator) selfFenced() bool { return c.SelfFenced != nil && c.SelfFenced() }

// NewCoordinator creates a new failover coordinator with the real fencer.
func NewCoordinator(hostName string, db *corrosion.Client) *Coordinator {
	return &Coordinator{
		hostName:       hostName,
		db:             db,
		fencer:         fence.Execute,
		fenced:         make(map[string]bool),
		fenceRelocated: make(map[string]bool),
		confirmResumed: make(map[string]string),
		Now:            func() time.Time { return time.Now() },
	}
}

// upgradingGrace reports when h, recorded 'upgrading', turned so, and whether
// it is still inside upgradingTimeout and so not fenced. It is timed from its
// membership row's state change when it has one, else from the hosts row; an
// unreadable time counts as inside.
func (c *Coordinator) upgradingGrace(ctx context.Context, h *corrosion.HostRecord) (time.Time, bool) {
	upd, ok := corrosion.ParseUpdatedAt(h.UpdatedAt)
	if since, sok, serr := corrosion.HostStateSince(ctx, c.db, h.Name); serr == nil && sok {
		upd, ok = since, true
	}
	return upd, !ok || c.now().Sub(upd) < c.upgradingTimeout()
}

// restartingWithinAllowance reports whether host is recorded 'upgrading' and
// still within upgradingTimeout: the fence path's skip (run). A host that
// cannot be read is not.
func (c *Coordinator) restartingWithinAllowance(ctx context.Context, host string) bool {
	h, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil || h == nil || h.State != "upgrading" {
		return false
	}
	_, within := c.upgradingGrace(ctx, h)
	return within
}

// noteUpgradingLives records, from each host's membership state this cycle,
// the span it was last recorded 'upgrading': its start while it lasts, and the
// activation that ended it, read on the first cycle that sees the host active
// after it. A life that ended in any state but active, or a later activation,
// is forgotten. An unreadable state keeps what was known. It is in memory
// only: a coordinator that did not see a host 'upgrading' (a new lease holder,
// a restart) knows of no life, and gives its runs afreshRun as before.
func (c *Coordinator) noteUpgradingLives(ctx context.Context) {
	states, err := corrosion.HostsStateSince(ctx, c.db)
	if err != nil {
		return
	}
	if c.upgradingLives == nil {
		c.upgradingLives = map[string]UpgradingLife{}
	}
	for host, life := range c.upgradingLives {
		st, ok := states[host]
		switch {
		case !ok:
			delete(c.upgradingLives, host)
		case st.State == "upgrading":
		case st.State == "active" && life.End.IsZero() && st.Since.After(life.Start):
			life.End = st.Since
			c.upgradingLives[host] = life
		case st.State == "active" && life.End.Equal(st.Since):
		default:
			delete(c.upgradingLives, host)
		}
	}
	for host, st := range states {
		if st.State == "upgrading" {
			c.upgradingLives[host] = UpgradingLife{Start: st.Since}
		}
	}
}

// upgradingTimeout is how long a host recorded 'upgrading' is skipped.
func (c *Coordinator) upgradingTimeout() time.Duration {
	if c.UpgradingTimeout > 0 {
		return c.UpgradingTimeout
	}
	return upgradingTimeout
}

// fenceSSHPath is how an SSH fence from this coordinator reaches target
// (FenceSSH), the legacy path when none is wired.
func (c *Coordinator) fenceSSHPath(ctx context.Context, target string) fence.SSHFence {
	if c.FenceSSH == nil {
		return fence.SSHFence{}
	}
	return c.FenceSSH(ctx, target)
}

// SetFencer replaces the fence implementation. Test-only; production code
// should not use this.
func (c *Coordinator) SetFencer(f Fencer) { c.fencer = f }

// SetNICGuardPlacement sets whether a recovery of a VM must land on a host
// that enforces NIC guards (placement.Request.RequireNICGuards): the daemon
// requires one for a guarded VM until every host does
// (grpcapi.Server.GuardHostNeeded).
func (c *Coordinator) SetNICGuardPlacement(fn func(ctx context.Context, vm string) bool) {
	c.nicGuardPlacement = fn
}

// addPlacementLabels adds what SetNICGuardPlacement requires to req.
func (c *Coordinator) addPlacementLabels(ctx context.Context, req *placement.Request, vm string) {
	if c.nicGuardPlacement != nil && c.nicGuardPlacement(ctx, vm) {
		req.RequireNICGuards = true
	}
}

// SetCapacityPolicy wires the cluster-wide capacity policy.
func (c *Coordinator) SetCapacityPolicy(p corrosion.CapacityPolicy) { c.capacity = p }

// vmSpecPin returns the host vm's stored spec pins it to, or "".
func vmSpecPin(vm corrosion.VMRecord) string {
	spec := &pb.VMSpec{}
	if vm.Spec == "" || json.Unmarshal([]byte(vm.Spec), spec) != nil || spec.Placement == nil {
		return ""
	}
	return spec.Placement.Host
}

// buildFailoverPlacementRequest constructs a placement request for a VM being
// rescheduled off failedHost, honoring the constraints in its stored spec.
// A spec pin to the failed host itself is dropped — the whole point is to leave.
//
// So is a pin to any other host that is down (pinDown): not in the host table,
// or not 'active'. The pin is the operator's "run it there", and while there is
// down it cannot be honoured whichever way the recovery goes; the choice is
// between running the VM elsewhere and not running it at all, which is the
// choice a pin to the failed host has always been resolved for. It arises
// whenever a recovery has already moved a pinned VM off its pin: kvm003 drill 6
// recovered pp4 off node-4, its pin, and when pp4's new host failed with node-4
// still down, the pin stranded it. Nothing about the stored spec changes: the
// pin is ignored for this recovery only, and honoured again by the next one
// once its host is back. A pin to a host that is up but cannot take the VM — a
// witness, or one without room — is still a hard constraint, and strands it.
func buildFailoverPlacementRequest(vm corrosion.VMRecord, failedHost string, capacity corrosion.CapacityPolicy, pinDown func(string) bool) placement.Request {
	req := placement.Request{
		VMName:       vm.Name,
		CPUNeeded:    vm.CPUActual,
		MemMiBNeeded: vm.MemActual,
		Capacity:     capacity,
	}
	if vm.Spec == "" {
		return req
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(vm.Spec), spec) != nil {
		return req
	}
	// USB passthrough: a mapped device restricts recovery to the hosts its
	// mapping lists; a raw one is plugged into the failed host and no other,
	// so the VM stays there (no candidate) rather than starting without it.
	if mappings, raw := corrosion.USBMappingNames(spec); len(mappings) > 0 || raw {
		req.USBMappings = mappings
		if raw {
			req.USBHost = vm.HostName
		}
	}
	if spec.Placement == nil {
		return req
	}
	p := spec.Placement
	if p.Host != "" && p.Host != failedHost && !pinDown(p.Host) {
		req.PinHost = p.Host
	}
	req.AntiAffinity = p.AntiAffinity
	req.Affinity = p.Affinity
	req.RequireLabels = p.Require
	req.PreferLabels = p.Prefer
	req.Spread = p.Spread
	if p.MaxPerNode > 0 {
		req.MaxPerNode = int(p.MaxPerNode)
	}
	return req
}

// resolveUSBPlacement loads the hosts a recovering VM's USB mappings have a
// device on, which SelectBatch cannot read itself. A read error leaves them
// unresolved, and an unresolved mapping qualifies no host: the VM is not
// recovered this pass rather than started where its device is not.
func (c *Coordinator) resolveUSBPlacement(ctx context.Context, req *placement.Request) {
	if err := placement.ResolveUSBMappingHosts(ctx, c.db, req); err != nil {
		slog.Warn("failover: cannot read a VM's USB mappings; leaving it this pass (fail closed)", "vm", req.VMName, "error", err)
	}
}

// now is the coordinator's clock — defaults to time.Now, overridable
// for virtual-time scenarios via the exported Now field.
func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func ownerEpochString(epoch int64) string {
	return strconv.FormatInt(epoch, 10)
}

// Start runs the coordinator loop. Blocks until ctx is cancelled.
func (c *Coordinator) Start(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.run(ctx)
		}
	}
}

// RunOnce executes a single coordinator cycle and returns. Exposed for
// cross-package integration tests in tests/cluster/. Production code uses
// Start which loops on the poll ticker.
func (c *Coordinator) RunOnce(ctx context.Context) { c.run(ctx) }

func (c *Coordinator) run(ctx context.Context) {
	c.beginMigratingAsks()
	// Self-fence is a HARD local gate: a doomed node (waiting for the watchdog to reboot
	// it) must not drive any failover decision during the live-but-doomed window, even if
	// it briefly reacquires quorum/lease. Checked before the lease so a fenced node also
	// stops renewing coordinator leadership.
	if c.selfFenced() {
		c.mAttempt(PhaseSkip, ResultSkipped, ErrSelfFenced)
		c.stepDownGauges()
		return
	}
	// One read of the failover scope and voter regions for the whole cycle:
	// the lease's quorum stand-down, each renewal and the cycle's own
	// decisions all ask it.
	c.cyclePolicy = health.NewDecisionPolicy(c.db)
	defer func() { c.cyclePolicy = nil }()
	// Leader election: only one coordinator may drive recovery at a time.
	// Acquire (or renew) the lease; if another coordinator holds it, skip.
	held, leaseErr := c.acquireLeaseResult(ctx)
	c.ha.holding.Store(held)
	if !held {
		// stepDownGauges publishes stranded_workloads = 0, which is a CLAIM
		// that nothing is stranded. Only a clean "another node holds the lease"
		// supports it. On a read error this node knows nothing, and if the
		// store problem is fleet-wide -- the case where workloads are most
		// likely to be stranded -- every node takes this path, max() across
		// instances reads 0, and the alert clears exactly when it should fire.
		// Same rule the strandedByHost branch below already follows. It
		// covers a node standing down for want of the voter majority too
		// (errLeaseNoQuorum): with none anywhere, nobody holds the lease.
		if leaseErr == nil {
			c.stepDownGauges()
			// Not deciding: whatever this node vetoed while it led is no
			// longer holding anything back.
			c.ha.cycleVetoes = nil
			c.syncHAVeto(ctx)
		}
		return
	}
	if c.leaseGap.Swap(false) {
		c.forgetEpisodes()
	}
	if c.VoterGenesis != nil {
		c.VoterGenesis(ctx, c.LeaseTerm())
	}
	if c.ClaimHealth != nil {
		c.ClaimHealth(ctx)
	}
	if c.PressureHealth != nil {
		c.PressureHealth(ctx)
	}

	// The voter set is both halves of the quorum: its size is the
	// denominator, and an observation counts toward a fence or a recovery only
	// if its observer is a member and is not the target itself. A fenced host
	// still probing, a deleted host whose daemon was never stopped, or a name
	// no host carries cannot supply a vote (colonelpanik/litevirt#251). It is
	// the same set health.QuorumProof counts over. A read error fails closed:
	// no voters, no fence, no recovery.
	//
	// Partition tolerance comes from the observer count, not from tightening
	// this denominator: a minority side computes the same N but has too few
	// observers to reach N/2+1. Tightening it further (e.g. requiring fresh
	// self-probes) creates a bootstrap hole where a just-started coordinator
	// has no probe rows yet and refuses to act on any failure.
	vr, err := c.cyclePolicy.VoterRegions(ctx)
	if err != nil {
		slog.Error("failover: read voter set", "error", err)
		c.mAttempt(PhaseQuorum, ResultError, ErrDBError)
		return
	}
	voters := vr.Voters
	if len(voters) < 1 {
		c.mAttempt(PhaseQuorum, ResultSkipped, ErrNoQuorum)
		return
	}

	// The failover scope decides whose observations count toward a decision
	// about each host: every voter, or the host's own region's voters
	// (docs/design/region-scoped-failover.md). Read once, so the whole cycle
	// decides against one policy. A policy this build cannot read or does not
	// know fails the cycle CLOSED — guessing either scope could fence what the
	// operator meant to protect.
	scope, err := c.cyclePolicy.Scope(ctx)
	if err != nil {
		slog.Error("failover: read failover scope; deciding nothing this cycle", "error", err)
		c.mAttempt(PhaseQuorum, ResultError, ErrDBError)
		return
	}
	c.scope = quorumView{region: scope.Region(), vr: vr}
	c.publishRegionsWithoutQuorum(ctx, c.scope)
	// The cluster HA policy, read once for the cycle (ha_disarm.go). Every
	// Held action re-reads it immediately before it runs; a policy this node
	// cannot read holds them all. A read error decides nothing.
	haCycle, err := c.haCycleRead(ctx)
	if err != nil {
		slog.Error("failover: read the cluster HA policy; deciding nothing this cycle", "error", err)
		c.mAttempt(PhaseQuorum, ResultError, ErrDBError)
		return
	}

	// Clear the "already handled this down-episode" flag for any host that has
	// recovered to active. Without this, the in-memory fenced set — which is
	// also set by the offline/terminal-state skip below, not just by an actual
	// fence — permanently suppressed re-fencing a host that went down, recovered,
	// then failed again, for the life of the coordinator process. (The skip is
	// silent, so this manifested as the coordinator quietly never fencing.)
	c.clearRecoveredFromFenced(ctx)

	// Find hosts where enough *fresh* observers agree the target has exceeded
	// the failure threshold. The freshness predicate prevents stale rows from
	// dead observers from satisfying quorum.
	//
	// Freshness is filtered in GO via corrosion.ParseUpdatedAt, NOT a SQL
	// `updated_at > cutoff` string compare: updated_at is the LWW key, which becomes
	// an HLC string ("<physms>-…") once hlc_lww is enabled, and a lexical/text compare
	// can't span the RFC3339 and HLC forms (an HLC row would sort below an RFC3339
	// cutoff and read as permanently stale — silently killing fencing quorum). Both
	// forms decode to a wall instant, so the DISTINCT-observer-per-target quorum
	// aggregation is done here too. An unparseable/stale row simply doesn't count.
	// The status exclusion below keeps a REACHABLE host out of fencing quorum.
	//
	// consecutive_failures counts failed observations, and once the health
	// checker probes readiness rather than TLS reachability, "the peer answered
	// and told me its database is wedged" is one of those. Left in, the new
	// signal would arrive as a power-off: three ticks of a busy database on a
	// host whose VMs are running fine, and quorum fences it. That is the
	// opposite of what the readiness probe is for, and it is also the one
	// direction that cannot be undone.
	//
	// Fencing is for a host that cannot be reasoned with. A host answering an
	// RPC to say it cannot serve is being reasoned with — it loses its votes,
	// its placements and its pushes by no longer being 'healthy' anywhere, and
	// keeps its power. If it then goes genuinely silent, the probe records
	// 'suspect' like any other unreachable peer and this query counts it.
	//
	// The status exclusion is the second line, not the only one: an unready row
	// also carries a pinned consecutive_failures of 1 (health.checkHost), so a
	// coordinator on an older build, whose query has no status clause, cannot
	// count it during a rolling upgrade either.
	obs, err := candidateObservations(ctx, c.db, c.hostName)
	if err != nil {
		slog.Error("failover: query host_health", "error", err)
		c.mAttempt(PhaseHealth, ResultError, ErrDBError)
		return
	}
	// Freshness is bounded on BOTH sides. A row stamped further ahead of this
	// node's clock than a whole freshness window is not a recent observation
	// but a skewed one — an observer whose clock runs fast, or one stepped
	// forward on resume before ours was — and without the upper bound it
	// stayed "fresh" for healthFreshness plus the skew. It counts once our
	// clock reaches it. This errs toward not fencing, and only for as long as
	// the skew lasts; host recovery (recoverHosts) deliberately keeps the
	// one-sided test, since readmitting a host is not the irreversible act.
	now := c.now()
	for _, o := range obs {
		if inst, _, future := observationInstant(o, now); future {
			slog.Warn("failover: ignoring a future-dated health observation (clock skew)",
				"target", o.Target, "observer", o.Observer,
				"updated_at", o.UpdatedAt, "ahead", inst.Sub(now).Round(time.Second))
		}
	}
	// An observation older than the moment its target turned active is about
	// the host before (joining, offline, fenced, upgrading), not the one active
	// now, so a host that just turned active is counted down afresh — and so
	// is one whose observation is newer but whose failing run began before the
	// activation (countedSinceActive). Unreadable: judged as before.
	activeSince, aerr := corrosion.HostsActiveSince(ctx, c.db)
	if aerr != nil {
		slog.Warn("failover: read when hosts turned active", "error", aerr)
	}
	// The count itself is FenceCandidates, a pure function of these inputs,
	// so the HA arm handler's list of down hosts is this decision exactly
	// (CurrentFenceCandidates). The side effects stay here.
	c.noteUpgradingLives(ctx)
	in := CandidateInputs{Self: c.hostName, RegionScope: c.scope.region, Voters: vr, Now: now,
		Observations: obs, ActiveSince: activeSince, UpgradingTimeout: c.upgradingTimeout(),
		UpgradingLives: c.upgradingLives}
	readFenceTimes(ctx, c.db, &in)
	candidates, declinedList := FenceCandidates(in)
	// Region scope: say so when the cluster-wide count would have fenced a
	// host and the region count does not. Silence here would read as "nothing
	// is down".
	declined := map[string]bool{}
	for _, d := range declinedList {
		declined[d.Target] = true
		c.noteRegionDeclined(c.scope, d.Target, d.ClusterObservers, d.RegionObservers)
	}
	c.clearRegionDeclined(declined)
	c.cycleCandidates = make(map[string]bool, len(candidates))
	for _, cand := range candidates {
		c.cycleCandidates[cand.Target] = true
	}
	c.ha.heldCandidates = nil
	// A recovery waiting on a partition-pause deadline is re-checked only from
	// the fence loop below, so only while its host is a fence candidate. A
	// failing voter whose probe succeeds once, at an exact quorum, takes the
	// host out of that loop for a few cycles: the deadline then waits, which
	// is safe, and the stall reason says so rather than that the pause is
	// still being waited out.
	var failing map[string]int
	for host, w := range c.pauseWaits {
		if c.cycleCandidates[host] || c.mono().Before(w.deadline) {
			continue
		}
		if failing == nil {
			failing = freshVoterCounts(in)
		}
		c.noteHold(host, fmt.Sprintf("the partition-pause deadline has passed, but it is re-checked only while a quorum "+
			"of voters fails the host, and %d of %d do now; it is re-checked once they do, "+
			"or 'lv host fence-confirm %s' once it is off", failing[host], c.scope.quorum(host), host))
	}

	// Relay health (colonelpanik/litevirt#175): demote a host whose probes
	// keep failing from relay duty, or restore one, as a replicated row every
	// node's relay election reads. Before any fence, so a fence that ends the
	// cycle early does not starve it, and told which hosts are fence
	// candidates — those are fenced, not demoted. It never fails the cycle.
	fenceCandidates := make(map[string]bool, len(candidates))
	for _, cand := range candidates {
		fenceCandidates[cand.Target] = true
	}
	c.evaluateRelayHealth(ctx, voters, fenceCandidates)

	// Which hosts partition_one_way is open for, from the replicated rows:
	// whoever raised one, this holder resolves it once its case is gone.
	c.syncOneWay(ctx)

	for _, cand := range candidates {
		// Re-validate lease before each destructive action: long fence runs
		// (IPMI verify up to 15 s) can outlast the lease without renewal.
		if _, st := c.holdLeaseFor(ctx, leaseRenewBefore); st != leaseHeld {
			slog.Warn("failover: lease lost, unshown or renewed as a new tenure mid-cycle, aborting",
				"host", c.hostName, "lease", st.String())
			c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
			// Losing the lease is a step-down: the node that takes it owns the
			// fleet's view from here. Not being able to show it holds the
			// lease is not (run's rule for an unreadable lease), and nor is a
			// renewal as a new tenure: this node still leads, and the next
			// cycle republishes from what it re-derives.
			if st == leaseLost {
				c.stepDownGauges()
			}
			return
		}

		target := cand.Target
		// One-way partitions are made visible, never acted on differently
		// (docs/design/partition-pause.md §7 F4). Not for a host still
		// restarting within its allowance, which the fence path below skips
		// too: its daemon writes healthy rows about its peers before its own
		// gRPC server serves, so it has exactly the one-way shape for the
		// 15-25 s a graceful restart takes (lab 1, 2026-10-16). It is neither
		// raised nor resolved for it until then. A host booting back from a
		// fence is recorded 'fenced' or 'offline' (hostboot), not 'upgrading',
		// and is not skipped: it can still raise the condition for that window.
		if !c.restartingWithinAllowance(ctx, target) {
			if failing, healthy, oneWay := c.detectOneWay(ctx, target); oneWay || c.oneWay[target] {
				c.noteOneWay(ctx, target, failing, healthy, oneWay)
			}
		}
		// HA disarmed, here or on a live voter: no fence, no resume of a
		// recorded fence, no claim retry or pause wait. All of it is kept,
		// and runs once HA is armed again.
		if c.haHold(ctx, target, haSiteCandidate) {
			c.noteHeldCandidate(target)
			continue
		}
		// afresh: an operator confirmed the host off during this outage and no
		// fence has run for it, so it goes down the fence path below although
		// it is recorded terminal (confirmationFencesAfresh).
		afresh := false
		if c.fenced[target] && !c.claimRetryOutageOver(ctx, target) {
			// A claim retry owed to an outage the host has since come back
			// from is re-judged before anything runs on that outage's fence
			// (claimRetryOutageOver); a host it could not read is skipped.
			continue
		}
		if c.fenced[target] {
			// A recovery a disarm held after its fence continues here.
			if c.resumeHAHeldRecovery(ctx, target, cand.Observers) {
				continue
			}
			// A recovery waiting out the host's partition pause continues
			// here; one whose deadline refused falls through, re-checked next
			// cycle.
			if c.retryPauseWait(ctx, target) {
				continue
			}
			// A recovery claim refused on an earlier tick is retried here: the
			// host is handled, but its workloads are not all moved.
			if c.retryClaims(ctx, target) {
				continue
			}
			// Handled this outage — unless an operator has since confirmed it
			// off after a refusal. Without this check the confirmation landed
			// on a host no code path would revisit (see confirmationResume).
			if c.resumeFromConfirmation(ctx, target) {
				continue
			}
			// Or confirmed it off before anything fenced it: the cached skip
			// of an 'offline' host would otherwise hide that for good.
			h, err := corrosion.GetHost(ctx, c.db, target)
			if err != nil || h == nil {
				continue
			}
			switch {
			case c.confirmationFencesAfresh(ctx, h):
				afresh = true
			case c.fenceAuthorityChanged(ctx, h):
				// A fence recorded since this coordinator handled the host
				// (an operator's, another coordinator's), or its own failed
				// fence due a retry: the cache must not hide either (lab drill
				// S5). The ordinary path below re-reads both and decides.
			case h.State == "offline" && c.fenceHeldStands(ctx, target):
				// A held fence (ha.fence_held) whose condition reached this
				// replica after the 'offline' it records: the two replicate as
				// separate entries, so this coordinator may have cached the
				// host as terminal first. The hold is re-decided every cycle
				// until a fence of the host is recorded since it was raised.
			default:
				continue
			}
			c.unmarkHandled(target)
			// The fence path decides afresh; neither a refused wait nor a
			// claim retry owed to the older fence outlives it.
			delete(c.pauseWaits, target)
			c.forgetClaimRetries(target)
			delete(c.ha.heldRecovery, target)
		}

		// A fence decision made on anything but the confirmation the host
		// was fenced afresh on ends that exemption (afreshConfirm); the
		// later afresh check below records it again when it applies.
		if !afresh {
			delete(c.afreshConfirm, target)
		}

		// Skip if this host is already in a terminal state.
		h, err := corrosion.GetHost(ctx, c.db, target)
		if err != nil {
			// A store error here silently drops a fence candidate; surface it.
			slog.Warn("failover: resolve target host failed, skipping", "host", target, "error", err)
			c.mAttempt(PhaseHealth, ResultError, ErrDBError)
			continue
		}
		if h == nil {
			continue // unknown host (e.g. raced delete) — quiet skip
		}
		// A host `lv host add` has admitted and whose daemon has not yet
		// started is down to every observer by construction: nothing listens
		// there until its setup finishes. It runs nothing and holds nothing
		// (no placement targets it), so there is nothing to fence it for, and
		// fencing it powers the machine off part-way through its setup — the
		// add then hangs (kvm003 drill 6, finding B6). Its first boot records
		// it 'upgrading' until its daemon serves, then 'active' (hostboot),
		// and from then on it is fenced like any host. Not cached:
		// the boot write can land on any cycle.
		if h.State == corrosion.HostStateJoining {
			slog.Info("failover: target is still joining (its daemon has not started), skipping fence", "host", target)
			c.mAttempt(PhaseSkip, ResultSkipped, ErrJoining)
			continue
		}
		// A host whose state this node cannot know — no membership row, and a
		// hosts copy the retire token stopped (corrosion.HostStateUnknown) —
		// is neither fenced nor recovered: a fence is irrevocable, and the
		// row is one anti-entropy cycle away. It may be in maintenance or
		// still joining. Not cached: re-read next cycle.
		if h.State == corrosion.HostStateUnknown {
			slog.Info("failover: target's membership row has not reached this node; skipping fence until it does", "host", target)
			c.mAttempt(PhaseSkip, ResultSkipped, ErrStateUnknown)
			continue
		}
		if aerr == nil && c.turnedActiveThisCycle(ctx, target, activeSince) {
			c.mAttempt(PhaseSkip, ResultSkipped, ErrJoining)
			continue
		}
		// recorded: h carries a successful fence a successor may resume from
		// (recordedFence), whether or not this cycle resumed it.
		recorded := false
		// retry: this host's newest fence attempt failed and its retry
		// backoff has passed (fenceRetryDue); it goes down the fence path
		// below although it is recorded 'offline'.
		retry := false
		var retryPlan fenceRetry
		if !afresh && (h.State == "offline" || h.State == "maintenance" || h.State == "fenced") {
			// A 'fenced' host is normally finished with — the fence ran and its
			// recovery ran with it. But the two halves can land on different
			// coordinators: a fence that ends with the lease gone records the
			// power-off and leaves the reschedule to whoever holds the lease
			// next (see failover). That host is still here, quorum-down with its
			// workloads on it, and a plain skip would strand them. Resume from
			// the record instead: the fence that wrote this state is the
			// authority to reschedule, either on its own or once a fresh
			// verified power-off has renewed it (see resumeActionFor).
			if rec, at, ok := c.recordedFence(ctx, h); ok {
				recorded = true
				switch act, why := c.resumeActionFor(ctx, h, rec, at); act {
				case resumeFromRecord:
					slog.Info("failover: resuming recovery from a fence a previous leader recorded",
						"host", target, "fence_id", rec.ID, "method", rec.Method)
					c.mAttempt(PhaseRecovery, ResultOK, ErrRecoveryResumed)
					c.noteFencedOn(target, rec.ID)
					c.recoverFenced(ctx, h, fence.Result{Success: true, Method: rec.Method, Detail: rec.Detail}, "", c.fenceStateLatched(ctx))
					continue
				case resumeAfterRefence:
					if c.refence(ctx, h, rec, cand.Observers) {
						continue
					}
				default:
					c.noteResumeDeclined(target, rec, why)
				}
			}
			// The other way a stranded recovery can be resumed: a refusal for
			// want of a confirmation, since confirmed. This is the path after a
			// restart, when the refusing process's memory is gone.
			if c.resumeFromConfirmation(ctx, target) {
				continue
			}
			// A confirmation of this outage that no fence has followed: fence
			// it now, as if it were still active (confirmationFencesAfresh).
			afresh = c.confirmationFencesAfresh(ctx, h)
			// A fence that FAILED does not park the host: once its backoff
			// has passed, it is fenced again (fenceRetryDue).
			if !afresh && !recorded {
				retryPlan = c.fenceRetryDue(ctx, h)
				retry = retryPlan.Due
				if !retry && !retryPlan.Next.IsZero() {
					c.retryHold(h, retryPlan.Next)
				}
			}
		}
		// held: h is 'offline' because its fence was held, nothing on it
		// needing one (ha.fence_held, holdUnneededFence). That is a decision
		// re-made every cycle, never a terminal state: it goes down the path
		// below, where the fence runs the moment something needs it. Unread,
		// the host is skipped this cycle without the cache.
		held := false
		if !afresh && !retry && !recorded && h.State == "offline" {
			var herr error
			if held, herr = c.fenceHeld(ctx, target); herr != nil {
				slog.Warn("failover: read "+CondFenceHeld+" failed, skipping", "host", target, "error", herr)
				c.mAttempt(PhaseHealth, ResultError, ErrDBError)
				continue
			}
		}
		if !afresh && !retry && !held && (h.State == "offline" || h.State == "maintenance" || h.State == "fenced") {
			// A 'fenced' host WITHOUT that proof is not settled, it is unproven:
			// hosts.state and fencing_log replicate independently, so the state
			// can land here a cycle or more before the row that authorises the
			// resume. Caching the skip would decide the question before the
			// evidence arrived and never look again — the cache is cleared only
			// for hosts back to 'active', which a fenced host is not. Leave it
			// eligible and re-read next cycle; the resume caches once it runs, so
			// the standing cost is one fencing_log read per cycle per host that
			// stays fenced. An 'offline' host whose newest fence succeeded is
			// the same case: once fence_state_v1 has latched, that is the
			// state an unverified fence records, and its resume path is the
			// one above (colonelpanik/litevirt#253). 'maintenance', and an
			// 'offline' host with no such fence, have no resume path at all,
			// so for those the cached skip is still the right answer.
			if h.State != "fenced" && !recorded {
				c.markHandled(ctx, target)
			}
			c.mAttempt(PhaseSkip, ResultSkipped, ErrTerminalState)
			continue
		}
		// Skip hosts that are intentionally restarting (a self-upgrade, or a
		// graceful daemon restart that marked itself 'upgrading' on SIGTERM).
		// They're unreachable for tens of seconds; quorum agreeing they're
		// "down" is normal — fencing them turns a routine restart into a
		// destructive false-positive failover. BUT a host that entered
		// 'upgrading' and never returned must still fail over, or its VMs are
		// stranded — so we only skip while it's within upgradingTimeout. On a
		// timestamp parse error we err on the safe side and keep skipping.
		//
		// The timeout runs from the STATE write (the membership row's own
		// timestamp, corrosion.HostStateSince), not from the hosts row: that
		// moves with every version or resource report, so a host stuck
		// 'upgrading' that kept reporting pushed its own timeout out. A host
		// with no membership row is timed from the hosts row as before.
		if h.State == "upgrading" {
			upd, within := c.upgradingGrace(ctx, h)
			if within {
				slog.Info("failover: target is upgrading, skipping fence", "host", target)
				c.mAttempt(PhaseSkip, ResultSkipped, ErrUpgrading)
				continue
			}
			slog.Warn("failover: host stuck 'upgrading' past timeout — treating as failed",
				"host", target, "upgrading_since", upd.UTC().Format(time.RFC3339))
			// fall through to fence
		}

		// Skip if fencing_log shows a recent successful fence — no double-fencing
		// across coordinator restarts or process race windows.
		//
		// The skip is NOT cached in c.fenced. The host is not in a terminal
		// state here, so the fence on record has not reached this replica's
		// host state yet: a leader on the previous release writes the row and
		// the state as separate entries, and a successor can hold the first a
		// cycle or more before the second. Caching would decide the question
		// before the state arrived, and the cache is cleared only for hosts
		// back to 'active', so once the 'fenced' state landed nothing would
		// reach the resume path above and the workloads would stay on the host.
		// Re-reading costs one fencing_log read per cycle for at most
		// recentFenceWindow.
		//
		// Not for a fresh fence on a confirmation: the recent row is the
		// operator's confirmation itself, and no attempt has followed it.
		//
		// For a retry, only a row newer than the failed attempt it repeats
		// counts (recentlyFencedAfter): a host a failed fence left 'offline'
		// is no longer dated by its activation, and a previous outage's fence
		// would otherwise hold the retry back for up to recentFenceWindow.
		// On a retry this catches only a success that replicated (or an
		// operator's fence that landed) after fenceRetryDue read the log this
		// cycle: fenceRetryDue already declined a retry for any success newer
		// than FailedAt. It is that race check, not the retry's guard against
		// fencing twice, which is the backoff (fenceRetryDelay).
		recent := false
		switch {
		case afresh:
		case retry:
			recent = c.recentlyFencedAfter(ctx, target, retryPlan.FailedAt)
		default:
			recent = c.recentlyFenced(ctx, target)
		}
		if recent {
			slog.Info("failover: host has recent fence record, skipping", "host", target)
			c.mAttempt(PhaseSkip, ResultSkipped, ErrRecentlyFenced)
			continue
		}

		// Checked last, immediately before the decision, so a stall that began
		// while this cycle was reading the candidates still defers it. Nothing is
		// cached: the next cycle after the grace window judges afresh.
		if c.LocalStall != nil && c.LocalStall() {
			slog.Warn("failover: quorum reached, but this node was itself not running moments ago — deferring the fence until it has watched for a full grace window",
				"host", target, "observers", cand.Observers, "quorum", c.scope.quorum(target), "grace", health.StallGrace)
			c.mAttempt(PhaseSkip, ResultSkipped, ErrLocalStall)
			continue
		}
		// Likewise a node that was itself cut off from the majority moments
		// ago: the failure rows it now holds were written during the cut, and
		// after a fleet-wide blip they name every host (partition pause, §7 F7).
		if c.QuorumRegain != nil && c.QuorumRegain(ctx, c.scope.graceScope(target)) {
			slog.Warn("failover: quorum reached, but this node regained the voter majority only moments ago — deferring the fence until the observers have re-probed",
				"host", target, "observers", cand.Observers, "quorum", c.scope.quorum(target), "grace", health.QuorumRegainGrace)
			c.mAttempt(PhaseSkip, ResultSkipped, ErrQuorumRegain)
			continue
		}

		// Last, immediately before the fence: a fence that nothing on the host
		// needs is held, the host recorded offline and ha.fence_held raised
		// (holdUnneededFence). Not for a fence afresh on an operator's
		// confirmation: the operator has already powered the host off.
		if !afresh && c.holdUnneededFence(ctx, h) {
			continue
		}

		slog.Warn("failover: quorum reached — host exceeded failure threshold",
			"host", target, "observers", cand.Observers, "quorum", c.scope.quorum(target),
			"region_scoped", c.scope.region)

		if retry {
			// Immediately before the fence, under the lease the candidate
			// loop re-validated: a host anyone has seen answer since the
			// attempt that failed is never fenced again (retryStillDown).
			if why, down := c.retryStillDown(ctx, target, retryPlan.FailedAt); !down {
				c.logRetryRefused(target, retryPlan.FailedAt, why)
				c.mAttempt(PhaseSkip, ResultSkipped, ErrRetryHostAnswered)
				c.noteHold(target, "fence failed, and the host has answered since; not retried: "+why)
				c.noteBridgedRetry(ctx, h, retryPlan.FailedAt)
				continue
			}
			slog.Warn("failover: the newest fence of this host failed; fencing it again",
				"host", target, "strategy", retryPlan.Strategy, "failures", retryPlan.Failures, "observers", cand.Observers)
			// The retry runs retryStrategy, never weaker than the host's
			// current strategy allows, as a re-fence runs the recorded method.
			again := *h
			again.FenceStrategy = retryPlan.Strategy
			h = &again
			c.retrying = &retryPlan
		}
		c.failover(ctx, h)
		c.retrying = nil
	}

	// A one-way condition raised for a host that is no longer a fence
	// candidate resolves: the quorum that could not reach it now can.
	candTargets := make([]string, 0, len(candidates))
	for _, cand := range candidates {
		candTargets = append(candTargets, cand.Target)
	}
	c.resolveOneWayGone(ctx, candTargets)
	c.resolveRefenceSettled(ctx)
	c.resolveFenceHeldSettled(ctx)

	// Recovery pass: bring a host the coordinator marked down (offline, or a
	// spurious no-VMs-moved fence) back to 'active' once a fresh quorum agrees
	// it's healthy again. A transient drop (a daemon restart, a brief blip) must
	// self-heal — otherwise health reconverges in seconds but hosts.state sticks.
	c.recoverHosts(ctx, c.scope)

	// The recovery passes below are Held while HA is disarmed; each proof
	// they would mint re-checks at its own site too.
	if !haCycle.Disarmed() && !c.haPassHeld(ctx) {
		// Workloads still recorded on a host that has been removed for good (`lv
		// host rm --dead`): under recovery claims their claims supersede to the
		// next attempt, and nothing else would ever visit them — a removed host is
		// no fence candidate.
		c.recoverRemovedHosts(ctx)
		// Re-certify, at the current generation, proofs whose certificate a forced
		// voter reconfiguration replaced: their destinations refuse them until then.
		c.recertifyReplaced(ctx)
		// Claim, for their own value, proofs minted without a certificate before
		// recovery claims were enforced: their destinations refuse them until then.
		c.certifyUncertified(ctx)
		// Move pending reschedules whose proofs the lease has outrun onto this
		// holder's term: their destinations refuse them as stale until then.
		c.sweepStaleTermProofs(ctx)

		// Settle any relocate-restore markers left by an indeterminate restore or a
		// coordinator crash mid-restore. This runs every cycle, independent of the
		// fence path (an already-fenced host is skipped above, so relocateContainers
		// won't re-run for it) — so a deferred restore still gets resolved.
		c.resolvePendingRelocations(ctx)
	}
	c.syncHAVeto(ctx)

	// Report workloads left on a host the cluster considers down. Read-only: see
	// strandedByHost for what the number does and does not mean, and for why
	// this reports rather than recovers. Runs after recoverHosts and
	// resolvePendingRelocations so a host or marker settled THIS cycle is already
	// out of the count.
	if byHost, err := c.strandedByHost(ctx); err != nil {
		// Leave the gauge holding its last measured value: publishing 0 here
		// would clear an operator's alert using a number we failed to read.
		slog.Error("failover: count stranded workloads", "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
	} else {
		n := 0
		for _, k := range byHost {
			n += k
		}
		c.mStranded(n)
		// Name each host whose recovery has stalled, and why
		// (alertStalledRecoveries): the fenced and offline hosts, each host
		// whose owed claim retry is held while a quorum still fails it
		// (withHeldClaimRetries), and the quorum-down hosts an HA hold kept
		// from being fenced at all (heldBeforeFence), which are still
		// recorded active.
		pending, unfenced := c.withHeldClaimRetries(ctx, byHost), map[string]bool(nil)
		if held := c.heldBeforeFence(ctx); len(held) > 0 {
			merged := make(map[string]int, len(pending)+len(held))
			for h, k := range pending {
				merged[h] = k
			}
			unfenced = make(map[string]bool, len(held))
			for h, k := range held {
				merged[h] = k
				unfenced[h] = true
			}
			pending = merged
		}
		c.alertStalledRecoveries(ctx, pending, unfenced)
		c.resolveBridgedSettled(ctx, byHost, c.noteBridgedBeforeFence(ctx))
		c.resolveUnprovenSettled(ctx, byHost)
		c.syncUnsafeBMC(ctx)
	}
}

// stepDownGauges clears the gauges this node owns when it is NOT driving
// failover — self-fenced, or not the lease holder. Every node runs a coordinator
// and every node serves /metrics, so without this a demoted leader pins its last
// value forever (Prometheus gauges retain) and pages the fleet after the
// condition heals, while every node that never held the lease publishes a
// permanent 0 that hides a real one. Same contract as stepDownDualRun: the
// leader's view is the fleet's view, and the rest keep their series clear.
//
// Nothing durable is lost by clearing. strandedByHost holds no state between
// cycles — it re-derives the count from hosts/vms/containers — so the new
// leader's first pass republishes the true value within one poll interval.
func (c *Coordinator) stepDownGauges() {
	c.mStranded(0)
	if c.HAPeerVetoGauge != nil {
		c.HAPeerVetoGauge(false)
	}
	c.mRegionsWithoutQuorum(0)
	// The stall alert is the leader's too: a node that takes the lease back
	// starts its clocks afresh rather than alerting on a stale one.
	c.stallSince, c.stallAlerted, c.stallUnfenced, c.holdReason, c.lastFenceFailure = nil, nil, nil, nil, nil
	c.holdBase, c.lastStale, c.unprovenRaised, c.restsOnTrust = nil, nil, nil, nil
	// So are the upgrading lives it saw: a later tenure has not seen what
	// happened meanwhile.
	c.upgradingLives = nil
}

// dropLeaseTerm records that this coordinator cannot show it holds the
// lease: a read or write error, a lease row it cannot use, or a stand-down for
// want of the voter majority. None of these is evidence that another node led,
// so it marks no gap: the re-take decides that from the lease row
// (acquireLeaseTenure). A lease that lapsed meanwhile is a new tenure there.
func (c *Coordinator) dropLeaseTerm() {
	c.leaseTerm.Store(0)
	if c.unshownSince.Load() == nil {
		at := c.mono()
		c.unshownSince.CompareAndSwap(nil, &at)
	}
}

// loseLease records that another node holds the lease, or claims it: a gap
// (leaseGap), whatever the lease row shows when this node takes it back.
func (c *Coordinator) loseLease() {
	c.leaseTerm.Store(0)
	c.leaseGap.Store(true)
}

// forgetEpisodes drops what this coordinator remembers of each host's outage,
// on taking the lease back after a gap (leaseGap): not after a read error or a
// stand-down that left the lease row naming this node unexpired at its own
// term. Another node may have led
// meanwhile: the host may have come back, failed again and been fenced
// afresh, or not at all, and nothing remembered from the earlier tenure
// speaks for that. Each host then goes down the path a fresh successor takes,
// from the replicated fence records (recordedFence, resumeActionFor), which
// re-derives any pause wait, recovery limit and claim retry from them.
func (c *Coordinator) forgetEpisodes() {
	c.fenced = make(map[string]bool)
	c.handledAt = nil
	c.fenceRelocated = make(map[string]bool)
	c.confirmResumed = make(map[string]string)
	c.afreshConfirm = nil
	c.fencedOn, c.lastFenceAt = nil, nil
	c.pauseWaits = nil
	c.ha.heldRecovery = nil
	c.claimRetry, c.claimRetryProposals, c.claimRetryAt, c.claimRetryMono = nil, nil, nil, nil
	c.claimRetryHeld = nil
	c.recoverOnly, c.unpausedHeld = nil, nil
	c.relocDeferred = nil
	c.retrying = nil
	c.retryNotified, c.retryRefusedLogged = nil, nil
	c.resumeDeclined, c.confirmStale, c.notRelying = nil, nil, nil
	c.stallSince, c.stallAlerted, c.stallUnfenced, c.holdReason, c.lastFenceFailure = nil, nil, nil, nil, nil
	c.holdBase, c.lastStale, c.unprovenRaised, c.restsOnTrust = nil, nil, nil, nil
	c.upgradingLives = nil
}

// resolvePendingRelocations re-derives every relocate-restore marker in the
// cluster (a container left "relocating" by an indeterminate restore or a crash),
// independent of the fence cycle. Leader-gated by run's lease.
func (c *Coordinator) resolvePendingRelocations(ctx context.Context) {
	// Decide-site gate (Phase 1): resuming a relocate-restore re-keys the container row —
	// imageRecreateOrSkip re-homes it and completeRestore tombstones the SOURCE — which is
	// a runtime-ownership DECISION. run()'s failover lease alone is insufficient: a CRDT
	// lease can be "held" on both sides of a partition, so a minority leader with a latched
	// gate could re-home the row to a minority target and tombstone the source without
	// quorum, manufacturing the two-row split Phase 6 exists to repair (execution on the
	// target is still ExecutionGate-blocked, so no double-run — but the DB ownership
	// diverges). Once enforced, require DecisionGate (quorum + coordinator-eligible).
	//
	// Under region scope the gate is per container: the quorum that may settle
	// a relocation is the source host's region's.
	enforced := c.gateEnforced(ctx)
	if enforced && !c.scope.region {
		if g := c.Gate.DecisionGate(ctx); !g.OK {
			c.noteGateRefused(ActionRelocate, g.Reason)
			return
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, "")
	if err != nil {
		return
	}
	for _, ct := range cts {
		target, token, restoring := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail)
		if !restoring {
			continue
		}
		if enforced && c.scope.region {
			if g := c.decideGate(ctx, ct.HostName); !g.OK {
				c.noteGateRefused(ActionRelocate, g.Reason)
				continue
			}
		}
		src, err := corrosion.GetHost(ctx, c.db, ct.HostName)
		if err != nil || src == nil {
			continue
		}
		// candidates are only consulted if the marker carries no target
		// (it always does), so an empty candidate set is fine here.
		c.resumeRestoreRelocation(ctx, src, ct, target, token, nil)
	}
}

// recoverHosts promotes a host the coordinator marked down back to 'active'
// once a fresh quorum of observers reports it healthy (consecutive_failures = 0).
// Without this, a host that briefly dropped (a daemon restart, a transient blip,
// or a spurious fence) never returns to active on its own — health reconverges
// in seconds but the authoritative hosts.state stays stuck.
//
//   - 'offline' with no successful fence as its newest attempt (a failed
//     fence — no successful fence, so the split-brain guard rescheduled
//     nothing unless an operator confirmed it): recovered whenever healthy,
//     once no fence is recent.
//   - 'offline' whose newest attempt SUCCEEDED: an unverified fence, which
//     records 'offline' once fence_state_v1 has latched
//     (colonelpanik/litevirt#253). It is treated exactly as 'fenced' below —
//     its workloads may have moved, by this coordinator or by a successor
//     resuming from it — and so is not put back in service just because
//     recentFenceWindow has passed.
//   - 'fenced' (a SUCCESSFUL fence): recovered ONLY if THIS coordinator did the
//     fence AND it relocated no VMs (fenceRelocated == false). A fence that moved
//     VMs — or one this coordinator has no record of (e.g. a prior leader) —
//     stays manual (`lv host undrain`), so we never resurrect a host into a
//     split-brain where a moved VM runs in two places.
//   - 'maintenance'/'draining': operator intent, never auto-cleared.
//
// Only a voter other than the host itself counts toward the recovery quorum,
// the same rule as the fence quorum (see countsAsVote). Under region scope the
// voters are the host's own region's, the same population that may fence it.
func (c *Coordinator) recoverHosts(ctx context.Context, q quorumView) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("failover: list hosts for recovery", "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return
	}
	freshCutoff := c.now().Add(-healthFreshness)
	for _, h := range hosts {
		switch h.State {
		case "offline":
			rec, _, ok, err := c.readNewestFenceAttempt(ctx, h.Name)
			if err != nil {
				// Fail closed: an unreadable log must not put back in
				// service a host whose workloads may have moved.
				slog.Warn("failover: fencing_log read for host recovery failed", "host", h.Name, "error", err)
				c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
				continue
			}
			if ok && rec.Result == fence.LogFenced {
				// A successful, unverified fence: the 'fenced' rule.
				reloc, fencedByMe := c.fenceRelocated[h.Name]
				if !fencedByMe || reloc {
					continue // not ours to clear, or VMs moved → manual undrain only
				}
			} else if c.recentlyFenced(ctx, h.Name) {
				continue // a real fence happened — treat like 'fenced'
			}
		case "fenced":
			reloc, fencedByMe := c.fenceRelocated[h.Name]
			if !fencedByMe || reloc {
				continue // not ours to clear, or VMs moved → manual undrain only
			}
		default:
			continue
		}

		// Freshness filtered in Go (both-format updated_at); see the fence-quorum
		// query above for why a SQL string compare can't span RFC3339 + HLC.
		rows, err := c.db.Query(ctx,
			`SELECT observer, updated_at
			 FROM host_health
			 WHERE target = ?
			   AND consecutive_failures = 0`,
			h.Name)
		if err != nil {
			// A query error would otherwise be indistinguishable from "not enough
			// healthy observers" and silently suppress recovery.
			slog.Warn("failover: recovery quorum query failed", "host", h.Name, "error", err)
			c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
			continue
		}
		fresh := map[string]struct{}{}
		voters, quorum := q.voters(h.Name), q.quorum(h.Name)
		for _, r := range rows {
			o := r.String("observer")
			if !countsAsVote(voters, o, h.Name) {
				continue
			}
			if inst, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && inst.After(freshCutoff) {
				fresh[o] = struct{}{}
			}
		}
		if len(fresh) < quorum {
			continue // not enough fresh healthy observers to recover
		}
		if err := corrosion.UpdateHostState(ctx, c.db, h.Name, "active"); err != nil {
			slog.Error("failover: recover host", "host", h.Name, "state", h.State, "error", err)
			c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
			continue
		}
		slog.Info("failover: host healthy again, marking active",
			"host", h.Name, "from", h.State, "healthy_observers", len(fresh), "quorum", quorum)
		c.mAttempt(PhaseRecovery, ResultRecovered, errClassNone)
		c.unmarkHandled(h.Name)
		delete(c.fenceRelocated, h.Name)
		c.forgetHost(h.Name)
	}
}

// clearRecoveredFromFenced drops hosts that are back to "active", or that
// recorded themselves 'upgrading' since they were handled
// (upgradingSinceHandled), from the in-memory fenced set. The set is meant to
// mean "already handled this down-episode"; it is set both by an actual fence
// AND by the terminal-state skip in run(). Because it was never cleared on recovery, a host that went
// down, recovered, then failed again was silently skipped forever (until the
// coordinator process restarted). Clearing recovered hosts each cycle restores
// re-fencing.
func (c *Coordinator) clearRecoveredFromFenced(ctx context.Context) {
	for host := range c.fenced {
		h, err := corrosion.GetHost(ctx, c.db, host)
		if err != nil || h == nil {
			continue
		}
		if h.State == "upgrading" && c.upgradingSinceHandled(ctx, h) {
			slog.Info("failover: a handled host recorded itself 'upgrading' since; judging it afresh, fenced if it does not serve within the upgrading timeout",
				"host", host)
		} else if h.State != "active" {
			continue
		}
		c.unmarkHandled(host)
		delete(c.fenceRelocated, host)
		c.forgetHost(host)
	}
}

// acquireLease tries to take or renew the failover-leader lease. Returns true
// if this coordinator holds the lease for at least leaseRenewBefore.
//
// The CRDT row store cannot offer linearisable CAS across partitions, so this
// is best-effort. We mitigate races by:
//  1. Updating only when the existing row is expired or already held by us.
//  2. Validating that precondition INSIDE the write transaction (the shared
//     helper's guard), so acquisition needs no post-write read; the renewal
//     path still reads back and refuses if the holder changed.
//  3. Re-validating before every destructive call (holdLease).
//  4. Renewing well before expiry (leaseRenewBefore head-room).
//
// The guarded upsert, its read-back, and the same-day expiry-compare fix now
// live in corrosion.AcquireLeaseWithTerm, shared with the rebalancer and the
// dual-run detector. leaseDuration and c.now() stay this coordinator's own:
// c.now() is the virtual clock the fleet harness overrides, and passing
// time.Now() instead would make its scenarios unable to advance past lease
// expiry without sleeping.
// acquireLease reports only whether the lease is held. Prefer
// acquireLeaseResult where the difference between "not the leader" and "could
// not tell" matters -- publishing a gauge, above all.
func (c *Coordinator) acquireLease(ctx context.Context) bool {
	held, _ := c.acquireLeaseResult(ctx)
	return held
}

// acquireLeaseResult takes or renews the failover lease and keeps the failure
// reason, so a caller can tell a lost election from an unreadable store.
func (c *Coordinator) acquireLeaseResult(ctx context.Context) (bool, error) {
	held, _, err := c.acquireLeaseTenure(ctx)
	return held, err
}

// acquireLeaseTenure is acquireLeaseResult, also reporting whether the lease
// was taken as a new tenure: this node has held the lease before, and either
// the lease row did not show its own unexpired tenure just before the take
// (ownTenureLive) or the take handed a term other than the one it last held.
// Another node may have led in between, so a new tenure marks a gap
// (leaseGap). A take that continues this node's own unexpired tenure at its
// own term marks none, however the lease was last checked: no other node can
// have taken a lease whose row still names this node unexpired.
//
// Neither half rests on this node's clock alone. The row must stay unexpired
// past fenceSkewMargin from now (ownTenureLive), so a peer whose clock runs
// that far ahead still sees it live. Before lease terms are minted (term 0),
// when no term comparison backs the row, a take after a stand-down longer
// than tenureStandDownBound is a new tenure too: a peer's take may not have
// replicated back yet.
func (c *Coordinator) acquireLeaseTenure(ctx context.Context) (held, newTenure bool, err error) {
	if c.lostEveryDecisionQuorum(ctx) {
		if !c.leaseQuorumLost.Swap(true) {
			slog.Warn("failover: this node has lost the voter majority; neither taking nor renewing the failover lease until it is back")
		}
		c.dropLeaseTerm()
		c.mAttempt(PhaseLease, ResultSkipped, ErrNoQuorum)
		// A lease nobody holds that this node cannot take over is a stalled
		// takeover: counted, and raised once it has lasted a TTL.
		corrosion.NoteLeaseNoQuorum(ctx, c.db, failoverLeaseKey, c.hostName, leaseDuration, c.now())
		// Not (false, nil): that is "another node holds the lease", on which
		// run steps this node's gauges down. When every node has lost its
		// majority nobody holds it, and every node publishing
		// stranded_workloads = 0 would clear the alert in exactly the
		// incident it is for. The former leader keeps its last values.
		return false, false, errLeaseNoQuorum
	}
	if c.leaseQuorumLost.Swap(false) {
		slog.Info("failover: the voter majority is back; contending for the failover lease again")
	}
	// Read before the take, which rewrites the row. Only a node that has held
	// the lease, and has seen no other holder since, has a tenure to continue.
	continues := false
	if c.everHeld.Load() && !c.leaseGap.Load() {
		continues = c.ownTenureLive(ctx)
	}
	held, term, err := corrosion.AcquireLeaseWithTerm(
		ctx, c.db, failoverLeaseKey, c.hostName, leaseDuration, c.now())
	if err != nil {
		// Covers both former error outcomes — the write failing and the
		// read-back failing — which reported this same metric triple.
		slog.Error("failover: lease write", "error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.dropLeaseTerm()
		return false, false, err
	}
	if !held {
		// Another coordinator holds it — the normal non-leader case.
		c.loseLease()
		c.mAttempt(PhaseLease, ResultSkipped, ErrNotLeader)
		return false, false, nil
	}
	if since := c.unshownSince.Swap(nil); since != nil && term == 0 &&
		c.mono().Sub(*since) > tenureStandDownBound {
		continues = false
	}
	if c.everHeld.Load() && (!continues || term != c.tenureTerm.Load()) {
		// A new incarnation: another holder may have led since this one's.
		newTenure = true
		c.leaseGap.Store(true)
	}
	c.everHeld.Store(true)
	c.tenureTerm.Store(term)
	c.leaseTerm.Store(term)
	c.mAttempt(PhaseLease, ResultOK, errClassNone)
	return true, newTenure, nil
}

// ownTenureLive reports whether the failover lease row names this node with
// an expiry more than fenceSkewMargin ahead: the tenure it last held has not
// lapsed even on a peer whose clock runs that far ahead, so no other node can
// have taken the lease since. A read error, or a row it cannot use, reports
// false.
func (c *Coordinator) ownTenureLive(ctx context.Context) bool {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil || len(rows) == 0 || rows[0].String("holder") != c.hostName {
		return false
	}
	exp, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	return err == nil && exp.After(c.now().Add(fenceSkewMargin))
}

// tenureStandDownBound is how long, before lease terms are minted, this
// coordinator may be unable to show it holds the lease and still continue its
// tenure on re-taking it: two polls, so a single failed read is not a gap.
const tenureStandDownBound = 2 * pollInterval

// onlyReportedPausedFilter keeps the items of kind that a recovery limited to
// only may move: those listed there, which the host reported pausing. A nil
// only keeps everything. dropped is the rest.
func onlyReportedPausedFilter[T any](only map[string]bool, kind string, items []T, name func(T) string) (keep, dropped []T) {
	if only == nil {
		return items, nil
	}
	for _, it := range items {
		if only[kind+"/"+name(it)] {
			keep = append(keep, it)
		} else {
			dropped = append(dropped, it)
		}
	}
	return keep, dropped
}

// heldVMNames names the VMs a limited recovery dropped that it would
// otherwise have recovered (wouldRecoverVM): the ones the host may still run
// and that wait for an operator. A VM never to be recovered (stopped by
// intent, on_host_failure=none, firmware state) is not one. A read error
// names the VM.
func (c *Coordinator) heldVMNames(ctx context.Context, dropped []corrosion.VMRecord) []string {
	if len(dropped) == 0 {
		return nil
	}
	enrolled, err := c.autoPromoteEnrolled(ctx)
	var names []string
	for _, vm := range dropped {
		if err == nil {
			if would, werr := c.wouldRecoverVM(ctx, vm, enrolled); werr == nil && !would {
				continue
			}
		}
		names = append(names, vm.Name)
	}
	return names
}

// heldContainerNames is heldVMNames for containers.
func heldContainerNames(dropped []corrosion.ContainerRecord) []string {
	var names []string
	for _, ct := range dropped {
		if containerNeedsFailover(ct) {
			names = append(names, ct.Name)
		}
	}
	return names
}

// noteNotReportedPaused says, for each workload a limited recovery left on
// host, why: the host answered through a bridge and did not report pausing
// it, so it may still be running there. It stays for an operator.
func (c *Coordinator) noteNotReportedPaused(host, kind string, names []string) {
	if len(names) == 0 {
		return
	}
	if c.unpausedHeld == nil {
		c.unpausedHeld = map[string]map[string]bool{}
	}
	if c.unpausedHeld[host] == nil {
		c.unpausedHeld[host] = map[string]bool{}
	}
	for _, n := range names {
		c.unpausedHeld[host][kind+"/"+n] = true
	}
	slog.Warn("failover: not recovering workloads the host answering through a bridge did not report pausing; they may still run there",
		"host", host, "kind", kind, "workloads", names)
	c.noteHold(host, "recovery left "+kind+" "+strings.Join(names, ",")+": the host did not report pausing them and may still run them")
}

// limitRecovery limits every recovery of host to only, for the rest of its
// down-episode; nil lifts the limit. A new list replaces the held names too:
// the next recovery names again what the new list still leaves.
func (c *Coordinator) limitRecovery(host string, only map[string]bool) {
	if only == nil {
		c.unlimitRecovery(host)
		return
	}
	if c.recoverOnly == nil {
		c.recoverOnly = map[string]map[string]bool{}
	}
	c.recoverOnly[host] = only
	delete(c.unpausedHeld, host)
}

// unlimitRecovery lifts host's recovery limit: it is back in service, or an
// operator's confirmation or a fence that proves it off (fence.ProofGrade)
// vouches for every workload on it.
func (c *Coordinator) unlimitRecovery(host string) {
	delete(c.recoverOnly, host)
	delete(c.unpausedHeld, host)
}

// unpausedHeldReason names the workloads a limited recovery has left on
// host, "" when none.
func (c *Coordinator) unpausedHeldReason(host string) string {
	if len(c.unpausedHeld[host]) == 0 {
		return ""
	}
	names := make([]string, 0, len(c.unpausedHeld[host]))
	for k := range c.unpausedHeld[host] {
		names = append(names, k)
	}
	sort.Strings(names)
	return "held for an operator, not reported paused by the host and possibly still running there: " + strings.Join(names, ",")
}

// errLeaseNoQuorum is acquireLeaseResult standing down because this node has
// lost every voter majority it could decide on.
var errLeaseNoQuorum = errors.New("this node has lost the voter majority")

// lostEveryDecisionQuorum is health.LostEveryDecisionQuorum over this
// coordinator's gate: a node that has lost every voter majority it could
// decide a failover on neither takes nor renews the failover lease. A
// coordinator with no gate keeps today's behaviour, and one whose gate cannot
// answer the regional question counts no region.
//
// Under region scope it stands down too when it has lost its own region's
// majority (health.LostOwnRegionQuorumUnder), whatever it reaches elsewhere:
// that majority may need the lease to fence this node.
//
// The failover lease asks more of a reading than the other leases do: a
// scope holds only on a Yes outside its quorum-regain grace (QuorumRegain).
// Unknown is not a Yes, so a holder that restarts inside a partition does not
// renew during its warmup, and one whose quorum flaps renews only once a Yes
// has lasted the grace. Either would otherwise keep refreshing its lease on a
// node bridging the halves.
func (c *Coordinator) lostEveryDecisionQuorum(ctx context.Context) bool {
	if c.Gate == nil {
		return false
	}
	var region func(context.Context, string) (health.QuorumState, int, int)
	if rg, ok := c.Gate.(RegionGate); ok {
		region = rg.RegionQuorumProof
	}
	held := func(ctx context.Context, st health.QuorumState, scope string) bool {
		return st == health.QuorumYes && (c.QuorumRegain == nil || !c.QuorumRegain(ctx, scope))
	}
	pol := c.policy()
	return health.LostOwnRegionQuorumUnder(ctx, pol, c.hostName, region, held) ||
		health.LostEveryDecisionQuorumUnder(ctx, pol, c.Gate.QuorumProof, region, held)
}

// policy is the failover scope and voter regions this cycle decides on, read
// once per cycle (cyclePolicy); outside a cycle, a fresh read.
func (c *Coordinator) policy() *health.DecisionPolicy {
	if c.cyclePolicy != nil {
		return c.cyclePolicy
	}
	return health.NewDecisionPolicy(c.db)
}

// LeaseTerm is the fencing term of the lease incarnation this coordinator holds,
// 0 when it holds none. Exported for the Phase-2 enforcement path and for tests;
// nothing enforces on it yet.
func (c *Coordinator) LeaseTerm() int64 { return c.leaseTerm.Load() }

// holdLease re-validates that we still hold the failover lease and that the
// remaining TTL is at least leaseRenewBefore. Renews if low. Returns false if
// the lease is lost or read fails.
// Every false return here CLEARS leaseTerm. holdLease is this coordinator's
// displacement detector — it is called per fence candidate and again immediately
// before the destructive call — so it is the one path that most needs to stop
// reporting a token this node has demonstrably lost. It did not clear it, so a
// coordinator displaced mid-cycle kept answering with its old term for up to a
// poll interval, including at the pre-fence check. acquireLease cleared on every
// loss path, which made the asymmetry easy to miss.
func (c *Coordinator) holdLease(ctx context.Context) bool {
	_, ok := c.holdLeaseAtLeast(ctx, leaseRenewBefore)
	return ok
}

// leaseHold is holdLeaseFor's answer.
type leaseHold int

func (st leaseHold) String() string {
	switch st {
	case leaseHeld:
		return "held"
	case leaseLost:
		return "lost"
	case leaseNewTenure:
		return "new_tenure"
	}
	return "unshown"
}

const (
	// leaseHeld: the lease is held, with the margin asked for.
	leaseHeld leaseHold = iota
	// leaseLost: another node holds the lease, or claims it. A step-down.
	leaseLost
	// leaseUnshown: this node cannot show it holds the lease (a read or
	// write error, a lease row it cannot use, the voter majority lost, or
	// too short a renewal). Not a step-down: nothing shows another node
	// leads.
	leaseUnshown
	// leaseNewTenure: renewed, but as a new tenure (acquireLeaseTenure).
	// This node still leads; the cycle's view of each host predates whoever
	// may have led in between, and the next cycle starts afresh.
	leaseNewTenure
)

// holdLeaseAtLeast re-validates the failover lease and guarantees strictly more
// than `need` remaining on it, renewing when the margin is short. It returns
// the remaining TTL so a caller can bound a long operation by the authority it
// actually holds rather than by a hardcoded guess.
//
// A renewal that still cannot reach `need` is a refusal, not a success: it
// means this node no longer holds enough of the lease to finish the work
// safely, and proceeding would be acting past its own authority.
func (c *Coordinator) holdLeaseAtLeast(ctx context.Context, need time.Duration) (time.Duration, bool) {
	left, st := c.holdLeaseFor(ctx, need)
	return left, st == leaseHeld
}

// holdLeaseFor is holdLeaseAtLeast, saying why when the lease is not held.
func (c *Coordinator) holdLeaseFor(ctx context.Context, need time.Duration) (time.Duration, leaseHold) {
	left, st := c.leaseRemaining(ctx)
	if st != leaseHeld {
		return 0, st
	}
	if c.leaseGap.Load() {
		// A renewal earlier in this cycle came back as a new tenure; run
		// clears the mark once the next cycle has started afresh.
		return 0, leaseNewTenure
	}
	if left > need {
		return left, leaseHeld
	}
	held, newTenure, err := c.acquireLeaseTenure(ctx)
	switch {
	case !held && err == nil:
		return 0, leaseLost
	case !held:
		return 0, leaseUnshown
	case newTenure:
		// Renewed as a new tenure: this cycle's view of each host predates
		// whoever may have led in between. The next cycle starts afresh.
		return 0, leaseNewTenure
	}
	left, st = c.leaseRemaining(ctx)
	if st != leaseHeld {
		return 0, st
	}
	if left <= need {
		return 0, leaseUnshown
	}
	return left, leaseHeld
}

// leaseRemaining reports how much of the failover lease this node still holds.
// It returns ok=false when the row is missing or unreadable, when the holder is
// someone else, or when expires_at cannot be parsed — every case in which this
// node cannot prove it is the leader.
//
// Every ok=false return CLEARS leaseTerm. This is the coordinator's
// displacement detector — holdLease reaches it per fence candidate and again
// immediately before the destructive call — so it is the one path that most
// needs to stop reporting a token this node has demonstrably lost. It did not
// clear it, so a coordinator displaced mid-cycle kept answering with its old
// term for up to a poll interval, including at the pre-fence check.
// acquireLease cleared on every loss path, which made the asymmetry easy to
// miss.
//
// Both callers inherit that: holdLease and the fence-bounding
// holdLeaseAtLeast read the lease through here and nowhere else.
func (c *Coordinator) leaseRemaining(ctx context.Context) (time.Duration, leaseHold) {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil {
		slog.Error("failover: lease read", "error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.dropLeaseTerm()
		return 0, leaseUnshown
	}
	if len(rows) == 0 {
		// The lease row is absent while this coordinator believes it may hold
		// it. Nothing in the tree ever DELETEs a leader_election row, so this is
		// local corruption or truncation, not the ordinary non-leader case — it
		// must stay distinguishable from the skip that fires on N-1 nodes every
		// poll, and must keep tripping the result="error" alert.
		slog.Warn("failover: lease row missing")
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.dropLeaseTerm()
		return 0, leaseUnshown
	}
	if rows[0].String("holder") != c.hostName {
		c.loseLease()
		return 0, leaseLost
	}
	expiresAt, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil {
		slog.Error("failover: lease expiry unparseable", "value", rows[0].String("expires_at"))
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		c.dropLeaseTerm()
		return 0, leaseUnshown
	}
	return expiresAt.Sub(c.now()), leaseHeld
}

// leaseTermEnforced reports whether this coordinator refuses to stamp on the
// strength of its lease term: the config flag AND the cluster-wide latch, the
// same `flag && Enforced` model as the rest of this family.
//
// Both halves are load-bearing, and the latch half especially. An operator sets
// enforcement.lease_term ahead of the latch during a roll — that is the intended
// order — and pre-latch a perfectly healthy leader holds term 0, because the
// ledger mint gate is still closed and AcquireLeaseWithTerm deliberately reports
// no term. Enforcing on the flag alone would therefore stand this coordinator
// down from every action it drives, on every node, for the whole rollout, while
// the executor (which gates on the same latch) went on accepting term-0 proofs.
// All cost, no safety.
func (c *Coordinator) leaseTermEnforced(ctx context.Context) bool {
	return c.LeaseTermEnforce && c.Gate != nil && c.Gate.Enforced(ctx, capabilities.LeaseTermV1)
}

// leaseTermStampAllowed reports whether this coordinator may stamp a proof with
// its recorded term.
//
// The term is c.LeaseTerm() — the incarnation this coordinator actually acquired
// — and NEVER a fresh ledger read. Deriving it here would let a displaced holder
// that has received the winner's term row stamp proofs with the winner's term,
// the privilege escalation Phase 1 closed. The ledger read below is the
// THRESHOLD, used only to reject, never to adopt.
func (c *Coordinator) leaseTermStampAllowed(ctx context.Context) bool {
	if !c.leaseTermEnforced(ctx) {
		// Nothing to check: pre-latch there is no term to be stale, and with the
		// flag off the operator has taken enforcement off this node deliberately.
		// Stamp whatever term we hold — 0 pre-latch — so the term is observable
		// before the flip rather than appearing for the first time with it.
		return true
	}
	term := c.LeaseTerm()
	if term <= 0 {
		// Enforcing, so the ledger has latched and a real holder has a real term.
		// No term here means this coordinator holds no lease incarnation — never
		// acquired one, or holdLease cleared it on a loss path — and acting as
		// leader without one produces exactly the unfenced write the term exists
		// to prevent.
		// Its two neighbouring arms below both log; this one did not, so the one
		// cause an operator cannot infer from the refusal itself was the one with
		// no line naming it.
		slog.Warn("failover: this coordinator holds no usable lease term — refusing to stamp "+
			"(never acquired one, or holdLease cleared it on a loss path)",
			"term", term, "coordinator", c.hostName)
		c.mAttempt(PhaseLease, ResultSkipped, ErrLeaseLost)
		return false
	}
	threshold, err := corrosion.CurrentLeaseTerm(ctx, c.db, failoverLeaseKey)
	if err != nil {
		// FAIL OPEN, deliberately, and this is the one place in the family that
		// does. Every caller is past the fence: the host is powered off and its
		// row is persisted offline, and a fenced host is processed only once, so
		// refusing here does not defer the work — it abandons it, and the
		// workload stays assigned to a dead host until an operator intervenes.
		//
		// Weigh that against what refusing buys. This precheck is an
		// optimisation; the executor's quorum barrier is the guarantee and runs
		// regardless. An unreadable threshold is no evidence we are superseded —
		// the overwhelmingly likely cause is a transient DB error on a
		// coordinator whose term is perfectly current — so stamping produces a
		// valid proof the executor accepts, and in the rare case we ARE stale the
		// barrier refuses it exactly as designed. Fail-closed here trades a
		// guaranteed stranded workload for a check that was never the guarantee.
		//
		// The error is still counted, so a threshold read that fails persistently
		// is visible rather than silently permissive.
		slog.Error("failover: read lease term threshold — stamping anyway (precheck fails open)",
			"error", err)
		c.mAttempt(PhaseLease, ResultError, ErrDBError)
		return true
	}
	if term < threshold {
		slog.Warn("failover: this coordinator's lease term is superseded — refusing to stamp",
			"term", term, "threshold", threshold)
		c.mAttempt(PhaseLease, ResultSkipped, ErrStaleLeaseTerm)
		return false
	}
	return true
}

// leaseStamp returns everything a proof records about this coordinator's tenure:
// the holder and expiry read from the lease row, and the fencing term from
// c.LeaseTerm(). ok is false when this coordinator must not stamp at all, and the
// caller must abandon the action rather than stamp a partial record.
//
// All three stamp sites go through this, and that is the point of it existing.
// The term is RETURNED rather than read at each site, so a site cannot silently
// omit it. And the holder comes from the lease row, not from c.hostName: two of
// the three sites previously wrote their own identity into LeaseHolder, which
// asserts "I hold the lease" on the authority of the process making the claim —
// precisely the assertion the fencing term exists to stop trusting. leaseSnapshot
// returns empty on a read error, so this field can be blank on a perfectly valid
// proof; blank is correct and self-reporting was a fabrication.
// noteLeaseTermRefusal records a lease-term stamp refusal the way every other
// abandonment branch in these loops records one: a log line and a failover.skip
// audit row naming the workload.
//
// It is not deferred work. strandedByHost's own doc says a fenced host is
// processed only once, and run() short-circuits the host on every later cycle,
// so a refusal here is a permanent per-workload outage. It used to leave only
// two counters — and it fires immediately after "failover: rescheduling VM", so
// the journal read as a reschedule that simply ended.
//
// Counters cannot answer the question an operator has at 3am, which is WHICH
// workloads were stranded: one superseded term strands every workload on the
// host at once and the metric just reaches 40.
func (c *Coordinator) noteLeaseTermRefusal(ctx context.Context, kind, name, from string) {
	slog.Error("failover: refusing to stamp an action proof — this coordinator's lease term is "+
		"unusable, so the workload is ABANDONED (a fenced host is processed only once)",
		kind, name, "from", from, "term", c.LeaseTerm(), "coordinator", c.hostName)
	c.audit(ctx, "failover.skip", name, "refused to stamp an action proof: this coordinator's lease term is unusable "+
		"(never acquired, cleared on a loss path, or superseded by a newer holder)", "refused")
}

func (c *Coordinator) leaseStamp(ctx context.Context) (holder, expiresAt string, term int64, key string, ok bool) {
	if !c.leaseTermStampAllowed(ctx) {
		return "", "", 0, "", false
	}
	holder, expiresAt = c.leaseSnapshot(ctx)
	term = c.LeaseTerm()
	// The key travels WITH the term, and only with it. A proof stamp is a pair,
	// and judgeProofLeaseTerm recognises exactly two valid shapes: a positive
	// term with a producible key, or the legacy sentinel (0, ""). The half-set
	// (0, "failover") is neither — it lands in "not a judgeable pair" and the
	// executor refuses the action outright, for every action including relocate,
	// which is deliberately outside leaseTermRequiredActions.
	//
	// It was reachable, and not through the flag it first looked like. Minting
	// gates on DurablyLatched(LeaseTermLedgerV1) — a token with no config flag —
	// so clearing enforcement.lease_term leaves the mint working and the term
	// positive. The producer is holdLeaseWithoutTerm, whose term is ALWAYS 0,
	// taken when MayMintLeaseTerm is false: a freshly joined or re-imaged host,
	// or one whose activation marker never persisted. That coordinator is not
	// enforcing, so the branch above lets it stamp, while executors that HAVE
	// latched enforce permanently — the latch never un-latches. A fenced host is
	// processed exactly once, so every workload in that window was abandoned for
	// good.
	//
	// Returning the key here rather than at the three call sites is the same
	// reason the term is returned here: a site cannot set one half of a pair it
	// never sees. That was already this function's stated purpose; the key was
	// simply left behind.
	if term <= 0 {
		return holder, expiresAt, term, "", true
	}
	return holder, expiresAt, term, corrosion.LeaseKeyFailover, true
}

// leaseSnapshot returns the current failover-lease holder + expiry to record in a
// proof, as the human-readable record of the tenure.
//
// It is NOT the proof's enforceable token: that is ActionProof.LeaseTerm, which
// comes from c.LeaseTerm() via leaseStamp. This snapshot deliberately returns
// empty on a read error — an honesty record must not FABRICATE a holder — so it
// can be blank on a perfectly valid proof, which is exactly why the executor's
// equal-term check compares against Coordinator rather than LeaseHolder.
func (c *Coordinator) leaseSnapshot(ctx context.Context) (holder, expiresAt string) {
	rows, err := c.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil || len(rows) == 0 {
		// An honesty record must not FABRICATE a holder on a read error — reporting self
		// would falsely assert this node held the lease. Return empty (unknown).
		return "", ""
	}
	return rows[0].String("holder"), rows[0].String("expires_at")
}

// stillOurTenure re-reads the failover lease and reports whether this
// coordinator still holds it.
//
// leaseStamp does NOT answer this. It reports whether stamping is allowed and
// returns the term this coordinator recorded at acquisition -- deliberately,
// so a displaced holder cannot adopt the winner's term -- but it never asks
// whether the lease is still ours. A tick that passed its own lease gate at
// the top and then stalled (a GC pause, a slow DB) can therefore act on a
// tenure a successor already took.
//
// Fails CLOSED. leaseSnapshot returns an empty holder on a read error rather
// than fabricating one, and an unknown holder is not a held lease: abandoning
// one VM's recovery costs a cycle, while promoting on a lapsed tenure defines
// and starts a VM on a new host while the old tenure's successor may be doing
// the same.
func (c *Coordinator) stillOurTenure(ctx context.Context) bool {
	holder, _ := c.leaseSnapshot(ctx)
	return holder != "" && holder == c.hostName
}

// recentlyFenced returns true if the fencing_log shows a successful fence for
// host within the recentFenceWindow. Prevents re-fence after restart or race.
func (c *Coordinator) recentlyFenced(ctx context.Context, host string) bool {
	return c.fenceWithinWindow(ctx, host, false)
}

// recentlyFencedAfter is recentlyFenced counting only rows stamped after
// failedAt: the recent-fence check of a RETRY of the fence attempt that failed
// at failedAt (fenceRetryDue's FailedAt).
//
// fenceRowCutoff dates a row against the moment the host last turned active,
// and a failed fence records the host 'offline', so from the first failed
// attempt of an outage on there is no such moment to judge by and every row
// under recentFenceWindow counted again — a successful fence or a
// confirmation of the host's PREVIOUS outage included. On lab 1 (2026-10-12,
// the Redfish drill, R1) that held every retry of a failed fence back until
// the previous outage's row was five minutes old, against a 30 s backoff.
//
// The failed attempt is the one boundary that outlasts the state change, and
// it is the right one: fenceRetryDue offers a retry only when the newest
// attempt on record failed, so any success or confirmation it read is older
// than the failure and already answered by it. One newer than the failure —
// it replicated here after fenceRetryDue read the log, or an operator fenced
// the host in between — still counts and skips the retry, and the next cycle
// resumes from it (recordedFence, resumeFromConfirmation). A row in the
// failure's own second does not count, as fenceRetryDue lets a failure win a
// same-second tie. What bounds the retries is not this check but the backoff,
// read from fencing_log by every coordinator alike (fenceRetryDelay).
func (c *Coordinator) recentlyFencedAfter(ctx context.Context, host string, failedAt time.Time) bool {
	return c.fenceWithinWindowAfter(ctx, host, false, failedAt)
}

// manualFenceConfirmed returns true if an operator has written a
// "manual-confirmed" row in fencing_log for this host within the recent
// fence window. The CLI command `lv host fence-confirm <host>` writes this
// row after the operator has physically powered the host off.
func (c *Coordinator) manualFenceConfirmed(ctx context.Context, host string) bool {
	return c.fenceWithinWindow(ctx, host, true)
}

// confirmedOffNow is the operator confirmation recoverFenced's gates accept:
// manualFenceConfirmed's recent one, and only while it still stands for the
// outage host is in now (confirmationStands) and, when life is known, was
// written in the host's current life. life is fenceRowCutoff read before
// recoverFenced recorded the host 'offline', which ends the life it measures.
// manualFenceConfirmed alone accepts any confirmation under five minutes old,
// so one from before the host last came back (a reboot boots it 'active')
// would be spent on a fence of its next outage while it runs its workloads.
// A refusal is noted with its remedy (noteConfirmationStale), and stale is
// that note then; it is empty when there is no recent confirmation at all, or
// on a read error. A gate that refuses on it still holds on its own reason,
// with stale appended (withStaleConfirmation): the confirmation is only why
// the gate did not pass.
func (c *Coordinator) confirmedOffNow(ctx context.Context, host string, life time.Time, lifeKnown bool) (stale string, confirmed bool) {
	if !c.manualFenceConfirmed(ctx, host) {
		return "", false
	}
	confirm, confirmedAt, _, ok := c.confirmationAndAttempt(ctx, host)
	if !ok || confirmedAt.IsZero() {
		return "", false
	}
	if lifeKnown && confirmedAt.Before(life) {
		return c.noteConfirmationStale(host, confirm, "it was written before the host last turned active"), false
	}
	why, stands := c.confirmationStands(ctx, host, confirmedAt)
	if !stands {
		return c.noteConfirmationStale(host, confirm, why), false
	}
	return "", true
}

// withStaleConfirmation appends to a gate's hold reason the operator
// confirmation that does not stand for this outage (confirmedOffNow's note),
// when there is one. The gate's own reason leads: it is why a confirmation is
// needed at all, and a stale confirmation alone reads as the only problem
// (the rc9 lab's A2: an untrusted SSH power-off held as "the confirmation
// does not stand", never naming the fence or the trust opt-in).
func withStaleConfirmation(reason, stale string) string {
	if stale == "" {
		return reason
	}
	if reason == "" {
		return stale
	}
	return reason + "; " + stale
}

// safeFenceRequiresProof reports whether a FAILED best-effort fence of h must be
// confirmed (like "manual") before rescheduling. True only when the safe-fence
// policy (SafeFenceDefaultV1) is enforced cluster-wide AND the host has not opted
// into the legacy proceed-anyway behavior via LabelUnsafeAutoFailover. Pre-flip
// (token not enforced) it is false, preserving today's behavior for a
// mixed-version roll. A nil Gate (tests without the split-brain gate wired) is
// also false — the policy is a strict addition on top of the gate.
func (c *Coordinator) safeFenceRequiresProof(ctx context.Context, h *corrosion.HostRecord) bool {
	// Config kill-switch (default false, zero value = legacy) AND the cluster-wide
	// capability latch. The flag short-circuits the latch, so it can be disabled
	// without a redeploy or marker deletion.
	if !c.SafeFenceEnforce || c.Gate == nil || !c.Gate.Enforced(ctx, capabilities.SafeFenceDefaultV1) {
		return false
	}
	return h == nil || h.Labels[corrosion.LabelUnsafeAutoFailover] != "true"
}

// sharedStorageFenceEnforced reports whether this coordinator enforces the
// shared-disk ownership-transfer fence gate: the config kill-switch AND the
// SharedStorageFenceV1 cluster-wide latch. Mirrors safeFenceRequiresProof's
// flag-short-circuits-latch model — a nil Gate (tests) is not enforcing.
func (c *Coordinator) sharedStorageFenceEnforced(ctx context.Context) bool {
	return c.SharedStorageFenceEnforce && c.Gate != nil && c.Gate.Enforced(ctx, capabilities.SharedStorageFenceV1)
}

// fenceWithinWindow reports whether host has a fencing_log row with an accepted
// result newer than now-recentFenceWindow. manualOnly restricts the accepted
// result to "manual-confirmed".
//
// The recency comparison is done in Go, NOT in SQL. fencing_log.timestamp is
// RFC3339 ("2026-06-08T11:52:15Z"); comparing it against datetime('now', …)
// (which yields space-separated text) is a string compare that breaks once the
// date matches — 'T' (0x54) sorts above ' ' (0x20) — so a same-day prior fence
// looks "recent" forever and the host is never re-fenced. SQLite's datetime()
// normalization of the Z suffix also differs between the CLI and the pure-Go
// (modernc) engine the daemon links, so neither SQL form is reliable here.
func (c *Coordinator) fenceWithinWindow(ctx context.Context, host string, manualOnly bool) bool {
	return c.fenceWithinWindowAfter(ctx, host, manualOnly, time.Time{})
}

// fenceWithinWindowAfter is fenceWithinWindow counting, when after is set,
// only rows stamped after it (recentlyFencedAfter).
func (c *Coordinator) fenceWithinWindowAfter(ctx context.Context, host string, manualOnly bool, after time.Time) bool {
	rows, err := c.db.Query(ctx,
		`SELECT result, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		// Fail open (treat as no recent fence) but make the read error visible —
		// it affects both recent-fence suppression and manual confirmation.
		slog.Warn("failover: fencing_log read failed, treating as no recent fence", "host", host, "error", err)
		c.mAttempt(PhaseHealth, ResultError, ErrDBError)
		return false
	}
	cutoff := c.now().Add(-recentFenceWindow)
	life, lifeKnown := c.fenceRowCutoff(ctx, host)
	for _, r := range rows {
		switch result := r.String("result"); {
		case manualOnly && result != "manual-confirmed":
			continue
		case !manualOnly && result != "fenced" && result != "manual-confirmed":
			continue
		}
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		if lifeKnown && ts.Before(life) {
			continue // an earlier life of the host (fenceRowCutoff)
		}
		if !after.IsZero() && !ts.After(after) {
			continue // answered by a later failed attempt (recentlyFencedAfter)
		}
		if ts.After(cutoff) {
			return true
		}
	}
	return false
}

// recordedFence returns the fence a leader recorded for h and stopped short of
// recovering from (it lost the lease, or died), or ok=false when there is
// none. It demands all of:
//
//   - the host is in 'fenced' or 'offline' state — the cluster's own record
//     that a fence of this host succeeded: 'fenced' for one that proved the
//     host off, 'offline' for one that did not (fenceRecordState). An operator
//     who has undrained the host back to 'active' has consumed that fence. So,
//     usually, has the host's own daemon, whose boot write records it
//     'active' — but that write can be lost (a failed startup write, or LWW
//     under clock skew), so nothing below relies on it;
//   - the NEWEST fence attempt on record ran and succeeded (result "fenced"):
//     not an operator's "manual-confirmed" attestation, which the confirmation
//     path (resumeFromConfirmation) owns, and not a later failed attempt — a
//     re-fence that failed leaves exactly that, and so does the failed fence
//     an 'offline' host is most often recorded for, which is what stops a host
//     being re-fenced every cycle.
//
// An UNVERIFIED fence is resumable from 'offline' (colonelpanik/litevirt#253):
// once fence_state_v1 has latched that is the only state it records, and
// refusing it would strand every recovery whose leader lost the lease after an
// SSH fence. What the successor does with it is resumeActionFor's decision,
// and the resumed recovery passes the same safe-fence policy and
// LabelFenceRequiresConfirmation gate the leader's would have.
func (c *Coordinator) recordedFence(ctx context.Context, h *corrosion.HostRecord) (fenceRecord, time.Time, bool) {
	if h.State != "fenced" && h.State != "offline" {
		return fenceRecord{}, time.Time{}, false
	}
	rec, at, ok := c.newestFenceAttempt(ctx, h.Name)
	if !ok || rec.Result != fence.LogFenced || rec.Method == "manual" {
		return fenceRecord{}, time.Time{}, false
	}
	return rec, at, true
}

// resumeAction is what a successor does with a recorded fence.
type resumeAction int

const (
	// resumeDecline leaves the workloads where they are, for an operator.
	resumeDecline resumeAction = iota
	// resumeFromRecord resumes the recovery on the recorded fence alone.
	resumeFromRecord
	// resumeAfterRefence powers the host off again, with the recorded
	// (verified) method, and recovers only if that fresh fence succeeds.
	resumeAfterRefence
)

// resumeActionFor decides how a successor takes over a recorded fence rec of
// host at `at`, and when it declines, why.
//
//   - A VERIFIED fence (corrosion.FenceProofGrade) is resumed from the record
//     only while it is fresh, inside recentFenceWindow, and still stands
//     (fenceStillStands). Otherwise — older, or with any doubt that the host
//     stayed down — the successor fences it again with the recorded method.
//     A verified power-off is idempotent and cheap, and a fresh one is
//     authority by itself: it closes the "host came back and nobody saw it"
//     gap without inferring anything from health rows, and it gives the
//     shared-disk gate (proofGradeFenceRef) a fence inside its window to bind.
//   - A fence that relied on the host's partition pause is resumed, while
//     that pause may still be relied on (relyOnPartitionPause), once an
//     observer has watched the host stay down since it: recoverFenced waits
//     afresh, and the deadline applies the self-pause rule. Once the pause
//     may not be relied on, it is an unverified fence, as below.
//   - An UNVERIFIED fence (SSH, best-effort) is resumed from the record while
//     it still stands, and never re-fenced: a second SSH power-off of a host
//     that is already off cannot connect and reports a FAILED fence, which
//     strands the workloads behind the split-brain guard. A best-effort fence
//     that no longer stands is declined, for an operator.
//
// The resume re-enters recoverFenced with the recorded method, so the
// safe-fence policy and LabelFenceRequiresConfirmation apply to it exactly as
// they would have to the leader: the successor gets the dead leader's
// authority and no more.
func (c *Coordinator) resumeActionFor(ctx context.Context, h *corrosion.HostRecord, rec fenceRecord, at time.Time) (resumeAction, string) {
	return c.resumeActionForIn(ctx, c.readHostHealth(ctx, h.Name), h, rec, at)
}

// resumeActionForIn is resumeActionFor over host_health rows already read, so
// a caller that has checked the read decides on exactly those rows.
func (c *Coordinator) resumeActionForIn(ctx context.Context, hr healthRead, h *corrosion.HostRecord, rec fenceRecord, at time.Time) (resumeAction, string) {
	host := h.Name
	if corrosion.ReliesOnPartitionPause(rec.Method, rec.Detail) && !c.relyOnPartitionPause(ctx, h) {
		// A self-pause record is authority only while the pause is relied
		// on: without it, nothing proves the host is off.
		return resumeDecline, whyPauseNotRelied
	}
	if corrosion.ReliesOnPartitionPause(rec.Method, rec.Detail) {
		// A fence that relied on the host's partition pause, which may still
		// be relied on. The host is up by design, so whether anybody has seen
		// it answer is not this point's question: recoverFenced starts a fresh
		// wait, and the deadline asks it (selfPauseStillStands). An outage
		// that has ended is still declined here.
		if !c.streakSpansIn(hr, host, at) {
			return resumeDecline, "no observer has watched the host stay down since the fence"
		}
		return resumeFromRecord, ""
	}
	why, _, stands := c.fenceStillStandsIn(hr, host, at)
	if !corrosion.FenceProofGrade(rec.Method, rec.Result) {
		if stands {
			return resumeFromRecord, ""
		}
		return resumeDecline, why
	}
	if stands && at.After(c.now().Add(-recentFenceWindow)) {
		return resumeFromRecord, ""
	}
	return resumeAfterRefence, ""
}

// fenceSkewMargin bounds the clock skew between the leader that stamped a
// fence (fencing_log.timestamp is its wall clock) and the observers whose
// host_health rows it is compared against (each observer's own clock). Every
// comparison below gives the margin to the safe side: an observer's failing
// run must have begun at least this long before the fence, and a verdict that
// the host answered counts from this long before it. It is the clock-skew
// alert threshold (litevirt_cluster_clock_skew_seconds > 5,
// docs/operating-model.md): skew beyond it makes these checks refuse more,
// and it is only an observer running BEHIND the leader by more than the
// margin that can make them accept wrongly.
//
// Under hlc_lww the stamps are HLC, not wall time: an observer that has
// adopted a fast peer's physical time stamps its rows that far ahead (up to
// hlc.MaxSkewMS), while a host that has just booted may stamp its activation
// from its own wall clock. countedSinceActive's afreshRun then shrinks by that
// lead, and past it a restarted host is fenced on its carried count as before
// this margin existed. That errs toward fencing, never toward leaving a dead
// host unfenced, and a graceful restart is covered regardless: it stays
// 'upgrading' until it serves (hostboot).
const fenceSkewMargin = 5 * time.Second

// fenceStillStands reports whether a fence of host at `at` is still authority
// over the outage host is in now, and when it is not, why.
//
// Two things must hold, and both fail towards refusing:
//
//   - some observer has watched the host fail without a break since before
//     the fence (observerStreakSpans). This is required however recent the
//     fence is: a genuine fence follows a quorum of failing runs, so it always
//     has one, and inside recentFenceWindow a host can still have answered,
//     failed again and had the 'active' record of its return lost — the
//     verdict that it answered is overwritten by the next failing one, and
//     only the run's start betrays it;
//   - nobody has seen the host answer since: no observer's latest verdict
//     about it, healthy or unready, is newer than the fence, and no
//     observer's failing run began after it (restartedSinceObserversIn) — a
//     run that starts after the fence follows an answer the next failing
//     verdict overwrote. A host that answered a probe after a verified
//     power-off was powered on again, and a host that answered after a
//     best-effort one was never off.
func (c *Coordinator) fenceStillStands(ctx context.Context, host string, at time.Time) (string, bool) {
	why, _, ok := c.fenceStillStandsIn(c.readHostHealth(ctx, host), host, at)
	return why, ok
}

// fenceStillStandsIn is fenceStillStands over host_health rows already read,
// also naming the observers that saw host answer since the fence, sorted.
func (c *Coordinator) fenceStillStandsIn(hr healthRead, host string, at time.Time) (string, []string, bool) {
	if !c.streakSpansIn(hr, host, at) {
		return whyNoStreakSpans, nil, false
	}
	why, obs, ok := c.answeredSinceIn(hr, host, at)
	if !ok {
		return why, obs, false
	}
	if obs := restartedSinceObserversIn(hr, host, at); len(obs) > 0 {
		return whyRestarted(obs), obs, false
	}
	return "", nil, true
}

// restartedSinceObserversIn names the observers whose current failing run
// about host began more than fenceSkewMargin after at, sorted: each saw the
// host answer after at, and its next failed probe overwrote that verdict, so
// only the run's start (the row's last_seen) still shows it. host itself is
// not one. A row with no run start (an older build's, last_seen NULL) is not
// read: its start is only estimated, and the estimate drifts later the longer
// the run goes on (observerRunStart). Like answeredSinceObserversIn, any
// observer counts and a stale row counts too: this only ever refuses. An
// observer that restarted its own daemon, or began probing the host only
// after at, also starts a run after at and refuses, for an operator.
//
// An observer whose own process stopped across at (frozen, suspended) also
// starts its run after at, once it resumes. That run says nothing about the
// host, and is not counted when the observer recorded it as silent through
// its stall — it has seen no answer from the host since before the stall —
// and the stall began more than fenceSkewMargin before at (silentThroughStall).
// Without that, an observer frozen across a fence refused the recovery for
// good (lab 1 Drill2, 2026-10-16). Only this check excuses it: the run is
// still no unbroken watch (observerStreakSpans).
func restartedSinceObserversIn(hr healthRead, host string, at time.Time) []string {
	var out []string
	for _, r := range hr.rows {
		if r.String("observer") == host || r.String("status") == health.StatusUnready {
			continue
		}
		if r.Int("consecutive_failures") <= 0 {
			continue
		}
		upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok {
			continue
		}
		started, ok := corrosion.ParseUpdatedAt(r.String("last_seen"))
		if !ok || started.After(upd) {
			continue
		}
		if started.After(at.Add(fenceSkewMargin)) && !hr.silentThroughStall(r.String("observer"), host, r.String("last_seen"), at) {
			out = append(out, r.String("observer"))
		}
	}
	sort.Strings(out)
	return out
}

// silentThroughStall reports whether observer recorded its failing run about
// host that began at lastSeen as silent through a stall of its own that
// began more than fenceSkewMargin before at: it has not seen host answer
// since before at (health.SilentSince). The record and the verdict replicate
// separately; a verdict that arrives first refuses until the record does.
//
// silent_since is the observer's clock and at the fence leader's, compared
// with the margin given to the safe side as the run-start check above is: an
// observer whose clock runs more than fenceSkewMargin behind can be excused
// for a stall that began just after at, the same exposure that check has
// (the clock-skew alert fires first).
func (hr healthRead) silentThroughStall(observer, host, lastSeen string, at time.Time) bool {
	since, ok := health.SilentSince(hr.stalls.evidence(observer), host, lastSeen)
	return ok && since.Before(at.Add(-fenceSkewMargin))
}

// whyRestarted is the refusal reason naming the observers whose failing run
// began after the fence.
func whyRestarted(observers []string) string {
	if len(observers) == 1 {
		return "observer " + observers[0] + "'s failing run began after the fence (it saw the host answer, or its own daemon restarted)"
	}
	return "observers " + strings.Join(observers, ",") + "' failing runs began after the fence (each saw the host answer, or its own daemon restarted)"
}

// healthRead is one read of host_health about a host (readHostHealth), the
// rows every check of one decision about that host is made over.
type healthRead struct {
	rows []corrosion.Row
	err  error
	// stalls is each observer's observer_stalled evidence (silentThroughStall),
	// read only if some run needs it. Unreadable, it is empty: nothing is
	// excused.
	stalls *stallRead
}

// stallRead is the observer_stalled evidence of every observer, read once,
// on first use, for one healthRead.
type stallRead struct {
	once sync.Once
	load func() map[string]string
	m    map[string]string
}

// evidence is observer's own observer_stalled evidence ("" when none).
func (s *stallRead) evidence(observer string) string {
	if s == nil {
		return ""
	}
	s.once.Do(func() { s.m = s.load() })
	return s.m[observer]
}

// readHostHealth reads every observer's latest verdict about host: observer,
// status, consecutive_failures, last_seen and updated_at; and every
// observer's observer_stalled evidence.
func (c *Coordinator) readHostHealth(ctx context.Context, host string) healthRead {
	rows, err := c.db.Query(ctx,
		`SELECT observer, status, consecutive_failures, last_seen, updated_at FROM host_health WHERE target = ?`, host)
	hr := healthRead{rows: rows, err: err}
	if err != nil {
		return hr
	}
	hr.stalls = &stallRead{load: func() map[string]string { return c.readStallEvidence(ctx, host) }}
	return hr
}

// readStallEvidence reads every host's observer_stalled evidence, by host.
// Only a host's own row counts: it is the only writer of it, and another
// host's row about it must not excuse its run. A read error yields none.
func (c *Coordinator) readStallEvidence(ctx context.Context, host string) map[string]string {
	stalled, err := c.db.Query(ctx,
		`SELECT subject_id, reporter, evidence FROM health_conditions
		 WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND deleted_at IS NULL`,
		health.StallEvaluator, health.CondObserverStalled)
	if err != nil {
		slog.Warn("failover: observer_stalled read failed; no observer's stall excuses its failing run", "host", host, "error", err)
		return nil
	}
	out := make(map[string]string, len(stalled))
	for _, r := range stalled {
		if id := r.String("subject_id"); r.String("reporter") == id {
			out[id] = r.String("evidence")
		}
	}
	return out
}

// answeredSinceObserversIn names the observers whose latest verdict about
// host, healthy or unready, is newer than at less fenceSkewMargin, sorted.
// host itself is not one.
func answeredSinceObserversIn(hr healthRead, host string, at time.Time) []string {
	var out []string
	for _, r := range hr.rows {
		if r.String("observer") == host {
			continue
		}
		if r.Int("consecutive_failures") != 0 && r.String("status") != health.StatusUnready {
			continue
		}
		if upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && upd.After(at.Add(-fenceSkewMargin)) {
			out = append(out, r.String("observer"))
		}
	}
	sort.Strings(out)
	return out
}

// whyAnswered is the refusal reason naming the observers that saw the host
// answer since the fence.
func whyAnswered(observers []string) string {
	if len(observers) == 1 {
		return "observer " + observers[0] + " saw the host answer after the fence"
	}
	return "observers " + strings.Join(observers, ",") + " saw the host answer after the fence"
}

// whyNoStreakSpans is fenceStillStands' refusal reason when no observer's
// failing run spans the fence.
const whyNoStreakSpans = "no observer has watched the host stay down since the fence"

// whyHealthUnreadable is the refusal reason when host_health cannot be read.
const whyHealthUnreadable = "host_health unreadable"

// answeredSince is fenceStillStands' second half: it reports false, and why,
// when some observer's latest verdict about host — healthy or unready — is
// newer than `at` (less fenceSkewMargin). It fails closed on a read error.
//
// Any observer counts, a non-voter included, and a verdict dated in the
// future is not discarded the way the fence-candidate count discards one.
// Both are deliberate and safe, because this check only ever REFUSES: a
// non-voter that saw the host answer is evidence it is up, and an observer
// whose clock runs ahead can delay a resume or a retry by at most its skew,
// never cause one.
func (c *Coordinator) answeredSince(ctx context.Context, host string, at time.Time) (string, bool) {
	why, _, ok := c.answeredSinceIn(c.readHostHealth(ctx, host), host, at)
	return why, ok
}

// answeredSinceIn is answeredSince over host_health rows already read, also
// returning the observers it names.
func (c *Coordinator) answeredSinceIn(hr healthRead, host string, at time.Time) (string, []string, bool) {
	if hr.err != nil {
		slog.Warn("failover: host_health read for a fence resume failed", "host", host, "error", hr.err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return whyHealthUnreadable, nil, false
	}
	if obs := answeredSinceObserversIn(hr, host, at); len(obs) > 0 {
		return whyAnswered(obs), obs, false
	}
	return "", nil, true
}

// refence fences h again before resuming its recovery from rec, an aged or
// doubted VERIFIED fence (resumeActionFor). It reports whether it acted;
// false means it deferred, and nothing was decided.
//
// It is an ordinary fence — failover, with its lease floor, its record and its
// recovery — run with the recorded method rather than the host's current
// strategy, so the fresh fence proves what the old one did. On success the
// recovery proceeds on, and binds shared-disk transfers to, the FRESH fence.
// On failure nothing is recovered: the failed attempt is now the newest on
// record, so recordedFence no longer offers the old fence and the host is not
// re-fenced every cycle, only on the failed-fence retry backoff
// (fenceRetryDue). Until a fence succeeds the host stays recorded 'offline'
// by the failed fence, with `lv host fence-confirm` resuming it through the
// confirmation path, and is counted as error_class=refence_failed.
func (c *Coordinator) refence(ctx context.Context, h *corrosion.HostRecord, rec fenceRecord, observers int) bool {
	// A re-fence is a new judgement, unlike a resume from the record, so it is
	// held back while this node is in its stall grace, like any fence.
	if c.LocalStall != nil && c.LocalStall() {
		slog.Warn("failover: deferring the re-fence of a host with an aged verified fence; this node was itself not running moments ago",
			"host", h.Name, "fence_id", rec.ID, "grace", health.StallGrace)
		c.mAttempt(PhaseSkip, ResultSkipped, ErrLocalStall)
		return false
	}
	slog.Warn("failover: re-fencing a host before resuming from a verified fence that is aged or in doubt",
		"host", h.Name, "fence_id", rec.ID, "method", rec.Method, "fenced_at", rec.TS, "observers", observers)
	again := *h
	again.FenceStrategy = rec.Method
	fr, fenced := c.failover(ctx, &again)
	if fenced && fr.Success {
		// Visibility only: an operator who finds the host powered off again
		// learns that the coordinator did it, and why — durably in the audit
		// log (any node's `lv events`, and the audit export), and live on
		// this leader's event stream.
		detail := fmt.Sprintf(
			"method=%s renews fence %s (%s at %s), which was aged or in doubt; recovering on the fresh fence",
			fr.Method, rec.ID, rec.Method, rec.TS)
		c.audit(ctx, "host.refence", h.Name, detail, "ok")
		c.publish("host.refenced", h.Name, detail)
	}
	if fenced && !fr.Success {
		slog.Error("failover: the re-fence failed, NOT resuming the recovery on the older fence",
			"host", h.Name, "fence_id", rec.ID, "method", fr.Method, "detail", fr.Detail,
			"hint", "confirm "+h.Name+" is powered off, then run 'lv host fence-confirm "+h.Name+"'; the recovery resumes from it")
		c.mAttempt(PhaseRecovery, ResultRefused, ErrRefenceFailed)
		c.noteRefenceFailed(ctx, h.Name, rec, fr)
	}
	return true
}

// noteResumeDeclined logs, once per host and fence, that a recorded fence was
// found and is no longer authority: the one line that explains why a 'fenced'
// host's workloads are staying where they are.
func (c *Coordinator) noteResumeDeclined(host string, rec fenceRecord, why string) {
	if c.resumeDeclined == nil {
		c.resumeDeclined = map[string]string{}
	}
	if c.resumeDeclined[host] == rec.ID {
		return
	}
	c.resumeDeclined[host] = rec.ID
	c.noteHold(host, "the recorded fence "+rec.ID+" no longer stands: "+why)
	slog.Warn("failover: the recorded fence of this host no longer stands, NOT resuming its recovery",
		"host", host, "fence_id", rec.ID, "method", rec.Method, "fenced_at", rec.TS, "reason", why,
		"hint", "if the host is down, 'lv host undrain "+host+"' lets the coordinator fence it afresh for this outage")
}

// newestFenceAttempt returns the newest fence that RAN against host (a
// fencing_log row with result "fenced" or "partial", of any age) and its time,
// or ok=false when none exists. Operator confirmations are not attempts.
// Timestamps are compared in Go on RFC3339, for fenceWithinWindow's reason.
func (c *Coordinator) newestFenceAttempt(ctx context.Context, host string) (fenceRecord, time.Time, bool) {
	rec, at, ok, err := c.readNewestFenceAttempt(ctx, host)
	if err != nil {
		slog.Warn("failover: fencing_log read for a fence resume failed", "host", host, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return fenceRecord{}, time.Time{}, false
	}
	return rec, at, ok
}

// readNewestFenceAttempt is newestFenceAttempt with the read error returned,
// for a caller that must fail closed on it rather than read "no fence".
func (c *Coordinator) readNewestFenceAttempt(ctx context.Context, host string) (fenceRecord, time.Time, bool, error) {
	rows, err := c.db.Query(ctx,
		`SELECT id, method, result, detail, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return fenceRecord{}, time.Time{}, false, err
	}
	var best time.Time
	var out fenceRecord
	found := false
	for _, r := range rows {
		if res := r.String("result"); res != "fenced" && res != "partial" {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		// fencing_log timestamps carry second precision, so two attempts can
		// share one. A failed attempt then counts as the newer: it is the
		// answer that offers nothing to resume from.
		if !found || ts.After(best) || (ts.Equal(best) && r.String("result") == "partial") {
			best, found = ts, true
			out = fenceRecord{
				ID: r.String("id"), Method: r.String("method"), Result: r.String("result"),
				Detail: r.String("detail"), TS: r.String("timestamp"),
			}
		}
	}
	return out, best, found, nil
}

// confirmationResume returns the operator confirmation that authorises
// resuming a refused recovery of h, or ok=false.
//
// A recovery refused for want of an operator confirmation — a manual fence, a
// best-effort fence under the safe-fence policy, a host carrying
// LabelFenceRequiresConfirmation — was never revisited. recoverFenced marks the
// host handled for the outage before its gates run, so a `lv host fence-confirm`
// written afterwards landed on a host nothing would look at again, in the same
// process or after a restart. The documented manual flow did not work.
//
// Authority to resume is three independent facts, not the confirmation alone:
//
//   - the cluster ITSELF attempted a fence of h (a fencing_log row with result
//     "fenced" or "partial" — written only by a fence that ran);
//   - an operator confirmation ("manual-confirmed") at or after the NEWEST such
//     attempt, so it attests to this outage and not an earlier one;
//   - h is still quorum-down, which the caller supplies by construction: this
//     runs only for fence candidates, i.e. hosts a fresh quorum observes failing;
//   - nobody has seen h answer since the confirmation (confirmationStands). A
//     quorum observing h down now does not show that: one observer whose path
//     to h never healed keeps its unbroken run across two outages while the
//     others saw h come back, so a confirmation of the first outage would
//     otherwise be spent in the second by a coordinator that has not spent it
//     (a new lease holder, a restart). Such a confirmation is refused with
//     the host's hold naming the remedy: confirm again.
//
// That answers the objection that withdrew the earlier stranded-workload sweep
// (397c39f4): fence-confirm has no precondition and runs no fence, so on its
// own a mistyped hostname would forge the proof. Here a mistype can only reach a
// host the cluster already fenced and still observes down — the same authority
// the manual path has always accepted at fence time via manualFenceConfirmed.
//
// Timestamps are compared in Go on RFC3339, for fenceWithinWindow's reason.
// ">=" rather than ">", because both rows carry second precision and a prompt
// operator can land in the fence's own second.
func (c *Coordinator) confirmationResume(ctx context.Context, h *corrosion.HostRecord) (fenceRecord, bool) {
	if h == nil || (h.State != "offline" && h.State != "fenced") {
		return fenceRecord{}, false
	}
	confirm, confirmedAt, attempt, ok := c.confirmationAndAttempt(ctx, h.Name)
	if !ok || attempt.IsZero() || confirmedAt.IsZero() || confirmedAt.Before(attempt) {
		return fenceRecord{}, false
	}
	if !c.attemptIsThisOutage(ctx, h.Name, attempt) {
		// A confirmation made during this outage is not refused: it puts the
		// host back on the fence path (confirmationFencesAfresh), and the fresh
		// fence is the attempt this outage lacks. Only a confirmation that is
		// itself older than the outage is news here.
		if !c.observerStreakSpans(ctx, h.Name, confirmedAt) {
			slog.Warn("failover: the newest fence attempt and the confirmation both predate this outage, NOT resuming on the confirmation",
				"host", h.Name, "attempt", attempt.Format(time.RFC3339), "confirmation", confirm.ID,
				"hint", "confirm "+h.Name+" is powered off, then run 'lv host fence-confirm "+h.Name+"' again: a confirmation made during this outage lets the coordinator fence it afresh")
			c.mAttempt(PhaseRecovery, ResultRefused, ErrManualUnconfirmed)
		}
		return fenceRecord{}, false
	}
	if c.confirmResumed[h.Name] == confirm.ID {
		// Spent by this coordinator: resumeFromConfirmation does not act on it
		// again, so it is not judged again either.
		return confirm, true
	}
	if why, stands := c.confirmationStands(ctx, h.Name, confirmedAt); !stands {
		c.noteConfirmationStale(h.Name, confirm, why)
		return fenceRecord{}, false
	}
	return confirm, true
}

// confirmationStands reports whether an operator confirmation of host at
// confirmedAt is still authority over the outage host is in now, and when it
// is not, why. It is fenceStillStandsIn with the confirmation as the fence:
// some observer has watched the host fail without a break since before it,
// and nobody has seen it answer since — no observer's latest verdict is an
// answer newer than it, and no observer's failing run began after it. Nor
// may this node have probed the host healthy since it (LastContact): the
// confirmation's time is mapped onto this node's monotonic clock through its
// wall clock, and counts from fenceSkewMargin before it, as an answered
// verdict does. A host_health read error does not stand, with no reason: the
// caller refuses this cycle without calling the confirmation stale.
func (c *Coordinator) confirmationStands(ctx context.Context, host string, confirmedAt time.Time) (string, bool) {
	hr := c.readHostHealth(ctx, host)
	if hr.err != nil {
		slog.Warn("failover: host_health read for a confirmation resume failed", "host", host, "error", hr.err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return "", false
	}
	if why, _, ok := c.fenceStillStandsIn(hr, host, confirmedAt); !ok {
		return why, false
	}
	since := c.mono().Add(-c.now().Sub(confirmedAt)).Add(-fenceSkewMargin)
	if c.contactedSince(host, since) {
		return "this node has probed the host healthy since the confirmation", false
	}
	return "", true
}

// noteConfirmationStale records that the operator confirmation confirm of
// host no longer stands (confirmationStands): the host's hold names it and
// the remedy every cycle, after whatever else holds it (holdBase), and it is
// logged and counted once per confirmation. It returns the note.
func (c *Coordinator) noteConfirmationStale(host string, confirm fenceRecord, why string) string {
	if why == "" {
		return ""
	}
	hint := "confirm " + host + " is powered off, then run 'lv host fence-confirm " + host + "' again"
	note := "the operator confirmation " + confirm.ID + " does not stand for this outage: " +
		strings.Replace(why, "the fence", "the confirmation", 1) + "; " + hint
	if c.holdReason == nil {
		c.holdReason = map[string]string{}
	}
	c.holdReason[host] = withStaleConfirmation(c.holdBase[host], note)
	if c.lastStale == nil {
		c.lastStale = map[string]string{}
	}
	c.lastStale[host] = note
	if c.confirmStale == nil {
		c.confirmStale = map[string]string{}
	}
	if c.confirmStale[host] == confirm.ID {
		return note
	}
	c.confirmStale[host] = confirm.ID
	slog.Warn("failover: the operator confirmation does not stand for this outage, NOT acting on it",
		"host", host, "confirmation", confirm.ID, "confirmed_at", confirm.TS, "reason", why, "hint", hint)
	c.mAttempt(PhaseRecovery, ResultRefused, ErrManualUnconfirmed)
	return note
}

// confirmationAndAttempt reads host's fencing_log for the newest operator
// confirmation ("manual-confirmed") and the time of the newest fence attempt (a
// row with result "fenced" or "partial", which only a fence that ran writes).
// Either is zero when there is none; ok is false on a read error.
func (c *Coordinator) confirmationAndAttempt(ctx context.Context, host string) (confirm fenceRecord, confirmedAt, attempt time.Time, ok bool) {
	rows, err := c.db.Query(ctx,
		`SELECT id, method, result, detail, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		slog.Warn("failover: fencing_log read for confirmation resume failed", "host", host, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return fenceRecord{}, time.Time{}, time.Time{}, false
	}
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		switch r.String("result") {
		case "fenced", "partial":
			if ts.After(attempt) {
				attempt = ts
			}
		case "manual-confirmed":
			if ts.After(confirmedAt) {
				confirmedAt = ts
				confirm = fenceRecord{
					ID: r.String("id"), Method: r.String("method"), Result: r.String("result"),
					Detail: r.String("detail"), TS: r.String("timestamp"),
				}
			}
		}
	}
	return confirm, confirmedAt, attempt, true
}

// confirmationFencesAfresh reports whether h, recorded terminal by an operator
// confirmation, is owed a fence of its own for the outage it is in now. When it
// is, the caller puts h back on the ordinary fence path.
//
// `lv host fence-confirm` records the host 'fenced' and runs nothing, and a
// terminal host is never a fence candidate. A confirmation written before the
// cluster fenced the host for this outage therefore left the host where nothing
// would ever fence it — and confirmationResume, rightly, will not resume on a
// confirmation alone. That is not a corner: it is the only order in which a
// forced voter reconfiguration can be done (docs/design/recovery-claims.md
// §4.6). The force demands a proof-grade fence of every lost host, and with a
// majority of voters gone no fence quorum can form to run one, so the operator
// confirms first; once the forced generation is adopted the survivors have a
// quorum again, and found nothing to fence (drill 6 on main-8d1e56dc).
//
// What such a confirmation authorises is the FENCE, not the recovery. The
// coordinator fences the host itself, as it would had the host still been
// active, and the recovery follows from that attempt under every gate the
// ordinary fence path applies: the strategy's split-brain guard, the safe-fence
// policy, LabelFenceRequiresConfirmation, the partition-pause wait. Where one
// of those demands an operator confirmation, manualFenceConfirmed reads the
// same recent one; an older one leaves the fresh fence refused and the host
// 'offline', and a new confirmation resumes it (confirmationResume).
//
// It holds when all of:
//
//   - h is 'fenced' or 'offline' (never 'maintenance': operator intent), and
//     still quorum-down, which the caller supplies by construction;
//   - an operator confirmation exists, and no fence attempt is at or after it:
//     a fence the cluster ran after the operator spoke is this outage's fence,
//     and confirmationResume owns it;
//   - no earlier attempt belongs to this outage (attemptIsThisOutage), which
//     would make this a resume rather than a fence;
//   - the confirmation itself belongs to this outage: some observer has watched
//     h fail without a break since before it, and nobody has seen h answer
//     since it (confirmationStands). A confirmation of an outage h has since
//     recovered from authorises nothing, exactly as before, and is refused
//     with the host's hold naming the remedy: confirm again. One observer's
//     unbroken run is not enough on its own: the manual fence this starts
//     accepts the same confirmation (manualFenceConfirmed).
//
// A mistyped hostname reaches only a host a quorum observes down, without a
// break, since before the confirmation was typed — and that host is then fenced
// as any quorum-down host would be. Nothing moves on the confirmation alone.
func (c *Coordinator) confirmationFencesAfresh(ctx context.Context, h *corrosion.HostRecord) bool {
	if h == nil || (h.State != "offline" && h.State != "fenced") {
		return false
	}
	confirm, confirmedAt, attempt, ok := c.confirmationAndAttempt(ctx, h.Name)
	if !ok || confirmedAt.IsZero() {
		return false
	}
	if !attempt.IsZero() && (!attempt.Before(confirmedAt) || c.attemptIsThisOutage(ctx, h.Name, attempt)) {
		return false
	}
	if why, stands := c.confirmationStands(ctx, h.Name, confirmedAt); !stands {
		c.noteConfirmationStale(h.Name, confirm, why)
		return false
	}
	slog.Warn("failover: an operator confirmed this host off during the outage in progress, and no fence has run for it; fencing it afresh",
		"host", h.Name, "confirmation", confirm.ID, "confirmed_at", confirm.TS)
	c.mAttempt(PhaseRecovery, ResultOK, ErrConfirmationFence)
	if c.afreshConfirm == nil {
		c.afreshConfirm = map[string]string{}
	}
	c.afreshConfirm[h.Name] = confirm.ID
	return true
}

// attemptIsThisOutage reports whether a fence attempt at attempt belongs to the
// outage h is in NOW, rather than to an earlier one.
//
// Ordering the confirmation against the attempt only says the operator spoke
// after the cluster fenced. It says nothing about whether that fence is about
// the host as it stands: a host fenced two days ago, back in service since,
// and terminal again without a fence of its own (an operator's fence-confirm
// writes 'fenced' and runs nothing) would otherwise have its workloads moved on
// the strength of a power-off that the host has long since recovered from.
//
// Either of two things binds the attempt to this outage:
//
//   - it is within recentFenceWindow — the window every other fence-recency
//     question in the coordinator uses. That alone does NOT show the host
//     stayed down: it can answer, fail again and lose the record of its return
//     within five minutes. A resume on a confirmation therefore also demands
//     that nobody has seen the host answer since the confirmation
//     (confirmationStands), whatever the attempt's age; a resume with no
//     confirmation demands the run below whatever the fence's age
//     (fenceStillStands); or
//   - some observer has watched the host fail WITHOUT A BREAK since before the
//     attempt (observerStreakSpans). This is what honours an operator who took
//     twenty minutes to reach the rack.
//
// Both fail towards refusing. A streak is reset by an observer restart or a
// stall, so across a cluster-wide restart a genuine confirmation can be
// refused; the recovery then needs a fresh fence, which `lv host undrain`
// followed by the ordinary fence path provides. An 'unready' row is an answer,
// not silence, and never counts as a streak.
func (c *Coordinator) attemptIsThisOutage(ctx context.Context, host string, attempt time.Time) bool {
	if attempt.After(c.now().Add(-recentFenceWindow)) {
		return true
	}
	return c.observerStreakSpans(ctx, host, attempt)
}

// observerStreakSpans reports whether some observer has watched host fail
// without a break since before `at`. Its fresh row's consecutive_failures is
// that unbroken run, and the run's start is the row's last_seen, which a
// failing verdict carries as the time of the run's first failed probe. The
// start must be at least fenceSkewMargin before `at` — the two are read off
// different hosts' clocks — and an 'unready' row is an answer, not silence, so
// it never counts as a run.
//
// A row from an older build carries no start (last_seen NULL). Its run is then
// taken to span (N-1) × health.ProbeInterval back from updated_at, a lower
// bound on its length that never counts an earlier outage's fence or
// confirmation as this one's. It is only a bound: a probe of a powered-off host
// runs out its dial timeout, so on the kvm003 lab a run advanced one count
// every ~2.85 s and the estimated start drifted later the longer the outage
// went on, until a fence or confirmation made minutes into it read as older
// than the outage (drills 3 and 6 on main-e004c250). Erring the other way has
// no bound to offer — a host refusing connections fails each probe at once —
// so the older build's rows keep the estimate, and the first observer on this
// build is enough: one spanning row answers the question.
func (c *Coordinator) observerStreakSpans(ctx context.Context, host string, at time.Time) bool {
	return c.streakSpansIn(c.readHostHealth(ctx, host), host, at)
}

// streakSpansIn is observerStreakSpans over host_health rows already read.
func (c *Coordinator) streakSpansIn(hr healthRead, host string, at time.Time) bool {
	if hr.err != nil {
		slog.Warn("failover: host_health read for a fence's outage failed", "host", host, "error", hr.err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return false
	}
	freshCutoff := c.now().Add(-healthFreshness)
	for _, r := range hr.rows {
		if r.String("status") == health.StatusUnready {
			continue
		}
		n := r.Int("consecutive_failures")
		if n < offlineThreshold {
			continue
		}
		upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || !upd.After(freshCutoff) {
			continue
		}
		if !observerRunStart(n, r.String("last_seen"), upd).After(at.Add(-fenceSkewMargin)) {
			return true
		}
	}
	return false
}

// observerRunStart is when an observer's unbroken run of n failed probes
// against its target began, from that host_health row: its last_seen, which a
// failing verdict carries as the run's first failed probe, or, on a row from an
// older build with none, (n-1) × health.ProbeInterval back from updated_at —
// a lower bound on the run's length (see observerStreakSpans for why). The
// fence path and the one-way detector both read a run's start through here, so
// they cannot disagree on when one began.
func observerRunStart(n int, lastSeen string, updatedAt time.Time) time.Time {
	if started, ok := corrosion.ParseUpdatedAt(lastSeen); ok && !started.After(updatedAt) {
		return started
	}
	return updatedAt.Add(-time.Duration(n-1) * health.ProbeInterval)
}

// resumeFromConfirmation resumes the recovery of target if an operator has
// confirmed it off since a refusal (confirmationResume), at most once per
// confirmation per process. Reports whether it did.
//
// Only the failover leader reaches it. Both call sites are inside run()'s
// candidate loop, after acquireLease and the per-candidate holdLease, which is
// the same lease check the fence path makes. That is also why the once-only map
// is enough: a non-leader never reaches this function, so it never spends a
// confirmation, and a coordinator that takes over the lease has not spent it
// either, so it still resumes. TestConfirmationResume_OnlyTheLeaderResumes and
// TestConfirmationResume_TheNextLeaderResumesAfterHandover pin both halves.
// The lease is best-effort (docs/operating-model.md, "Leader-gated recovery"). If
// two coordinators each hold it in their own replica, both get here, exactly as
// both would fence.
//
// It resumes at recoverWorkloads, past recoverFenced's gates: those gates exist
// to demand exactly the confirmation confirmationResume has just established,
// and manualFenceConfirmed only looks back recentFenceWindow — five minutes, less
// time than it takes to walk to a rack — so re-entering them would refuse a
// genuine confirmation for being slow. recoverWorkloads keeps its own late
// gates, and binds shared-disk transfers to a proof-grade fence, for which a
// fresh confirmation qualifies.
func (c *Coordinator) resumeFromConfirmation(ctx context.Context, target string) bool {
	h, err := corrosion.GetHost(ctx, c.db, target)
	if err != nil || h == nil {
		return false
	}
	rec, ok := c.confirmationResume(ctx, h)
	if !ok || c.confirmResumed[target] == rec.ID {
		return false
	}
	// Decide-site gate, as at every other point that asserts runtime ownership:
	// the lease alone can be held on both sides of a partition.
	if c.gateEnforced(ctx) {
		if g := c.decideGate(ctx, target); !g.OK {
			slog.Warn("failover: decision gate refused a confirmation resume", "host", target, "reason", g.Reason)
			c.noteGateRefused(ActionReschedule, g.Reason)
			c.mAttempt(PhaseRecovery, ResultRefused, ErrNoQuorum)
			return false
		}
	}
	slog.Info("failover: operator confirmed a host whose recovery was refused, resuming",
		"host", target, "confirmation", rec.ID, "confirmed_at", rec.TS)
	c.mAttempt(PhaseRecovery, ResultOK, ErrConfirmationResumed)
	c.markHandled(ctx, target)
	c.confirmResumed[target] = rec.ID
	c.unlimitRecovery(target) // an operator confirmed the host off
	delete(c.pauseWaits, target)
	// The recovery rests on the recorded fence as well as the confirmation:
	// a claim it has refused is retried under that fence (retryClaims), not
	// mistaken for one owed to an older fence.
	if rec, _, ok := c.recordedFence(ctx, h); ok {
		c.noteFencedOn(target, rec.ID)
	}
	// The operator's word is that the host is off now: a claim retry this
	// recovery leaves owed acts on this moment (claimRetryOutageOver).
	c.noteRecoveryAt(target, c.now(), c.mono())
	delete(c.restsOnTrust, target) // it rests on the operator's word now
	c.resolveUnproven(ctx, target, "an operator confirmed the host off")
	c.recoverWorkloads(ctx, h)
	return true
}

// fenceRecord is one fencing_log row read back: the fence that physically
// happened, as a coordinator that did not perform it sees it.
type fenceRecord struct {
	ID     string
	Method string
	Result string
	Detail string
	TS     string
}

// newestProofGradeFence returns the newest PROOF-GRADE fence of host within
// recentFenceWindow, or ok=false when none exists (a best-effort / SSH fence, or
// no fence yet). The recency filter is Go-side on RFC3339, mirroring
// fenceWithinWindow. An IPMI fence finds the row this cycle just inserted; a
// manual fence finds the operator's "manual-confirmed" row (the fence-time
// "manual"/"partial" row is not proof-grade). See newestProofGradeFenceWhy.
func (c *Coordinator) newestProofGradeFence(ctx context.Context, host string) (fenceRecord, bool) {
	rec, ok, _, _ := c.newestProofGradeFenceWhy(ctx, host)
	return rec, ok
}

// newestProofGradeFenceWhy is newestProofGradeFence, and when a proof-grade
// row exists but proves nothing now, why. The life cut (fenceRowCutoff) does
// not apply once the host is recorded down, which it is by the time a
// recovery binds a transfer, so two more rules keep an earlier outage's row
// from binding:
//
//   - a fence attempt that is not proof-grade, newer than the row, means the
//     host was failing again since — running in between, as
//     corrosion.FenceRecordProvesOff reads it — and proves nothing about it
//     now. A "manual" attempt is not one: it is the cluster asking for a
//     confirmation, and a confirmation made before it (the afresh path) is
//     judged by the next rule. Nor is the fence this coordinator ran on the
//     confirmation it fenced the host afresh on (afreshConfirm, and the row
//     it noted in fencedOn): a lenient best-effort fence of a host already
//     off records success after the confirmation, and the confirmation is
//     still judged by the next rule. Any other attempt is not exempt. A
//     row in the same second as the proof-grade one does not outrank it.
//   - an operator confirmation binds only while it stands for the outage the
//     host is in now (confirmationStands): nobody, this node's probe
//     included, has seen the host answer since it. An IPMI or Redfish row in
//     the same second is preferred: it needs no such judgement.
//
// retry reports a read error: nothing was judged, and the caller retries
// rather than spending the transfer.
func (c *Coordinator) newestProofGradeFenceWhy(ctx context.Context, host string) (rec fenceRecord, ok bool, why string, retry bool) {
	rows, err := c.db.Query(ctx,
		`SELECT id, method, result, detail, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		slog.Warn("failover: fencing_log read for fence_epoch failed", "host", host, "error", err)
		return fenceRecord{}, false, "the fence log could not be read", true
	}
	cutoff := c.now().Add(-recentFenceWindow)
	life, lifeKnown := c.fenceRowCutoff(ctx, host)
	var best time.Time
	type attempt struct {
		id string
		ts time.Time
	}
	var unverified []attempt
	var out fenceRecord
	found := false
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		method, result := r.String("method"), r.String("result")
		if !corrosion.FenceProofGrade(method, result) {
			if (result == "fenced" || result == "partial") && method != "manual" {
				unverified = append(unverified, attempt{id: r.String("id"), ts: ts})
			}
			continue
		}
		if !ts.After(cutoff) || (lifeKnown && ts.Before(life)) {
			continue
		}
		preferred := found && ts.Equal(best) && out.Result == "manual-confirmed" && result != "manual-confirmed"
		if !found || ts.After(best) || preferred {
			best, found = ts, true
			out = fenceRecord{
				ID:     r.String("id"),
				Method: method,
				Result: result,
				Detail: r.String("detail"),
				TS:     r.String("timestamp"),
			}
		}
	}
	if !found {
		return fenceRecord{}, false, "", false
	}
	// The fence this coordinator ran on the confirmation it fenced the host
	// afresh on is the one attempt exempt: any other writer's newer attempt
	// (an operator's `lv host fence`, say) still refuses.
	ownAfresh := out.Result == "manual-confirmed" && c.afreshConfirm[host] == out.ID
	var newestUnverified time.Time
	for _, a := range unverified {
		if !a.ts.After(best) || !a.ts.After(newestUnverified) {
			continue
		}
		if ownAfresh && a.id != "" && a.id == c.fencedOn[host] {
			continue
		}
		newestUnverified = a.ts
	}
	if newestUnverified.After(best) {
		return fenceRecord{}, false, "a fence attempt that is not proof-grade (" +
			newestUnverified.UTC().Format(time.RFC3339) + ") is newer than the proof-grade fence " + out.ID, false
	}
	if out.Result == "manual-confirmed" {
		if why, stands := c.confirmationStands(ctx, host, best); !stands {
			if why == "" {
				return fenceRecord{}, false, "whether the operator confirmation " + out.ID +
					" still stands could not be read", true
			}
			return fenceRecord{}, false, "the operator confirmation " + out.ID + " does not stand for this outage: " +
				strings.Replace(why, "the fence", "the confirmation", 1), false
		}
	}
	return out, true, "", false
}

// proofGradeFenceRef returns the fence_epoch binding for the newest proof-grade
// fence of host, or "" when there is none. A shared-disk cross-host transfer
// executor re-reads FenceID from fencing_log and re-verifies it (never a stale
// hosts.state).
func (c *Coordinator) proofGradeFenceRef(ctx context.Context, host string) string {
	ref, _, _ := c.proofGradeFenceRefWhy(ctx, host)
	return ref
}

// proofGradeFenceRefWhy is proofGradeFenceRef, with why a proof-grade row on
// record does not bind (newestProofGradeFenceWhy) when ref is "", and whether
// that is a read error to retry.
func (c *Coordinator) proofGradeFenceRefWhy(ctx context.Context, host string) (ref, why string, retry bool) {
	rec, ok, why, retry := c.newestProofGradeFenceWhy(ctx, host)
	if !ok {
		return "", why, retry
	}
	return corrosion.FenceEpochRef{Host: host, FenceID: rec.ID, TS: rec.TS}.String(), "", false
}

// sharedDiskUnproven notes, on host's hold, why a shared-disk VM was not
// moved off it: no proof-grade fence binds (why, from proofGradeFenceRefWhy).
// A read error owes a retry of the recovery on the same authority
// (retryClaims), and the hold says so; anything else names the remedy. It
// returns the text, for a stopped VM's skip detail.
func (c *Coordinator) sharedDiskUnproven(host, why string, retry bool) string {
	var msg string
	if retry {
		c.retryClaimsFor(host)
		msg = "a shared-disk VM transfer is waiting: " + why + "; retrying next cycle"
	} else {
		if why == "" {
			why = "no proof-grade fence of the host is on record"
		}
		msg = "a shared-disk VM transfer needs a proof-grade fence of the host, and " + why +
			"; confirm " + host + " is powered off, then run 'lv host fence-confirm " + host + "', or set an IPMI or Redfish fence strategy"
	}
	c.noteHold(host, msg)
	return msg
}

// autoPromoteEnabled reports whether vmName has a replication schedule with
// auto_promote set. Best-effort: a query error returns false (fall back to a
// bare reschedule rather than risk an unwanted promotion).
func (c *Coordinator) autoPromoteEnabled(ctx context.Context, vmName string) bool {
	rows, err := corrosion.ListBackupSchedules(ctx, c.db)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if r.Type == "replication" && r.AutoPromote && r.VMName == vmName {
			return true
		}
	}
	return false
}

// countsAsVote reports whether a host_health row from observer about target
// may count toward a quorum over voters: the observer must be a voter, and a
// host never votes on itself.
func countsAsVote(voters map[string]bool, observer, target string) bool {
	return observer != target && voters[observer]
}

// failover fences the host and reschedules its VMs. It returns the fence's
// result, and false when it stopped before fencing (the lease was too short).
func (c *Coordinator) failover(ctx context.Context, h *corrosion.HostRecord) (fence.Result, bool) {
	// Named span for the fence+reschedule sequence; the fence RPC and the
	// per-VM peer relocations hang off it, so an auto-failover is one connected
	// trace across the coordinator and the target hosts. No-op when tracing off.
	ctx, span := obs.Span(ctx, "failover.host")
	span.SetAttribute("host.name", h.Name)
	defer span.End()

	// NOTE: c.fenced and c.fenceRelocated are deliberately NOT seeded here. Both
	// are claims about a recovery THIS coordinator is driving, and every return
	// below abandons that drive — a lease too short to fence, or a lease lost
	// while fencing. Seeding them up front left a coordinator that had abdicated
	// still asserting "I handled this host" and "nothing moved off it": the
	// first suppressed its own resume (the cached-state skip in run runs before
	// recordedFence can look), and the second let it auto-undrain a host whose
	// VMs the SUCCESSOR had since relocated. They are seeded at the point of
	// commitment instead, just before recoverFenced.

	// Re-validate the lease immediately before the destructive fence call, and
	// require enough of it left to FINISH that call. Checking only that the
	// lease is currently held is not sufficient: a fence run (IPMI verify alone
	// is up to 15 s) can outlast the remaining TTL, and once the row expires a
	// second coordinator can take the lease and start fencing the same host
	// while this call is still in flight.
	// Whether fence_state_v1 has latched decides the state this fence records
	// (fenceRecordState). It is read HERE, before the fence and before the
	// lease floor is measured, never between the fence and its record: until
	// the token latches, Enforced runs a live Ping sweep (up to
	// capActivationTimeout), and a leader that died or lost its lease in that
	// gap lost the record of a fence that had happened.
	latched := c.fenceStateLatched(ctx)
	// Whether an assumed best-effort fence relies on the host's partition
	// pause is decided here too, for the same reason (reliesOnPauseIfAssumed).
	pauseRelied := c.reliesOnPauseIfAssumed(ctx, h)
	// Whether the host trusts a confirmed SSH power-off is decided here, once,
	// and recorded with the fence (fence.WithTrust): every later judgement of
	// this fence, a successor's resume included, reads that decision, never
	// the label as it reads then. Trust is never retroactive.
	trusted := trustsSSHPoweroff(h)

	leaseLeft, ok := c.holdLeaseAtLeast(ctx, minFenceLease)
	if !ok {
		slog.Warn("failover: lease lost or too short to fence, aborting",
			"host", h.Name, "required", minFenceLease)
		c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
		return fence.Result{}, false
	}

	// Bound the fence by the lease that authorises it. The deadline is derived
	// from the time this node actually holds, less a margin so the call returns
	// while it is still the leader — not from a constant that could quietly
	// exceed the lease if either value is ever retuned.
	fenceCtx, cancelFence := context.WithTimeout(ctx, leaseLeft-leaseFenceMargin)
	defer cancelFence()

	// Immediately before the fence: HA may have been disarmed since this
	// host was selected.
	if c.haHold(ctx, h.Name, haSiteFence) {
		return fence.Result{}, false
	}

	// Step 1: Fence the host.
	if c.lastFenceAt == nil {
		c.lastFenceAt = map[string]time.Time{}
	}
	c.lastFenceAt[h.Name] = c.now()
	fr := c.fencer(fenceCtx, fence.HostConfig{
		Name:          h.Name,
		Address:       h.Address,
		SSHUser:       h.SSHUser,
		SSHPort:       h.SSHPort,
		FenceStrategy: h.FenceStrategy,
		IPMIAddress:   h.IPMIAddress,
		IPMIUser:      h.IPMIUser,
		IPMIPass:      h.IPMIPass,
		Redfish:       h.Redfish,
		WatchdogDev:   h.WatchdogDev,
		// A retired credential is reported, never sent as an empty password.
		IPMICredentialRetired: h.IPMIPassRetired,
		SSH:                   c.fenceSSHPath(fenceCtx, h.Name),
	})
	// A best-effort fence that did not reach the host is recorded as
	// self-pause when this coordinator relies on the host's partition pause
	// (docs/design/partition-pause.md §4.2): same row shape, assurance
	// self_paused, and recoverFenced then waits out the pause.
	fr = notAFenceUnlessPaused(asSelfPause(fr, pauseRelied, trusted))
	if fr.Method == "ssh" && fr.Success {
		fr.Detail = fence.WithTrust(fr.Detail, trusted, ranPath(fr))
	}

	logResult := fr.LogResult()
	if !fr.Success {
		c.mAttempt(PhaseFence, ResultPartial, ErrFenceFailed)
	} else {
		c.mAttempt(PhaseFence, ResultSuccess, errClassNone)
	}

	// Record the fence, and, for a fence that SUCCEEDED, the state it
	// establishes, in ONE replicated entry (corrosion.RecordFenceWithState):
	// 'fenced' for a fence that PROVED the host off, 'offline' for one that
	// succeeded without proving it (fenceRecordState). Either is a fact about
	// the host, the same class of thing as the fencing_log row: it is true no
	// matter who holds the lease a moment later. Both are written BEFORE the
	// leadership re-check so a handoff mid-fence still leaves the cluster
	// describing what physically happened, and so the next leader can pick the
	// recovery up from it (see run's resume path). They are written TOGETHER
	// because a successor holding the row without the state skipped the host
	// as recently fenced, and a leader that died between two pushes left it
	// that way. A FAILED fence establishes nothing about the host; the
	// "offline" it leaves is an inference, so recoverFenced writes that one,
	// behind the check, with the reschedule.
	//
	// Failure to log is a real problem — we are about to reschedule VMs based
	// on a fence that has no audit trail — but intentionally non-blocking: the
	// fence physically happened, and a lost audit row must not strand the VMs.
	rec := corrosion.FenceLogRecord{
		ID:       randid.New(),
		HostName: h.Name,
		Method:   fr.Method,
		Result:   logResult,
		Detail:   fr.Detail,
	}
	state := fenceRecordState(h, fr, latched)
	if state != "" {
		if err := corrosion.RecordFenceWithState(ctx, c.db, rec, state); err != nil {
			// Fall back to the two writes separately: each is worth more than
			// neither, and a successor waits for a state that arrives late.
			slog.Error("failover: write fence_log and host state together", "host", h.Name, "state", state, "error", err)
			c.writeFenceLog(ctx, rec)
			c.markHostState(ctx, h.Name, state)
		}
	} else {
		c.writeFenceLog(ctx, rec)
	}

	if c.OnFence != nil && c.fenceNotifies(h.Name, fr) {
		c.OnFence(h.Name, fr.Method, logResult, fr.Detail)
	}
	if fr.Success {
		// A fence that succeeded answers whatever held the recovery back;
		// recoverFenced records anything that holds it now.
		c.clearHold(h.Name)
	}

	// Say so, at the moment it matters, when the fence proves nothing. The row
	// above reads "fenced" either way; this is the line an on-call engineer
	// reading this node's journal during a failover will actually see.
	if a := corrosion.FenceAssuranceDetail(fr.Method, logResult, fr.Detail); a == corrosion.FenceRequested || a == corrosion.FenceAssumed {
		slog.Warn("failover: this fence was not verified — the host may still be running",
			"host", h.Name, "method", fr.Method, "assurance", a,
			"fix", "give "+h.Name+" an ipmi or redfish fence strategy to make its fences verifiable")
	}

	// The fence is recorded; confirm this node is still the leader before acting
	// on it. If the lease expired while the fence ran, another coordinator may
	// already be driving this host's recovery, and continuing would mean two
	// coordinators rescheduling the same VMs. Deliberately placed AFTER the
	// fence log, OnFence and the proof-grade state write: those record a
	// physical act that did happen and must survive regardless of who holds the
	// lease now. What stops here is everything that ASSERTS authority — the
	// placement and reschedule below, which the new leader resumes from the
	// record rather than repeating.
	if !c.holdLease(ctx) {
		slog.Warn("failover: lease lost during fence, leaving the recovery for the new leader to resume",
			"host", h.Name)
		c.mAttempt(PhaseFence, ResultRefused, ErrLeaseLost)
		return fr, true
	}

	// Committed: this coordinator fenced the host and is driving its recovery, so
	// it can say whether any VM moved. A fence that moves nothing (a spurious
	// fence of a host whose VMs all stayed put) is safe to auto-recover later;
	// one that relocated VMs must stay manual to avoid split-brain. Absent
	// entirely — the resuming-leader case — means "not mine to judge", which
	// recoverHosts reads as manual-undrain-only. See recoverHosts.
	// A retry or re-fence of a host this coordinator already recovered from
	// must not erase "VMs moved": only the first commit seeds it.
	if _, seen := c.fenceRelocated[h.Name]; !seen {
		c.fenceRelocated[h.Name] = false
	}
	c.noteFencedOn(h.Name, rec.ID)

	// recoverFenced sees the host as this fence recorded it, so it does not
	// write the same state a second time as a separate entry.
	recorded := *h
	if state != "" {
		recorded.State = state
	}
	c.recoverFenced(ctx, &recorded, fr, h.FenceStrategy, latched)
	return fr, true
}

// writeFenceLog records a fence's fencing_log row on its own, surfacing a
// write failure without aborting (see failover).
func (c *Coordinator) writeFenceLog(ctx context.Context, rec corrosion.FenceLogRecord) {
	if err := corrosion.InsertFenceLog(ctx, c.db, rec); err != nil {
		slog.Error("failover: write fence_log", "host", rec.HostName, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrFenceLogWrite)
	}
}

// fenceRecordState is the host state a fence fr of h records beside its
// fencing_log row: "fenced" when the host is recorded as known to be off,
// "offline" when the fence succeeded without proving that, and "" for a
// failed fence, which records nothing until recoverFenced infers 'offline'.
//
// 'fenced' is the cluster's statement that the host is OFF, and once
// fence_state_v1 has latched only a proof-grade fence makes it: a verified
// IPMI power-off (fr.ProvedOff, the rule corrosion.FenceProofGrade applies to
// the row). An SSH, watchdog or best-effort success had a host accept a
// poweroff, or assumed it did, and nothing looked afterwards
// (colonelpanik/litevirt#253).
//
// Until the token latches it keeps the rule every earlier build applies
// (legacyFenceProvedOff), because a successor on an older build resumes a
// recovery only from 'fenced': an unverified fence recorded 'offline' while
// one could still take the lease would strand the workloads. The readers that
// take a host to be off do not depend on this — they ask
// corrosion.HostProvedOff, which judges a 'fenced' state by its row either
// way.
//
// latched is fenceStateLatched, read by the caller before the fence ran.
func fenceRecordState(h *corrosion.HostRecord, fr fence.Result, latched bool) string {
	switch {
	case !fr.Success:
		return ""
	case fr.ProvedOff():
		return "fenced"
	case !latched && legacyFenceProvedOff(h, fr):
		return "fenced"
	default:
		return "offline"
	}
}

// fenceStateLatched reports whether fence_state_v1 has latched: every node
// that can hold the failover lease resumes from an unverified fence recorded
// 'offline'. A nil Gate (tests without the split-brain gate wired) has not.
//
// It reads the latch WITHOUT pinging when the gate can (LatchReader;
// *health.Checker can): until the token latches, Enforced runs a live Ping
// sweep of every activation target, up to capActivationTimeout, and that
// would sit in front of every fence, a verified IPMI one included. The HA
// monitor's capability driver forms the latch in the background, so a stale
// false only records the legacy 'fenced' for an unverified fence — the safe
// direction. A gate that cannot read a latch without pinging is asked
// Enforced, as before.
func (c *Coordinator) fenceStateLatched(ctx context.Context) bool {
	if c.Gate == nil {
		return false
	}
	if lr, ok := c.Gate.(LatchReader); ok {
		return lr.Latched(capabilities.FenceStateV1)
	}
	return c.Gate.Enforced(ctx, capabilities.FenceStateV1)
}

// LatchReader is a gate that can report a token's latch from memory, without
// a Ping (health.Checker.Latched). The coordinator finds it by type assertion
// on its Gate; internal/daemon pins that *health.Checker implements it.
type LatchReader interface {
	Latched(token string) bool
}

// legacyFenceProvedOff is the rule a coordinator before fence_state_v1 used to
// decide that fr proved h off: any successful, non-manual fence — or, for a
// host carrying LabelFenceRequiresConfirmation, only a verified one. It
// decides the recorded state only until the token latches
// (fenceRecordState); nothing reads it as proof.
func legacyFenceProvedOff(h *corrosion.HostRecord, fr fence.Result) bool {
	if requiresFenceConfirmation(h) {
		return fr.ProvedOff()
	}
	return fr.Success && fr.Method != "manual"
}

// fenceWasBestEffort reports whether a fence reporting method, run under
// strategy ranUnder, was a best-effort one — the class the safe-fence policy
// gates.
//
// It is keyed on the fence, never on the host's current strategy. A resumed
// recovery acts on a fence recorded earlier, and an operator can have changed
// the host's strategy since: keyed on the strategy, a best-effort fence
// followed by a switch to ipmi skipped the safe-fence confirmation entirely.
//
// The method alone cannot always tell: best-effort's proceed-after-failure
// reports "best-effort-ssh", but its lenient success reports "ssh", exactly
// like the ssh strategy's. So when the strategy the fence ran under is known
// (a live fence) it decides; when it is not (a resume, ranUnder ""), an "ssh"
// fence is taken to be best-effort. That makes a resumed ssh-strategy recovery
// under the policy wait for a confirmation it would not have needed live — the
// safe direction.
func fenceWasBestEffort(method, ranUnder string) bool {
	if method == "best-effort-ssh" {
		return true
	}
	if ranUnder != "" {
		return fence.ResolveStrategy(ranUnder) == "best-effort"
	}
	return method == "ssh"
}

// requiresFenceConfirmation reports whether h has opted into "an unverified
// fence is not enough" via LabelFenceRequiresConfirmation.
//
// A per-host label, not a config flag or a capability token, and deliberately
// so. The decision it changes is made in ONE place — the coordinator creating
// the recovery — so no peer has to honour anything, and a coordinator on an
// older binary simply does not read the label and behaves exactly as today:
// the fail-mode of a mixed-version roll is the existing behaviour, never a
// weaker one. It is per host because the answer differs by host: one with a
// separate management network is safer to trust than one without. And it
// needs no schema change, beside LabelUnsafeAutoFailover, the fencing policy
// label already here.
func requiresFenceConfirmation(h *corrosion.HostRecord) bool {
	return h != nil && h.Labels[corrosion.LabelFenceRequiresConfirmation] == "true"
}

// markHostState records a host-state transition the coordinator decided on,
// surfacing a write failure without aborting: the caller is mid-recovery and a
// lost state row must not strand the workloads.
func (c *Coordinator) markHostState(ctx context.Context, host, state string) {
	if err := corrosion.UpdateHostState(ctx, c.db, host, state); err != nil {
		slog.Error("failover: mark host state", "host", host, "state", state, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
	}
}

// recoverFenced is the half of a failover that ASSERTS authority: it applies the
// split-brain guards and re-homes the workloads that were on the fenced host.
// It is separate from the fence itself because the two halves can end up on
// different coordinators — a fence whose lease runs out is recorded but not
// acted on, and the next leader resumes here from the fencing_log row rather
// than powering off a host that is already provably down.
//
// fr is the fence this recovery acts on: the live result when called straight
// from failover, or one reconstructed from the recorded fence when resuming.
// ranUnder is the fence strategy fr ran under: the host's strategy at the
// moment of a live fence, or "" when resuming, because the host's strategy
// NOW says nothing about the fence on record (see fenceWasBestEffort).
// The caller must hold the failover lease.
func (c *Coordinator) recoverFenced(ctx context.Context, h *corrosion.HostRecord, fr fence.Result, ranUnder string, latched bool) {
	// Mark the host handled for this down-episode before any early return, so a
	// resumed recovery does not re-enter on every cycle. Note that
	// c.fenceRelocated is deliberately NOT seeded here: it means "THIS
	// coordinator fenced the host and knows whether VMs moved", and a resuming
	// leader knows neither — leaving it unset keeps recoverHosts' auto-recovery
	// off a host somebody else's fence relocated VMs away from.
	c.markHandled(ctx, h.Name)
	// A best-effort fence counts only as a self-pause, live or resumed: a
	// row an older build recorded as an assumed success is not one here.
	// Nor does an SSH power-off the remote shell confirmed, unless the host
	// trusted one when the fence was judged (the decision recorded with it,
	// fence.RecordedTrust, live or resumed) AND still trusts one now: trust is
	// never retroactive, and its revocation holds a recovery not yet made.
	// Why it did not count is read first, from the fence as it ran.
	trustNote := sshTrustNote(h, fr)
	fr = holdUntrustedSSH(notAFenceUnlessPaused(fr), fence.RecordedTrust(fr.Detail) && trustsSSHPoweroff(h))
	// And a self-pause counts only while the pause is still relied on.
	if fr.Success && corrosion.ReliesOnPartitionPause(fr.Method, fr.Detail) && !c.relyOnPartitionPause(ctx, h) {
		fr.Success = false
		fr.Detail += "; " + whyPauseNotRelied
	}

	// Step 2b: a fence that did not record the host "fenced" leaves it
	// "offline" — a weaker claim, and the one the split-brain guards below
	// still demand confirmation for. A successful fence wrote its state with
	// its row, before the lease re-check, so it survives a handoff; this
	// covers a failed fence, and a resumed one recorded 'fenced' that this
	// build would not record so. A host already 'offline' is not written
	// again: that would move the moment its current life began
	// (corrosion.HostFenceLife) past the fence it is recovering on.
	// The host's current life is read before that write, which would end the
	// life fenceRowCutoff measures (confirmedOffNow). It is known only while
	// the host is still recorded active here, which in practice means a fence
	// that failed: a successful one has already recorded the host fenced or
	// offline with its row (failover), and a resumed or afresh recovery finds
	// it so. For those, confirmedOffNow's gates rest on confirmationStands.
	life, lifeKnown := c.fenceRowCutoff(ctx, h.Name)
	if fenceRecordState(h, fr, latched) != "fenced" && h.State != "offline" {
		c.markHostState(ctx, h.Name, "offline")
	}

	// Safe-fence default (gated by SafeFenceDefaultV1). A best-effort fence is
	// fire-and-forget SSH: it reports Success=true even when the poweroff never
	// landed (fence.fenceSSH lenient mode), so it can NEVER confirm the host is
	// actually down. This check must therefore run BEFORE the !fr.Success guard
	// below — a lenient best-effort success would otherwise sail straight through
	// to reschedule. Once the policy is enforced cluster-wide, a best-effort fence
	// is treated like "manual": reschedule only with an operator fence-confirm,
	// unless the host explicitly opts into legacy proceed-anyway. Pre-flip (token
	// not enforced) this is a no-op, so a mixed-version roll keeps today's behavior.
	if fenceWasBestEffort(fr.Method, ranUnder) && c.safeFenceRequiresProof(ctx, h) {
		if stale, ok := c.confirmedOffNow(ctx, h.Name, life, lifeKnown); !ok {
			slog.Error("failover: best-effort fence unconfirmed under safe-fence policy, NOT rescheduling",
				"host", h.Name, "detail", fr.Detail,
				"hint", strings.TrimPrefix(fenceFailedWayOut(h), "; or "))
			if stale == "" { // a stale confirmation is counted once (noteConfirmationStale)
				c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
			}
			c.holdUnproven(ctx, h, "best-effort fence is not proof the host is off (safe-fence policy)"+fenceFailedWayOut(h),
				"the best-effort fence is not proof "+h.Name+" is off, and the safe-fence policy asks for proof", stale, "")
			return
		}
		slog.Info("failover: operator confirmed best-effort fence, proceeding", "host", h.Name)
		c.mAttempt(PhaseSplitBrain, ResultOK, ErrManualConfirmed)
	}

	// A fence that ends a hold (ha.fence_held) and did not reach the host
	// recovers nothing until an operator confirms the host off: what it would
	// recover became recoverable during the hold, so the host's partition pause
	// never paused it, and it may still run there (heldThisOutage).
	if fr.Method == "best-effort-ssh" && c.heldThisOutage(ctx, h.Name) {
		if stale, ok := c.confirmedOffNow(ctx, h.Name, life, lifeKnown); !ok {
			slog.Error("failover: the fence ending a held fence did not reach the host, NOT rescheduling",
				"host", h.Name, "detail", fr.Detail,
				"hint", strings.TrimPrefix(fenceFailedWayOut(h), "; or ")+"; the recovery resumes from it")
			if stale == "" {
				c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
			}
			c.holdUnproven(ctx, h, "best-effort fence after a held fence did not reach the host"+fenceFailedWayOut(h),
				"the best-effort fence that ended a held fence (ha.fence_held) did not reach "+h.Name+
					", and what it would recover was never paused by its partition pause", stale, "")
			return
		}
		slog.Info("failover: operator confirmed a host whose fence was held, proceeding", "host", h.Name)
		c.mAttempt(PhaseSplitBrain, ResultOK, ErrManualConfirmed)
	}

	// Per-host "an unverified fence is not enough" (LabelFenceRequiresConfirmation).
	// A successful fence that did not VERIFY the power-off — SSH, or best-effort
	// in either of its forms — is treated like a manual one: reschedule only on
	// an operator confirmation. A verified (IPMI) fence passes; a failed fence
	// falls through to the split-brain guard below, which refuses it anyway.
	//
	// A confirmation written AFTER this refusal is picked up by the fence loop
	// (resumeFromConfirmation), which resumes the recovery from it.
	if requiresFenceConfirmation(h) && fr.Success && !fr.ProvedOff() {
		if stale, ok := c.confirmedOffNow(ctx, h.Name, life, lifeKnown); !ok {
			slog.Error("failover: host requires a verified fence and this one was not verified, NOT rescheduling",
				"host", h.Name, "method", fr.Method, "detail", fr.Detail,
				"label", corrosion.LabelFenceRequiresConfirmation,
				"hint", "run 'lv host fence-confirm "+h.Name+"' once the host is powered off; the recovery resumes from it")
			if stale == "" {
				c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
			}
			c.noteGateHold(h.Name, "unverified "+fr.Method+" fence awaiting 'lv host fence-confirm "+h.Name+"' ("+corrosion.LabelFenceRequiresConfirmation+")", stale)
			return
		}
		slog.Info("failover: operator confirmed an unverified fence, proceeding", "host", h.Name, "method", fr.Method)
		c.mAttempt(PhaseSplitBrain, ResultOK, ErrManualConfirmed)
	}

	// Split-brain guard. Reschedule only if:
	//   - fence succeeded (real fence happened), OR
	//   - strategy is "manual" or "best-effort" AND an operator confirmation
	//     row stands (confirmedOffNow).
	// Manual fence used to claim Success=true unconditionally; it now reports
	// Success=false and the coordinator must see an explicit confirmation row
	// in fencing_log (written by `lv host fence-confirm`) before rescheduling.
	// A best-effort fence is the same unless the host's partition pause is
	// relied on (asSelfPause, waited out below): one that failed — refused,
	// unstarted, or dialled with nothing confirmed — proves nothing, and the
	// operator's confirmation is its only other way to recover, including
	// the afresh fence run on that confirmation, which cannot reach a host
	// that is off.
	if !fr.Success {
		bestEffort := fr.Method == "best-effort-ssh" && fence.ResolveStrategy(h.FenceStrategy) == "best-effort"
		switch {
		case h.FenceStrategy == "manual" || bestEffort || fr.Unproven:
			// A stale confirmation (stale) is not why the recovery is held:
			// the fence is. Each refusal holds on its own reason, the stale
			// confirmation appended (noteGateHold), and a stale one is
			// counted once, by noteConfirmationStale.
			if stale, ok := c.confirmedOffNow(ctx, h.Name, life, lifeKnown); !ok {
				if fr.Unproven {
					slog.Error("failover: an SSH power-off the remote shell confirmed is not proof the host is off, NOT rescheduling",
						"host", h.Name, "detail", fr.Detail, "hint", strings.TrimPrefix(fenceFailedWayOut(h), "; or "))
					if stale == "" {
						c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
					}
					c.holdUnproven(ctx, h, "the SSH fence's remote shell confirmed the power-off, which is not proof the host is off"+
						fenceFailedWayOut(h)+" ("+trustNote+")",
						"the SSH fence's remote shell confirmed the power-off, which is not proof "+h.Name+
							" is off, and the trust setting does not count it", stale, trustNote)
					return
				}
				if bestEffort {
					slog.Error("failover: the best-effort fence proves nothing and the host's partition pause is not relied on, NOT rescheduling",
						"host", h.Name, "detail", fr.Detail, "hint", strings.TrimPrefix(fenceFailedWayOut(h), "; or "))
					if stale == "" {
						c.mAttempt(PhaseSplitBrain, ResultRefused, ErrFenceFailed)
					}
					c.noteFenceFailure(h, fr)
					c.holdUnproven(ctx, h, c.holdBase[h.Name],
						"the best-effort fence proves nothing ("+fr.Detail+"), and "+h.Name+"'s partition pause is not relied on", stale, "")
					return
				}
				slog.Error("failover: manual fence not confirmed by operator, NOT rescheduling",
					"host", h.Name, "detail", fr.Detail,
					"hint", "run 'lv host fence-confirm "+h.Name+"' once the host is powered off")
				if stale == "" {
					c.mAttempt(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)
				}
				c.noteGateHold(h.Name, "manual fence awaiting 'lv host fence-confirm "+h.Name+"'", stale)
				return
			}
			slog.Info("failover: operator confirmed the host off, proceeding",
				"host", h.Name, "strategy", h.FenceStrategy)
			c.mAttempt(PhaseSplitBrain, ResultOK, ErrManualConfirmed)
		default:
			slog.Error("failover: CRITICAL — fencing failed, NOT rescheduling VMs to prevent split-brain",
				"host", h.Name, "strategy", h.FenceStrategy, "detail", fr.Detail)
			c.mAttempt(PhaseSplitBrain, ResultRefused, ErrFenceFailed)
			c.noteFenceFailure(h, fr)
			// A host fenced only over SSH has no other way to be proven off:
			// one that lost power leaves the fence nothing to reach, and only
			// the operator can say it is off (the rc9 lab's F1a).
			// One raised before, on a host since given a BMC strategy whose
			// fence failed too, is kept current: the reason is this failure.
			// With the newest stale confirmation, as the settle sweep raises
			// it, so the row is not rewritten twice per retry.
			if fence.SSHOnly(h.FenceStrategy) {
				c.raiseUnproven(ctx, h, "the SSH fence of "+h.Name+" failed ("+fr.Detail+"), so nothing proves "+h.Name+
					" is off; the fence is retried with backoff, and an SSH fence cannot reach a host that has lost power", c.lastStale[h.Name], "")
			} else if c.unprovenOpen(ctx, h.Name) {
				c.raiseUnproven(ctx, h, "the "+fr.Method+" fence of "+h.Name+" failed ("+fr.Detail+"), so nothing proves "+h.Name+
					" is off; the fence is retried with backoff", c.lastStale[h.Name], "")
			}
			return
		}
	}

	// Whether this recovery rests on a trusted SSH power-off: a claim retry it
	// leaves owed re-judges that trust before it runs (retryClaims).
	if c.restsOnTrust == nil {
		c.restsOnTrust = map[string]bool{}
	}
	c.restsOnTrust[h.Name] = fr.Method == "ssh" && fr.Success

	// Past every gate: whatever fence held the recovery for want of proof
	// no longer does (ha.recovery.unproven_fence).
	c.resolveUnproven(ctx, h.Name, "the recovery went ahead")

	// A fence that relied on the host's partition pause starts nothing until
	// the pause has certainly happened (docs/design/partition-pause.md §4.2);
	// retryPauseWait finishes it from the fence loop.
	if corrosion.ReliesOnPartitionPause(fr.Method, fr.Detail) && !c.pauseDeadlinePassed(ctx, h) {
		c.noteHold(h.Name, "waiting out the host's partition pause")
		return
	}
	delete(c.pauseWaits, h.Name)
	if fr.ProvedOff() {
		// A fence that proves the host off answers for every workload on it.
		// One that does not (best-effort in either form, a plain SSH request)
		// keeps a bridged host's limit: it says nothing about the workloads
		// the host was seen running and did not report pausing.
		c.unlimitRecovery(h.Name)
	}

	// The fence is done and h's state row is written; everything below is
	// recovery, and every refusal in it is therefore post-fence.
	c.noteRecoveryAt(h.Name, c.now(), c.mono())
	c.recoverWorkloads(ctx, h)
}

// recoverWorkloads moves every recoverable workload off a host that is already
// fenced: VMs by replica promotion or reschedule, containers by relocation.
//
// It performs NO fencing. failover has already fenced h and written its state
// row by the time this runs, so re-fencing here would power-cycle a machine
// that is already down and mint a second fence epoch for one outage.
//
// Everything it needs is re-derived from persisted state rather than passed in:
// fenceEpoch from fencing_log via proofGradeFenceRef, the candidate set from
// healthyHosts, and the work itself from the rows still pointing at h. That
// makes it idempotent — a successful reschedule re-homes the VM row and a
// successful relocation tombstones the source row — which is what lets it be
// read as a separate step rather than as the tail of the fence.
//
// It is a separate function because the fence and the recovery answer different
// questions, and because every refusal inside it happens AFTER the fence: the
// host is already marked down, so a decline here leaves work assigned to a
// machine that will not run it. strandedByHost reports that condition.
//
// One consequence of taking fenceEpoch from fencing_log is deliberate:
// proofGradeFenceRef only counts a fence inside recentFenceWindow, so a VM with
// a writable shared disk fails CLOSED at the shared-storage gate once that
// window lapses. Transferring a shared disk on aged-out evidence of power-off is
// the split-brain the gate exists to prevent.
func (c *Coordinator) recoverWorkloads(ctx context.Context, h *corrosion.HostRecord) {
	// Bind cross-host transfer proofs to THIS fence: for a VM with a writable
	// shared disk the executor requires a proof-grade power-off of the old owner
	// (SharedStorageFenceV1), re-verified from fencing_log via this reference. ""
	// when the fence wasn't proof-grade (best-effort/SSH) — the executor then fails
	// a shared-disk transfer closed while a local-disk transfer still proceeds.
	// Every recovery is Held while HA is disarmed; the fence loop resumes it
	// once HA is armed (resumeHAHeldRecovery).
	if c.haHold(ctx, h.Name, haSiteRecovery) {
		c.noteHAHeldRecovery(h.Name)
		return
	}
	fenceEpoch, fenceEpochWhy, fenceEpochRetry := c.proofGradeFenceRefWhy(ctx, h.Name)
	// Recovery is running: whatever held it back before no longer does, and
	// a refusal below records what holds it now (the stall alert's reason).
	c.clearHold(h.Name)

	// Step 3: Find VMs that should be restarted.
	vms, err := corrosion.ListVMs(ctx, c.db, "", h.Name)
	if err != nil {
		slog.Error("failover: list VMs", "host", h.Name, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
		c.noteHold(h.Name, "recovery could not list the host's VMs: "+err.Error())
		return
	}
	// Highest compose migrate.priority first, ties by name (ListVMs returns
	// this replica's insertion order, which another coordinator's need not
	// share).
	// Everything below follows this order: auto-promote, the batch placement
	// (SelectBatch commits each request's capacity before the next is
	// scored, so a higher-priority VM is placed before the room runs out),
	// and the claim and proof mint of each reschedule. It only orders work:
	// every gate below still decides each VM on its own.
	corrosion.SortVMsByMigratePriority(vms)
	vms, notPaused := onlyReportedPausedFilter(c.recoverOnly[h.Name], health.PauseKindVM, vms,
		func(v corrosion.VMRecord) string { return v.Name })
	c.noteNotReportedPaused(h.Name, health.PauseKindVM, c.heldVMNames(ctx, notPaused))

	// Step 4: Verify healthy hosts exist before attempting rescheduling.
	candidates, err := c.healthyHosts(ctx, h.Name)
	if err != nil {
		slog.Error("failover: list healthy hosts", "host", h.Name, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
		c.noteHold(h.Name, "recovery could not list healthy hosts: "+err.Error())
		return
	}
	if len(candidates) == 0 {
		slog.Warn("failover: no healthy hosts available for VM rescheduling", "host", h.Name)
		c.mAttempt(PhaseFence, ResultRefused, ErrNoCandidates)
		c.noteHold(h.Name, "no healthy host to recover its workloads onto")
		return
	}
	// A spec pin to a host that is down is ignored for this recovery
	// (buildFailoverPlacementRequest). Every live host is listed, not only the
	// candidates: a pin to a host that is up but cannot take the VM, a
	// witness say, still holds and strands it.
	allHosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("failover: list hosts", "host", h.Name, "error", err)
		c.mAttempt(PhaseFence, ResultError, ErrDBError)
		c.noteHold(h.Name, "recovery could not list hosts: "+err.Error())
		return
	}
	hostState := make(map[string]string, len(allHosts))
	for _, ah := range allHosts {
		hostState[ah.Name] = ah.State
	}
	pinDown := func(host string) bool {
		st, ok := hostState[host]
		return !ok || st != "active"
	}
	// Hosts whose bridge cannot carry an access-VLAN NIC are passed over
	// for a VM with one while another host qualifies.
	vlanView := c.readAccessVLANView(ctx)

	// Step 5: Reschedule VMs using placement engine for proper resource-aware scheduling.
	type failoverPlan struct {
		vm             corrosion.VMRecord
		targetName     string
		needsPlacement bool
		// rekeyStopped: a VM stopped by intent on shared storage, moved to the
		// target still stopped and never started (rekeyStoppedVM).
		rekeyStopped bool
	}
	plans := make([]failoverPlan, 0, len(vms))
	placementReqs := make([]placement.Request, 0, len(vms))
	// The PCI passthrough devices of each VM placed with them, described
	// for its hold (pci_devices.go).
	devHeld := map[string][]string{}

	// A VM recorded migrating may run on the migration's target: it is
	// started nowhere until the target is asked (migrating_row.go).
	migrating := c.settleMigratingVMs(ctx, h, vms)
	for _, vm := range vms {
		if vm.State == "migrating" && !c.recoverMigratingVM(h, vm, migrating) {
			continue
		}
		// A stopped VM is decided FIRST, ahead of auto-promote, which defines
		// and starts a VM too (skip_stopped.go):
		//   - stopped by intent: never started. On shared storage only, it is
		//     moved to a live host still stopped; otherwise it stays on h with
		//     its disks;
		//   - stopped without intent (a guest or host shutdown) with a
		//     host-local disk: stays — a restart elsewhere would rebuild that
		//     disk blank and strand the real one on h;
		//   - stopped without intent, all disks shared: recovered below as
		//     main recovered it, on its real disks.
		// The writes re-check the stop inside their transactions, so a stop that
		// lands after this read still wins.
		if vm.State == "stopped" {
			disks, derr := corrosion.GetVMDisks(ctx, c.db, vm.Name)
			if derr != nil {
				slog.Warn("failover: cannot read a stopped VM's disks; leaving it (fail closed)", "vm", vm.Name, "error", derr)
				c.mVM(ActionReschedule, ResultError, ErrDBError)
				continue
			}
			if corrosion.VMStoppedForFailover(vm) {
				if c.stoppedVMRekeyable(ctx, h.Name, vm, disks, fenceEpoch) {
					req := buildFailoverPlacementRequest(vm, h.Name, c.capacity, pinDown)
					c.addPlacementLabels(ctx, &req, vm.Name)
					vlanView.avoid(&req, vm)
					c.resolveUSBPlacement(ctx, &req)
					if _, hold := c.addDevicePlacement(ctx, &req, vm); hold != "" {
						c.skipStoppedVM(ctx, h.Name, vm, stoppedVMDetail(h.Name)+"; not moved: "+hold)
						continue
					}
					req.RequireRegion = c.vmRecoveryRegion(h.Name, vm)
					placementReqs = append(placementReqs, req)
					plans = append(plans, failoverPlan{vm: vm, needsPlacement: true, rekeyStopped: true})
					continue
				}
				detail := stoppedVMDetail(h.Name)
				if fenceEpoch == "" && c.sharedStorageFenceEnforced(ctx) && c.vmWasCandidate(ctx, vm) &&
					!vmUsesFirmwareState(vm) && !corrosion.VMHasHostLocalDisk(disks) &&
					corrosion.VMHasSharedDisk(ctx, c.db, disks, c.hostName) {
					// Not moved on its shared disks for want of a fence that
					// binds: say why, as a running VM's hold does.
					detail += "; not moved on its shared disks: " + c.sharedDiskUnproven(h.Name, fenceEpochWhy, fenceEpochRetry)
				}
				c.skipStoppedVM(ctx, h.Name, vm, detail)
				continue
			}
			if corrosion.VMHasHostLocalDisk(disks) {
				c.skipStoppedVM(ctx, h.Name, vm, stoppedLocalDiskDetail(h.Name, vm.StateDetail))
				continue
			}
		}

		// A Secure-Boot/vTPM VM's firmware state (UEFI NVRAM + swtpm) is host-local,
		// so it died with the fenced host — neither a reschedule (would boot a fresh
		// TPM) nor a disk-only replica promotion can recover it. Skip automatic
		// failover and surface it; recovery is an explicit restore from a backup
		// that carried the firmware (G1).
		if vmUsesFirmwareState(vm) {
			slog.Warn("failover: skipping Secure Boot / vTPM VM — firmware state was host-local and died with the host; restore from backup",
				"vm", vm.Name, "host", h.Name)
			c.auditSkip(ctx, h.Name, vm.Name, "Secure Boot / vTPM VM not auto-failed-over (firmware state lost with "+h.Name+")", "skipped")
			c.mVM(ActionReschedule, ResultSkipped, ErrFirmwareState)
			continue
		}

		// Automated recovery must never act on a workload whose OWNERSHIP is in
		// dispute. The fenced host is only ONE of the condition's holders: the
		// other side may still be live and unfenced, and rescheduling (or
		// promoting) this VM onto a third host manufactures exactly the
		// dual-writer the condition was raised to prevent. The owner-assert and
		// self-heal paths already refuse on this; failover is the remaining
		// automated writer. Fail closed on a read error — a coordinator that
		// cannot see the conditions must not assume there are none.
		if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, c.db, "vm", vm.Name); cerr != nil {
			slog.Warn("failover: cannot read health conditions; deferring VM recovery (fail closed)",
				"vm", vm.Name, "error", cerr)
			c.mVM(ActionReschedule, ResultError, ErrDBError)
			continue
		} else if disputed {
			slog.Warn("failover: refusing VM recovery — active ownership condition; resolve the dispute first",
				"vm", vm.Name, "condition", code)
			c.noteGateRefused(corrosion.ActionReschedule, health.ReasonOwnershipDispute)
			c.mVM(ActionReschedule, ResultRefused, ErrOwnershipDispute)
			c.noteHold(h.Name, "VM "+vm.Name+": active ownership condition "+code+"; resolve the dispute")
			c.auditSkip(ctx, h.Name, vm.Name, "active ownership condition "+code+" — automated recovery refused", "refused")
			continue
		}

		// Shared-disk split-brain gate (decide site): if this coordinator enforces
		// the shared-storage fence and the VM has a writable shared disk, a cross-host
		// transfer needs a PROOF-GRADE fence of the old owner. fenceEpoch is non-empty
		// ONLY when proofGradeFenceRef found one (IPMI / manual-confirmed); a
		// best-effort fence yields "". Refuse to CREATE the transfer (auto-promote OR
		// reschedule) at the SOURCE when there's no proof-grade fence — so a
		// config-skewed / regressed target can never receive (and ungated-start) a
		// shared-disk transfer lacking a proven power-off. When a proof-grade fence
		// DOES exist the transfer proceeds and even an unenforcing target starts
		// safely (the owner is provably down). The executor re-verifies as
		// defense-in-depth. Operator remediation: `lv host fence-confirm` (or an IPMI
		// fence strategy) makes fenceEpoch proof-grade on the next cycle.
		if fenceEpoch == "" && c.sharedStorageFenceEnforced(ctx) {
			if disks, derr := corrosion.GetVMDisks(ctx, c.db, vm.Name); derr == nil && corrosion.VMHasSharedDisk(ctx, c.db, disks, c.hostName) {
				slog.Error("failover: shared-disk VM transfer refused — no proof-grade fence of old owner (storage_unverified); run 'lv host fence-confirm' or set an IPMI or Redfish fence strategy",
					"vm", vm.Name, "old_owner", h.Name, "reason", fenceEpochWhy)
				c.sharedDiskUnproven(h.Name, fenceEpochWhy, fenceEpochRetry)
				c.noteGateRefused(corrosion.ActionReschedule, health.ReasonStorageUnverified)
				c.mVM(ActionReschedule, ResultError, ErrStorageUnverified)
				continue
			}
		}

		// Auto-promotion is an explicit per-schedule DR opt-in, so it takes
		// precedence over the VM's on_host_failure policy (which defaults to
		// "none" for `lv run` VMs). A VM on the fenced host's local storage has
		// no disk on any other host, so a bare reschedule can't start it;
		// promoting the freshest replica defines + starts the VM on the host
		// holding it and re-homes the record. On success, move to the next VM.
		// On failure, fall through to the policy-based reschedule below.
		if c.Promoter != nil && c.autoPromoteEnabled(ctx, vm.Name) {
			// Split-brain gate (Phase 1, decide site): promoting a replica is a
			// runtime-ownership action; once enforced, re-check DecisionGate before
			// initiating so an isolated minority coordinator can't promote. The
			// execute-side proof (metadata-carried, single-use) is the remaining
			// direct-RPC closeout. Fail-open until cluster-wide.
			if c.gateEnforced(ctx) {
				if g := c.decideGate(ctx, h.Name); !g.OK {
					slog.Warn("failover: decision gate refused auto-promote", "vm", vm.Name, "reason", g.Reason)
					c.noteGateRefused(corrosion.ActionPromote, g.Reason)
					c.mVM(ActionPromote, ResultError, ErrNoQuorum)
					continue
				}
			}
			// Promote is as destructive as reschedule and relocate -- it
			// defines and starts a VM on a new host -- so it takes the same
			// stale-tenure abandon the three sibling sites take. Without it a
			// coordinator whose lease lapsed mid-loop had its reschedule and
			// relocate refused while its promote went through: gateEnforced
			// passes (a lapse is not quorum loss) and, for a local-disk DR VM,
			// requireProofGradeFence never fires either.
			_, _, promoteTerm, _, ok := c.leaseStamp(ctx)
			// stillOurTenure as well as leaseStamp: the stamp says a term may
			// be recorded, not that the lease is still held. A tick that
			// stalled after its own lease gate is exactly the case this has
			// to catch, and it is the only one in which a stale-tenure
			// promote is reachable at all.
			if !ok || !c.stillOurTenure(ctx) {
				c.noteGateRefused(corrosion.ActionPromote, health.ReasonStaleLeaseTerm)
				c.mVM(ActionPromote, ResultError, ErrStaleLeaseTerm)
				c.noteLeaseTermRefusal(ctx, "vm", vm.Name, h.Name)
				continue
			}
			if c.haHold(ctx, h.Name, haSitePromote) {
				c.noteHAHeldRecovery(h.Name)
				continue
			}
			// The disks as they were before the promotion re-homes them: what
			// it leaves on the failed host, recorded once it succeeds.
			disksBefore, disksErr := corrosion.GetVMDisks(ctx, c.db, vm.Name)
			if err := c.autoPromote(ctx, h, vm, fenceEpoch, promoteTerm); err != nil && errors.Is(err, corrosion.ErrPromoteHeld) && c.holdsDown(ctx, vm, heldCause(err)) {
				// Held: the VM's only replicas are not point-in-time, or the
				// replica is on a witness (heldCause). A
				// host-local disk cannot be restarted elsewhere, so a
				// reschedule would only re-home the record onto a host that
				// cannot start it and hide the hold; the VM stays where it
				// is, down, until an operator promotes it by hand (the
				// promotion's event names the command).
				slog.Warn("failover: VM held down; "+heldCause(err), "vm", vm.Name, "error", err)
				c.mVM(ActionPromote, ResultSkipped, ErrPromoteFailed)
				c.auditSkip(ctx, h.Name, vm.Name, "held: "+heldCause(err)+heldSteps(err), "held")
				continue
			} else if err != nil {
				// Fall through to the reschedule path on ANY promote error, including a
				// retryable Unavailable (e.g. the fence_epoch fencing_log row hasn't
				// replicated to the replica host yet). This is NOT a downgrade to a
				// weaker path: the reschedule now carries the same fence_epoch, and the
				// TARGET reconciler re-enforces the shared-disk proof-grade gate before
				// starting — and, unlike this once-per-fenced-host loop, the reconciler
				// genuinely retries a not-yet-replicated fence on its next tick. A bare
				// `continue` here would strand the VM, since a fenced host is processed
				// only once (c.fenced / state=="fenced" / recentlyFenced all short-circuit
				// later cycles until the host recovers).
				slog.Warn("failover: auto-promote failed, falling back to reschedule",
					"vm", vm.Name, "error", err)
				c.mVM(ActionPromote, ResultError, ErrPromoteFailed)
			} else {
				slog.Info("failover: VM recovered via replica promotion", "vm", vm.Name)
				c.fenceRelocated[h.Name] = true
				c.mVM(ActionPromote, ResultSuccess, errClassNone)
				c.audit(ctx, "failover.promote", vm.Name, "promoted replica after fencing "+h.Name, "ok")
				c.noteDisksLeftByPromote(ctx, h.Name, vm, disksBefore, disksErr)
				continue
			}
		}

		policy := vmFailurePolicy(vm)
		if policy == "none" || policy == "" {
			slog.Info("failover: VM skipped (on_host_failure=none)", "vm", vm.Name)
			c.mVM(ActionReschedule, ResultSkipped, ErrPolicyNone)
			continue
		}

		var targetName string

		if policy == "restart-same" {
			same, _ := corrosion.GetHost(ctx, c.db, vm.HostName)
			if same != nil && same.State == "active" {
				targetName = same.Name
			}
			if targetName == "" {
				// Elsewhere would rebuild a host-local disk blank: such a VM
				// waits for its host (restart_same.go). All-shared moves on.
				disks, derr := corrosion.GetVMDisks(ctx, c.db, vm.Name)
				if derr != nil {
					slog.Warn("failover: cannot read a restart-same VM's disks; leaving it (fail closed)", "vm", vm.Name, "error", derr)
					c.mVM(ActionReschedule, ResultError, ErrDBError)
					continue
				}
				if corrosion.VMHasHostLocalDisk(disks) {
					c.holdRestartSame(ctx, h.Name, vm, disks)
					continue
				}
			}
		}

		if targetName == "" {
			req := buildFailoverPlacementRequest(vm, h.Name, c.capacity, pinDown)
			c.addPlacementLabels(ctx, &req, vm.Name)
			vlanView.avoid(&req, vm)
			c.resolveUSBPlacement(ctx, &req)
			devs, hold := c.addDevicePlacement(ctx, &req, vm)
			if hold != "" {
				c.holdForDevices(ctx, h.Name, vm, nil, hold)
				continue
			}
			if len(devs) > 0 {
				devHeld[vm.Name] = devs
			}
			if pin := vmSpecPin(vm); pin != "" && pin != h.Name && req.PinHost == "" {
				slog.Warn("failover: the VM's pinned host is down; recovering it elsewhere for this outage, its pin unchanged",
					"vm", vm.Name, "pinned_host", pin, "pinned_host_state", hostState[pin], "from", h.Name)
			}
			// Region scope keeps the recovery in the fenced host's region, as a
			// hard constraint: a VM no host there can hold stays put, loudly,
			// like any other unsatisfiable constraint.
			req.RequireRegion = c.vmRecoveryRegion(h.Name, vm)
			placementReqs = append(placementReqs, req)
			plans = append(plans, failoverPlan{vm: vm, needsPlacement: true})
			continue
		}

		plans = append(plans, failoverPlan{vm: vm, targetName: targetName, needsPlacement: false})
	}

	placements := map[string]placement.BatchResult{}
	if len(placementReqs) > 0 {
		allVMs, err := corrosion.ListVMs(ctx, c.db, "", "")
		if err != nil {
			slog.Error("failover: list VMs for batch placement", "host", h.Name, "error", err)
			c.mAttempt(PhaseFence, ResultError, ErrDBError)
			return
		}
		ctMem, err := corrosion.SumContainerMemoryByHost(ctx, c.db)
		if err != nil {
			ctMem = nil
		}
		// Effective-capacity observations, best-effort: absent, the batch
		// degrades to DB-only arithmetic; present, runtime-only usage counts
		// against headroom and an incomplete/stale host is excluded.
		observations, oerr := corrosion.ListHostCapacityObservations(ctx, c.db)
		if oerr != nil {
			observations = nil
		}
		// There is deliberately NO fallback on a batch error. The old code
		// round-robined the fenced host's VMs across whatever candidates were
		// healthy — blind to capacity, labels, affinity, spread, max-per-node,
		// and incomplete-inventory exclusions — and the target reconciler
		// re-checks none of those before starting, so an infeasible placement
		// simply landed. Refusing leaves the rows on the fenced host, loudly,
		// and the operator (or the next placement input change) recovers them;
		// hard constraints that no surviving host satisfies must strand the
		// workload, not relocate it somewhere it was never allowed to run.
		if selected, err := c.selectBatch(ctx, c.pitOverlaySafeTargets(ctx, candidates), allVMs, ctMem,
			observations, c.now(), placementReqs); err != nil {
			slog.Error("failover: batch placement failed — affected VMs are left for operator recovery, NOT round-robined",
				"host", h.Name, "error", err)
			c.noteHold(h.Name, "batch placement failed: "+err.Error())
			for i := range plans {
				if plans[i].needsPlacement {
					c.mVM(ActionReschedule, ResultError, ErrPlacementFailed)
					c.auditSkip(ctx, h.Name, plans[i].vm.Name, "batch placement failed after fencing "+h.Name+": "+err.Error(), "error")
				}
			}
			plans = plans[:0]
		} else {
			placements = selected
		}
	}

	for _, p := range plans {
		vm := p.vm
		if p.needsPlacement {
			result, ok := placements[vm.Name]
			if !ok || result.Host == "" {
				// No eligible host under the VM's hard constraints. Same
				// reasoning as the batch-error path above: skip loudly.
				// result.Err names the filter that refused each survivor — the
				// operator's only clue to what would let the VM place.
				detail := "no eligible host satisfies its placement constraints after fencing " + h.Name
				if result.Err != nil {
					detail += ": " + result.Err.Error()
				}
				if devs := devHeld[vm.Name]; len(devs) > 0 {
					why := ""
					if result.Err != nil {
						why = result.Err.Error()
					}
					c.holdForDevices(ctx, h.Name, vm, devs, why)
					continue
				}
				slog.Warn("failover: no eligible host for VM — left for operator recovery, NOT round-robined",
					"vm", vm.Name, "from", h.Name, "reason", result.Err)
				c.mVM(ActionReschedule, ResultSkipped, ErrPlacementFailed)
				c.noteHold(h.Name, "VM "+vm.Name+": "+detail)
				c.auditSkip(ctx, h.Name, vm.Name, detail, "skipped")
				continue
			}
			p.targetName = result.Host
			p.needsPlacement = false
		}

		targetName := p.targetName

		if p.rekeyStopped {
			c.rekeyStoppedVM(ctx, h.Name, vm, targetName, fenceEpoch)
			continue
		}

		slog.Info("failover: rescheduling VM",
			"vm", vm.Name, "from", vm.HostName, "to", targetName, "policy", vmFailurePolicy(vm))

		if c.haHold(ctx, h.Name, haSiteReschedule) {
			c.noteHAHeldRecovery(h.Name)
			continue
		}
		if c.gateEnforced(ctx) {
			// ListVMs deliberately omits operation-control columns, including
			// vm_owner_epoch. Re-read the full authoritative row at the decision
			// boundary so the proof binds the real ownership generation; the
			// transactional writer checks the same epoch again to close the race.
			freshVM, ferr := corrosion.GetVM(ctx, c.db, vm.Name)
			if ferr != nil || freshVM == nil || freshVM.HostName != h.Name {
				slog.Warn("failover: VM ownership changed before proof mint; deferring",
					"vm", vm.Name, "expected_host", h.Name, "error", ferr)
				c.mVM(ActionReschedule, ResultError, ErrDBError)
				continue
			}
			vm = *freshVM
			// Enforcement active: re-check DecisionGate (quorum + coordinator-eligible;
			// the lease is already held in this failover path) as close to the write as
			// possible, then write a durable proof linked to the pending transition so
			// the target's reconciler can validate + single-use-claim it before starting.
			if g := c.decideGate(ctx, h.Name); !g.OK {
				slog.Warn("failover: decision gate refused reschedule", "vm", vm.Name, "reason", g.Reason)
				c.noteGateRefused(ActionReschedule, g.Reason)
				c.mVM(ActionReschedule, ResultError, ErrNoQuorum)
				continue
			}
			// Never stamp a proof for a target that no longer advertises the gate
			// (a regressed/replaced host that couldn't honor it) — fresh-Ping it
			// first and refuse (fail closed) rather than reschedule there ungated.
			if !c.destAdvertisesGate(ctx, targetName) {
				slog.Warn("failover: reschedule target does not advertise split-brain gate — refusing (fail closed)",
					"vm", vm.Name, "target", targetName)
				c.noteGateRefused(ActionReschedule, health.ReasonUnsupportedCapability)
				c.mVM(ActionReschedule, ResultError, ErrDestUngated)
				continue
			}
			live, needed := c.proofQuorum(ctx, h.Name)
			// The fencing term of THIS tenure, taken from what the coordinator
			// recorded at acquisition — never from a fresh MAX(term) read, which
			// would let a displaced holder adopt the winner's term.
			//
			// reschedule is the one action in leaseTermRequiredActions, and this
			// is its only mint site, so an unstamped proof here is refused
			// outright once lease_term_v1 latches: judgeProofLeaseTerm sees
			// term 0 with an empty key and returns ReasonStaleLeaseTerm, so the
			// VM is never started and sits pending forever. Nothing detected
			// that, because LeaseTermReadiness checks whether this node can MINT
			// a term, not whether its producers STAMP one.
			leaseHolder, leaseExp, leaseTerm, leaseKey, ok := c.leaseStamp(ctx)
			if !ok {
				c.noteGateRefused(ActionReschedule, health.ReasonStaleLeaseTerm)
				c.mVM(ActionReschedule, ResultError, ErrStaleLeaseTerm)
				c.noteLeaseTermRefusal(ctx, "vm", vm.Name, h.Name)
				continue
			}
			proof := corrosion.ActionProof{
				ID: randid.New(), Action: corrosion.ActionReschedule, TargetKind: "vm",
				TargetName: vm.Name, DestHost: targetName, Coordinator: c.hostName,
				LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
				QuorumLive: live, QuorumNeeded: needed, FenceEpoch: fenceEpoch,
				OwnerEpoch: ownerEpochString(vm.OwnerEpoch),
				LeaseTerm:  leaseTerm, LeaseKey: leaseKey,
			}
			// Claim before mint (docs/design/recovery-claims.md §3.13): the
			// proof written below is the DECIDED value — ours, or another
			// coordinator's, re-materialized with its own ID and destination.
			// Without a certificate nothing is written.
			if c.claimsEnforced(ctx) {
				cl, cerr := c.claimRecoveryFor(ctx, proof, h.Name, vm.CreatedAt, func(d corrosion.HostRecord) string {
					return c.vmFitsOn(ctx, vm, h.Name, d)
				})
				if cerr != nil {
					c.noteClaimRefused(ctx, ActionReschedule, "vm", vm.Name, h.Name, cerr)
					continue
				}
				if cl.Proof.Action != corrosion.ActionReschedule {
					c.noteClaimLost(ActionReschedule, "vm", vm.Name, h.Name, cl.Proof)
					continue
				}
				if cl.Proof.DestHost == h.Name {
					// Decided FOR the host being recovered, which died before
					// it acted: stranded until it returns or is removed for
					// good (ha.claim.stranded names the command).
					c.noteClaimStranded("vm", vm.Name, h.Name, cl.Proof)
					continue
				}
				proof, targetName = cl.Proof, cl.Proof.DestHost
			}
			// The mint itself: re-checked last, after the claim's round trips.
			if c.haHold(ctx, h.Name, haSiteReschedule+"-mint") {
				c.noteHAHeldRecovery(h.Name)
				continue
			}
			if err := corrosion.WriteVMRescheduleProof(ctx, c.db, proof, vm.Name, targetName); err != nil {
				if errors.Is(err, corrosion.ErrWorkloadStopped) {
					// Stopped after it was chosen: the stop wins.
					c.skipStoppedVM(ctx, h.Name, vm, stoppedVMDetail(h.Name))
					continue
				}
				slog.Error("failover: write reschedule proof", "vm", vm.Name, "error", err)
				c.mVM(ActionReschedule, ResultError, ErrDBError)
				continue
			}
		} else if err := corrosion.RescheduleVMHost(ctx, c.db, vm.Name, targetName, "pending"); err != nil {
			// Legacy (pre-activation) path.
			if errors.Is(err, corrosion.ErrWorkloadStopped) {
				c.skipStoppedVM(ctx, h.Name, vm, stoppedVMDetail(h.Name))
				continue
			}
			slog.Error("failover: update VM host", "vm", vm.Name, "error", err)
			c.mVM(ActionReschedule, ResultError, ErrDBError)
			continue
		}
		c.fenceRelocated[h.Name] = true
		c.mVM(ActionReschedule, ResultSuccess, errClassNone)

		c.audit(ctx, "failover", vm.Name, "rescheduled from "+h.Name+" to "+targetName, "ok")
		// A hold an earlier pass recorded (for its PCI devices) is over.
		if err := health.ResolveHeldMoved(ctx, c.db, c.hostName, vm.Name, h.Name, c.now()); err != nil {
			slog.Warn("failover: could not clear the hold of a VM recovered since", "vm", vm.Name, "error", err)
		}
		c.noteDiskStranded(ctx, h.Name, vm, targetName)
		// The VM may now run on its own replica target: replicate back to the
		// host it left (or leave the schedule suspended, reported by its runs).
		corrosion.ReverseReplicationAudited(ctx, c.db, "vm", vm.Name, "", h.Name, targetName, func(detail, result string) {
			c.audit(ctx, "replication.reverse", vm.Name, detail, result)
		})
	}

	// Step 6: Relocate containers on the fenced host (B5). Unlike VMs, a
	// container's rootfs lived on the (now dead) host, so relocation re-creates
	// it from a re-pullable image origin on the target. This is state-only here
	// — re-key the row to the target as pending+relocate-recreate; the target's
	// container reconciler does the actual recreate. Stateful / non-re-pullable
	// containers are skipped and loudly audited (their data can't be recovered
	// without a backup — the backup-restore tier is a follow-up).
	c.relocateContainers(ctx, h, candidates)
}

// relocateContainers re-homes the fenced host's relocatable containers onto
// healthy hosts. For each, it prefers a faithful restore-from-backup (tier-2),
// falls back to image-recreate (tier-1), else skips — and re-derives the outcome
// of any in-flight restore-relocation (crash recovery). Shares the round-robin
func (c *Coordinator) relocateContainers(ctx context.Context, h *corrosion.HostRecord, candidates []corrosion.HostRecord) {
	// Split-brain gate (Phase 1, decide site): once enforced, re-check DecisionGate
	// (quorum + coordinator-eligible; lease already held in the failover path)
	// before relocating any container off the fenced host — an isolated minority
	// coordinator must not initiate relocation. Fail-open until cluster-wide.
	if c.gateEnforced(ctx) {
		if g := c.decideGate(ctx, h.Name); !g.OK {
			slog.Warn("failover: decision gate refused container relocation", "host", h.Name, "reason", g.Reason)
			c.noteGateRefused(corrosion.ActionRelocate, g.Reason)
			c.mCt(ActionRelocate, ResultError, ErrNoQuorum)
			return
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, h.Name)
	if err != nil {
		slog.Error("failover: list containers", "host", h.Name, "error", err)
		c.mCt(ActionRelocate, ResultError, ErrDBError)
		return
	}
	cts, notPaused := onlyReportedPausedFilter(c.recoverOnly[h.Name], health.PauseKindContainer, cts,
		func(ct corrosion.ContainerRecord) string { return ct.Name })
	c.noteNotReportedPaused(h.Name, health.PauseKindContainer, heldContainerNames(notPaused))
	for _, ct := range cts {
		// A stopped container is not a failover candidate either
		// (ContainerRecoverableOnHostFailure): relocating it recreates and
		// starts it on another host. The first check, as for VMs; the
		// relocation writes re-check it in their transactions.
		if corrosion.ContainerStoppedForFailover(ct) {
			c.skipStoppedContainer(ctx, h.Name, ct)
			continue
		}
		if ct.OnHostFailure == "" || ct.OnHostFailure == "none" {
			continue
		}
		// Already triaged to skipped in a prior pass — left visible for operator
		// recovery; don't re-process (and don't loop on it). On a host removed
		// for good it is retried once a host can take it: nothing else ever
		// moves it, and the name cannot be re-admitted while it is recorded
		// there (retrySkippedOnRemovedHost).
		if ct.StateDetail == corrosion.ContainerRelocateSkippedDetail && !c.retrySkippedOnRemovedHost(ctx, h, ct) {
			continue
		}
		// Same ownership-dispute refusal as the VM loop: the other holder of the
		// dispute may be live on an unfenced host, and recreating this container
		// elsewhere adds a writer. Fail closed on a read error.
		if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, c.db, "container", ct.Name); cerr != nil {
			slog.Warn("failover: cannot read health conditions; deferring container relocation (fail closed)",
				"container", ct.Name, "error", cerr)
			c.mCt(ActionRelocate, ResultError, ErrDBError)
			continue
		} else if disputed {
			slog.Warn("failover: refusing container relocation — active ownership condition; resolve the dispute first",
				"container", ct.Name, "condition", code)
			c.noteGateRefused(corrosion.ActionRelocate, health.ReasonOwnershipDispute)
			c.mCt(ActionRelocate, ResultRefused, ErrOwnershipDispute)
			c.noteHold(h.Name, "ct "+ct.Name+": active ownership condition "+code+"; resolve the dispute")
			continue
		}
		// Crash recovery: a prior tick already began a restore-relocation (marker on
		// the source row, carrying the target + attempt token). Re-derive.
		if target, token, restoring := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail); restoring {
			c.resumeRestoreRelocation(ctx, h, ct, target, token, candidates)
			continue
		}
		c.startRelocation(ctx, h, ct, candidates)
	}
}

// startRelocation relocates one not-yet-marked container: restore-from-backup if
// possible, else image-recreate, else skip.
func (c *Coordinator) startRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord) {
	target, _ := c.pickContainerTarget(ctx, ct, candidates)
	if target == "" {
		slog.Warn("failover: no target for container relocation", "container", ct.Name)
		return
	}

	if c.haHold(ctx, h.Name, haSiteRelocate) {
		c.noteHAHeldRecovery(h.Name)
		return
	}
	// Tier-2: restore-from-backup when a restorer is wired and the survivor is
	// schema-compatible.
	if c.Restorer != nil && c.survivorSchemaCompatible(ctx, target) {
		// Mark the SOURCE row first (idempotent; carries the target + a fresh attempt
		// token) so a crash mid-restore is recoverable. The marker is load-bearing
		// for that recovery, so if its write FAILS we must NOT proceed with the
		// restore (an unmarked restore the next tick couldn't re-derive) — defer.
		token := randid.New()
		var claimed *corrosion.ActionProof
		// Split-brain hardening: under active enforcement, mint a durable single-use
		// proof bound to this restore token so RestoreContainer validates + claims it
		// (dest==self + quorum) before importing/recording. Fail-open until cluster-wide.
		if c.gateEnforced(ctx) {
			// Never stamp a proof for a target that doesn't advertise the gate.
			if !c.destAdvertisesGate(ctx, target) {
				slog.Warn("failover: restore-relocation target does not advertise split-brain gate — refusing (fail closed)",
					"container", ct.Name, "target", target)
				c.noteGateRefused(ActionRelocate, health.ReasonUnsupportedCapability)
				c.mCt(ActionRelocate, ResultError, ErrDestUngated)
				return
			}
			leaseHolder, leaseExp, leaseTerm, leaseKey, ok := c.leaseStamp(ctx)
			if !ok {
				c.noteGateRefused(ActionRelocate, health.ReasonStaleLeaseTerm)
				c.mCt(ActionRelocate, ResultError, ErrStaleLeaseTerm)
				c.noteLeaseTermRefusal(ctx, "container", ct.Name, ct.HostName)
				return
			}
			proof := corrosion.ActionProof{
				ID: randid.New(), Action: corrosion.ActionRelocate, TargetKind: "container",
				TargetName: ct.Name, DestHost: target, Coordinator: c.hostName,
				LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
				RelocationToken: token,
				OwnerEpoch:      ownerEpochString(ct.OwnerEpoch),
				LeaseTerm:       leaseTerm, LeaseKey: leaseKey,
			}
			if c.claimsEnforced(ctx) {
				// Claim before mint. One decision covers the whole
				// relocation: if the restore below falls back to
				// image-recreate, the recreate carries THIS proof, token and
				// destination rather than a second, unclaimed one.
				decided, proceed := c.claimContainerRelocation(ctx, h, ct, proof)
				if !proceed {
					return
				}
				if decided.Coordinator != c.hostName {
					// Completing another coordinator's decision: tier-1, as
					// the decided value says. A restore it may have left
					// half-streamed is its to resolve.
					c.imageRecreateOrSkip(ctx, h, ct, decided.DestHost, &decided)
					return
				}
				claimed = &decided
				target, token = decided.DestHost, decided.RelocationToken
			} else if err := corrosion.WriteActionProof(ctx, c.db, proof); err != nil {
				slog.Warn("failover: write restore-relocation proof; deferring", "container", ct.Name, "error", err)
				c.mCt(ActionRelocate, ResultError, ErrDBError)
				return
			}
		}
		if err := corrosion.MarkContainerRelocateRestore(ctx, c.db, h.Name, ct.Name, target, token); err != nil {
			if errors.Is(err, corrosion.ErrWorkloadStopped) {
				c.skipStoppedContainer(ctx, h.Name, ct)
				return
			}
			slog.Warn("failover: failed to mark relocate-restore; deferring relocation to next tick",
				"container", ct.Name, "error", err)
			c.mCt(ActionRelocate, ResultError, ErrDBError)
			return
		}
		// We do NOT pre-create a target row — RestoreContainer refuses an existing
		// row, and a genuinely-failed restore must leave none. The token rides to the
		// target, which stamps it on the restored row so we can prove it's ours.
		switch outcome, err := c.Restorer.RestoreContainerFromBackup(ctx, ct.Name, target, token); outcome {
		case corrosion.RestoreLanded:
			// The target recorded its row (even if a later start errored) — complete
			// the handoff; do NOT image-recreate over a valid restored container.
			c.completeRestore(ctx, h, ct, target)
			return
		case corrosion.RestoreUnknown:
			// Indeterminate: the row MAY have been recorded on the target (the
			// confirmation frame/stream was lost). Destructively falling back could
			// clobber a landed restore — instead leave the relocate-restore marker
			// and let resolvePendingRelocations settle it on a later tick (target row
			// appears ⇒ complete; stale + absent ⇒ image-recreate).
			slog.Warn("failover: container restore outcome indeterminate; leaving marker for the resolve pass",
				"container", ct.Name, "target", target, "error", err)
			c.mCt(ActionRelocate, ResultError, ErrRestoreUnknown)
			return
		default: // RestoreNotAttempted | RestoreFailedBeforeRow → nothing landed
			slog.Warn("failover: container restore not attempted / failed before any row; falling back to image-recreate",
				"container", ct.Name, "target", target, "error", err)
		}
		// Tier-1 fallback under a claim carries the claimed proof.
		c.imageRecreateOrSkip(ctx, h, ct, target, claimed)
		return
	}
	// Tier-1: image-recreate (re-pullable) or skip. RelocateContainer (recreate)
	// soft-deletes the source row, clearing any relocate-restore marker; the skip
	// path replaces the marker with a terminal relocate-skipped detail.
	c.imageRecreateOrSkip(ctx, h, ct, target, nil)
}

// resumeRestoreRelocation re-derives a relocate-restore marker on a re-tick
// (typically after a coordinator restart mid-restore).
func (c *Coordinator) resumeRestoreRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target, token string, candidates []corrosion.HostRecord) {
	// Restore already landed? (crashed after the target row was created but before
	// the source was tombstoned). Require PROVENANCE: the (target,name) row must
	// carry OUR attempt token (the target stamps relocate_token from the marker's
	// token). Names aren't cluster-unique, so a same-name row could otherwise be an
	// unrelated container (operator create / delayed anti-entropy) — completing on
	// that would tombstone the source over it. A token match proves it's our restore.
	if target != "" && token != "" {
		if tgt, _ := corrosion.GetContainer(ctx, c.db, target, ct.Name); tgt != nil && tgt.RelocateToken == token {
			c.completeRestore(ctx, h, ct, target)
			return
		}
	}
	// No target row. Fresh marker → a restore may be in flight; skip to avoid a
	// duplicate. Stale marker → it never completed; fall back to image-recreate.
	if c.markerFresh(ct) {
		return
	}
	slog.Warn("failover: stale relocate-restore marker — falling back to image-recreate",
		"container", ct.Name, "target", target)
	// Under claims the relocation the marker records was decided, and its
	// certificate is on the proof bound to the marker's token: reuse it rather
	// than claim a second relocation (docs/design/recovery-claims.md §9 Q7).
	// A marker whose proof carries no certificate is re-claimed below, which
	// learns whatever was decided.
	var claimed *corrosion.ActionProof
	if token != "" && c.claimsEnforced(ctx) {
		if pr, ok, _ := corrosion.GetActionProofByToken(ctx, c.db, token); ok && pr.ClaimCertificate != "" &&
			pr.TargetName == ct.Name && pr.Action == corrosion.ActionRelocate {
			p := pr.ActionProof
			claimed, target = &p, p.DestHost
		}
	}
	if claimed == nil {
		c.failAbandonedRestoreProof(ctx, ct, token)
	}
	if target == "" {
		var skipped bool
		if target, skipped = c.pickContainerTarget(ctx, ct, candidates); skipped {
			return // marked relocate-skipped, and audited, by the placement refusal
		}
	}
	c.imageRecreateOrSkip(ctx, h, ct, target, claimed)
}

// completeRestore finalizes a successful restore: the target row was created by
// RestoreContainer, so tombstone the dead-host source row to complete the
// (logical, idempotent) handoff — the source host is fenced and won't write again.
func (c *Coordinator) completeRestore(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target string) {
	if err := corrosion.DeleteContainer(ctx, c.db, h.Name, ct.Name); err != nil {
		// The restore itself landed, but the handoff is INCOMPLETE: the dead
		// host's source row is still live next to the target's — a duplicate
		// the scheduler and quota both count. Recording success here would
		// declare the relocation clean while that duplicate exists. Report a
		// partial result instead and DON'T mark the host relocated: the next
		// sweep re-enters this path (the marker and token-matched target row
		// are still in place) and retries the tombstone until it lands.
		slog.Warn("failover: source row tombstone failed after restore — will retry next sweep",
			"container", ct.Name, "from", h.Name, "to", target, "error", err)
		c.mCt(ActionRelocate, ResultPartial, ErrDBError)
		c.audit(ctx, "ct.relocate.restored", ct.Name,
			"restored to "+target+" but the source row on "+h.Name+" is still live (tombstone failed; retrying)", "error")
		return
	}
	c.fenceRelocated[h.Name] = true
	c.mCt(ActionRelocate, ResultSuccess, errClassNone)
	slog.Info("failover: container relocated via restore-from-backup", "container", ct.Name, "from", h.Name, "to", target)
	c.audit(ctx, "ct.relocate.restored", ct.Name, "restored from backup to "+target+" after fencing "+h.Name, "ok")
	c.noteRootfsStranded(ctx, h.Name, ct, target, "backup-restore")
	c.reverseContainerReplication(ctx, h.Name, ct, target)
}

// reverseContainerReplication switches the direction of a relocated container's
// replication schedule when it landed on its own replica target: the host it left
// becomes the target (corrosion.ReverseReplicationOnMove). Never fails the
// relocation; a schedule that cannot be re-pointed is audited as skipped.
func (c *Coordinator) reverseContainerReplication(ctx context.Context, from string, ct corrosion.ContainerRecord, to string) {
	corrosion.ReverseReplicationAudited(ctx, c.db, "container", ct.Name, ct.Project, from, to, func(detail, result string) {
		c.audit(ctx, "replication.reverse", ct.Name, detail, result)
	})
}

// imageRecreateOrSkip is the tier-1 path: recreate from a re-pullable image, else
// skip. The skip leaves the row VISIBLE (for operator recovery) with a terminal
// relocate-skipped detail — which also replaces any relocate-restore marker, so
// the relocate loop won't re-process it.
//
// claimed, when non-nil, is a relocation already decided under a recovery
// claim (the restore it fell back from, or a marker's): the recreate carries
// that proof, token and destination instead of minting another.
func (c *Coordinator) imageRecreateOrSkip(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, target string, claimed *corrosion.ActionProof) {
	// A container with no re-pullable image can't be rebuilt here (its rootfs died
	// with the host) — skip and loudly audit so the operator knows to recover it.
	if !containerImageRepullable(ct.Image) {
		// Keep the row visible; "stopped" reflects that it isn't running anywhere,
		// and the terminal detail stops the relocate loop from re-processing it.
		if err := corrosion.SetContainerStateDetail(ctx, c.db, h.Name, ct.Name, "stopped", corrosion.ContainerRelocateSkippedDetail); err != nil {
			slog.Warn("failover: mark container relocate-skipped", "container", ct.Name, "error", err)
		}
		slog.Warn("failover: container not relocatable (no re-pullable image, no usable backup) — skipping",
			"container", ct.Name, "image", ct.Image, "host", h.Name)
		c.audit(ctx, "ct.relocate.skipped", ct.Name,
			"no re-pullable image and no usable backup after fencing "+h.Name+" (left for operator recovery)", "skipped")
		c.mCt(ActionRelocate, ResultSkipped, ErrNonRepullable)
		return
	}
	// No collision-free target (none available, or the only candidate already runs
	// a same-name container). Skip — leave the source visible; recreating would
	// either have nowhere to go or clobber an unrelated container. Mark terminal so
	// it doesn't loop (and so any relocate-restore marker is cleared, not left for
	// the resolve pass to misread against an unrelated target row).
	if target == "" || c.targetHasLiveContainer(ctx, target, ct.Name) {
		if err := corrosion.SetContainerStateDetail(ctx, c.db, h.Name, ct.Name, "stopped", corrosion.ContainerRelocateSkippedDetail); err != nil {
			slog.Warn("failover: mark container relocate-skipped", "container", ct.Name, "error", err)
		}
		slog.Warn("failover: no collision-free target for container relocation — skipping",
			"container", ct.Name, "target", target, "host", h.Name)
		c.audit(ctx, "ct.relocate.skipped", ct.Name,
			"no collision-free relocation target after fencing "+h.Name+" (left for operator recovery)", "skipped")
		c.mCt(ActionRelocate, ResultSkipped, ErrNoCandidates)
		return
	}
	// Split-brain hardening (Phase 1): under active enforcement, mint a durable
	// single-use proof bound to a relocation token and stamp the token on the
	// re-keyed row, so the target claims it by token before recreating. Fail-open
	// (empty token, no proof) until split_brain_gate_v1 is cluster-wide.
	if c.haHold(ctx, h.Name, haSiteRecreate) {
		c.noteHAHeldRecovery(h.Name)
		return
	}
	relocToken := ""
	if claimed != nil {
		// Already decided and written: re-key to exactly what was decided.
		target, relocToken = claimed.DestHost, claimed.RelocationToken
	} else if c.gateEnforced(ctx) {
		// Never stamp a proof for a target that doesn't advertise the gate.
		if !c.destAdvertisesGate(ctx, target) {
			slog.Warn("failover: relocation target does not advertise split-brain gate — refusing (fail closed)",
				"container", ct.Name, "target", target)
			c.noteGateRefused(ActionRelocate, health.ReasonUnsupportedCapability)
			c.mCt(ActionRelocate, ResultError, ErrDestUngated)
			return
		}
		leaseHolder, leaseExp, leaseTerm, leaseKey, ok := c.leaseStamp(ctx)
		if !ok {
			c.noteGateRefused(ActionRelocate, health.ReasonStaleLeaseTerm)
			c.mCt(ActionRelocate, ResultError, ErrStaleLeaseTerm)
			c.noteLeaseTermRefusal(ctx, "container", ct.Name, ct.HostName)
			return
		}
		relocToken = randid.New()
		proof := corrosion.ActionProof{
			ID: randid.New(), Action: corrosion.ActionRelocate, TargetKind: "container",
			TargetName: ct.Name, DestHost: target, Coordinator: c.hostName,
			LeaseHolder: leaseHolder, LeaseExpiresAt: leaseExp,
			RelocationToken: relocToken,
			OwnerEpoch:      ownerEpochString(ct.OwnerEpoch),
			LeaseTerm:       leaseTerm, LeaseKey: leaseKey,
		}
		if c.claimsEnforced(ctx) {
			decided, proceed := c.claimContainerRelocation(ctx, h, ct, proof)
			if !proceed {
				return
			}
			target, relocToken = decided.DestHost, decided.RelocationToken
			if c.targetHasLiveContainer(ctx, target, ct.Name) {
				slog.Warn("failover: the decided relocation target already holds a same-name container — left for operator recovery",
					"container", ct.Name, "target", target)
				c.mCt(ActionRelocate, ResultSkipped, ErrNoCandidates)
				return
			}
		} else if err := corrosion.WriteActionProof(ctx, c.db, proof); err != nil {
			slog.Error("failover: write relocation proof", "container", ct.Name, "error", err)
			c.mCt(ActionRelocate, ResultError, ErrDBError)
			return
		}
	}
	if err := corrosion.RelocateContainerWithToken(ctx, c.db, h.Name, ct.Name, target, relocToken); err != nil {
		if errors.Is(err, corrosion.ErrWorkloadStopped) {
			// Stopped after it was chosen: the stop wins.
			c.skipStoppedContainer(ctx, h.Name, ct)
			return
		}
		// Includes the no-clobber guard (a same-name container appeared on the
		// target since the check above) — never lose the source.
		slog.Error("failover: relocate container (image-recreate)", "container", ct.Name, "error", err)
		c.mCt(ActionRelocate, ResultError, ErrRelocateFailed)
		return
	}
	c.fenceRelocated[h.Name] = true
	c.mCt(ActionRelocate, ResultSuccess, errClassNone)
	slog.Info("failover: relocating container (image-recreate)", "container", ct.Name, "from", h.Name, "to", target)
	c.audit(ctx, "ct.relocate.recreate", ct.Name,
		"relocated from "+h.Name+" to "+target+" (recreate from image)", "ok")
	c.noteRootfsStranded(ctx, h.Name, ct, target, "image-recreate")
	c.reverseContainerReplication(ctx, h.Name, ct, target)
}

// pickContainerTarget chooses a survivor via the placement engine, falling back
// to round-robin over the candidate list. It skips any host that already runs a
// LIVE container of the same name (names aren't cluster-unique), so relocation
// never collides with / clobbers an unrelated container. Returns "" if no
// collision-free target exists, with skipped=true when that refusal already
// marked the container relocate-skipped (no host has a container runtime).
func (c *Coordinator) pickContainerTarget(ctx context.Context, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord) (target string, skipped bool) {
	// A container replicated on a schedule that allows auto-promote is restored
	// where its replica is, so the data is already there: place it on that host
	// when it is a healthy candidate and placement accepts it, and only then fall
	// back to placement over every candidate.
	if rh := c.containerReplicaHost(ctx, ct, candidates); rh != "" {
		req := c.containerPlacementRequest(ct)
		req.PinHost = rh
		if t, perr := placement.Select(ctx, c.db, req); perr == nil && t == rh && !c.targetHasLiveContainer(ctx, t, ct.Name) {
			return t, false
		}
	}

	// The single-VM Select path carries the full capacity model (observations,
	// reserves, incomplete-host exclusion). There is deliberately NO
	// round-robin fallback on its failure: the old one walked the raw healthy
	// candidate list — blind to capacity and to incomplete-inventory exclusions
	// — so a container that genuinely fit nowhere was relocated somewhere it
	// did not fit. "" tells the caller to skip loudly and leave the row for
	// operator recovery instead.
	target, err := placement.Select(ctx, c.db, c.containerPlacementRequest(ct))
	if err != nil {
		if c.skippedNoContainerRuntime(ctx, ct, err) {
			return "", true
		}
		slog.Warn("failover: container placement failed — left for operator recovery, NOT round-robined",
			"container", ct.Name, "error", err)
		return "", false
	}
	if c.targetHasLiveContainer(ctx, target, ct.Name) {
		// The chosen host already runs an unrelated container of this name
		// (names are per-host). Rare; skip rather than blind-pick elsewhere.
		slog.Warn("failover: container relocation target holds a same-name container — left for operator recovery",
			"container", ct.Name, "target", target)
		return "", false
	}
	return target, false
}

// targetHasLiveContainer reports whether host already runs a live (non-deleted)
// container of the given name — a relocation collision (names are PK'd by
// (host_name,name), so the same name can legitimately exist on another host).
func (c *Coordinator) targetHasLiveContainer(ctx context.Context, host, name string) bool {
	r, err := corrosion.GetContainer(ctx, c.db, host, name)
	return err == nil && r != nil
}

// survivorSchemaCompatible reports whether the survivor is at least as new as
// this coordinator's schema, so it fully supports the restore/create_spec path. A
// behind survivor (mid rolling-upgrade) or unknown schema → fall back to
// image-recreate (graceful; restore-failure also falls back regardless).
func (c *Coordinator) survivorSchemaCompatible(ctx context.Context, target string) bool {
	hr, err := corrosion.GetHost(ctx, c.db, target)
	if err != nil || hr == nil {
		return false
	}
	return hr.SchemaVersion >= corrosion.CurrentSchemaVersion
}

// markerFresh reports whether a relocate-restore marker is still within the
// in-flight window (a restore might still be running).
func (c *Coordinator) markerFresh(ct corrosion.ContainerRecord) bool {
	to := c.RelocateRestoreTimeout
	if to <= 0 {
		to = defaultRelocateRestoreTimeout
	}
	t, ok := corrosion.ParseUpdatedAt(ct.UpdatedAt)
	if !ok {
		return true // unparseable → conservatively treat as fresh (avoid double-restore)
	}
	return c.now().Sub(t) < to
}

// audit records one coordinator action on this host's audit chain.
//
// It is the coordinator's only audit write, and it writes through c.db, which is
// the daemon's client: that client carries the host's signing keyring, so every
// row lands signed when signing is on. Keep it the only one —
// TestAuditWriters_EveryCallSiteIsCovered fails on a new InsertAuditLog call
// site until it is listed there with a test proving its rows are signed.
func (c *Coordinator) audit(ctx context.Context, action, target, detail, result string) {
	_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
		ID: randid.New(), Username: "failover-coordinator", HostName: c.hostName,
		Action: action, Target: target, Detail: detail, Result: result,
	})
}

// containerImageRepullable reports whether a container's image origin can be
// re-pulled to rebuild its rootfs on another host (an OCI/registry ref or a
// download-template ref). An empty image (e.g. a hand-built rootfs) can't.
func containerImageRepullable(image string) bool {
	if image == "" {
		return false
	}
	// oci://… , docker.io/…:tag , alpine:3.19 — anything with a registry scheme
	// or a name:tag form is re-pullable. A bare path / empty is not.
	return strings.Contains(image, "://") || strings.Contains(image, ":") || strings.Contains(image, "/")
}

// healthyHosts returns active hosts excluding the failed host.
func (c *Coordinator) healthyHosts(ctx context.Context, excludeHost string) ([]corrosion.HostRecord, error) {
	all, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return nil, err
	}
	var out []corrosion.HostRecord
	for _, h := range all {
		if h.Name != excludeHost && h.State == "active" {
			out = append(out, h)
		}
	}
	return out, nil
}

// pitOverlaySafeTargets is candidates without the hosts a VM must not be
// restarted on once the pit_overlay release feature is in use (P2 of the
// #256 re-review 5). A host recorded as isolated — rolled back below a latched
// token and WAL-quarantined, or isolated by an operator — or one whose own Ping
// says it is WAL-quarantined, or that does not answer
// (PeerRecoveryExclusions: from the rollback's first answer, cycles before the
// HA monitor records the isolation) may run a build that
// knows nothing of point-in-time overlays: it would define the VM on the bare
// disk and drop the writes an overlay on a shared pool still holds. Before the
// feature is used no overlay exists, and nothing is filtered: recovery is
// exactly as it was. Containers keep the full list (they have no overlays).
// The batch placement and the check of an adopted claim's destination
// (vmFitsOn) both apply it.
func (c *Coordinator) pitOverlaySafeTargets(ctx context.Context, candidates []corrosion.HostRecord) []corrosion.HostRecord {
	info, _ := capabilities.LookupFeature(capabilities.FeaturePITOverlay)
	used, err := corrosion.ReleaseFeatureUsed(ctx, c.db, info.Token, string(capabilities.FeaturePITOverlay))
	if err == nil && !used {
		return candidates
	}
	var excluded map[string]string
	if c.PeerRecoveryExclusions != nil {
		peers := make([]string, 0, len(candidates))
		for _, h := range candidates {
			if h.Name != c.hostName {
				peers = append(peers, h.Name)
			}
		}
		excluded = c.PeerRecoveryExclusions(ctx, peers)
	}
	out := make([]corrosion.HostRecord, 0, len(candidates))
	for _, h := range candidates {
		epoch, reason, ierr := corrosion.HostIsolation(ctx, c.db, h.Name)
		if ierr == nil && epoch == 0 {
			why, bad := excluded[h.Name]
			if !bad || h.Name == c.hostName {
				out = append(out, h)
				continue
			}
			reason = why
		}
		slog.Warn("failover: not restarting VMs on this host while point-in-time overlays are in use; it is isolated, WAL-quarantined or did not answer, and may not understand them",
			"host", h.Name, "reason", reason, "error", ierr)
	}
	return out
}

// heldCause is why an automatic promotion was held, for the log, the audit and
// the shared-disk event: a replica on a witness is told apart from the
// default, a replica that is not point-in-time.
func heldCause(err error) string {
	if errors.Is(err, corrosion.ErrReplicaOnWitness) {
		return "the only replica is on a witness, which runs no workloads, so the VM cannot be started there"
	}
	return "the only replica is not point-in-time"
}

// heldSteps is the operator's way forward for a hold whose steps are two:
// for a replica on a witness, promote it there by hand (it is left defined and
// stopped), then move it to a worker.
func heldSteps(err error) string {
	if errors.Is(err, corrosion.ErrReplicaOnWitness) {
		return "; promote it by hand with `lv replication promote <vm> --host <witness> ...`, then `lv migrate <vm> <worker> --cold` and `lv start <vm>`"
	}
	return ""
}

// holdsDown reports whether a VM whose automatic promotion was held stays
// down rather than falling back to a reschedule: any disk that is not on
// shared storage (or disks that cannot be read) holds it. A VM whose disks
// are all shared is rescheduled as before — restarting from its own live disk
// beats any replica — and an event says so.
func (c *Coordinator) holdsDown(ctx context.Context, vm corrosion.VMRecord, cause string) bool {
	disks, err := corrosion.GetVMDisks(ctx, c.db, vm.Name)
	if err != nil || len(disks) == 0 || corrosion.VMHasHostLocalDisk(disks) {
		return true
	}
	detail := "automatic promotion held (" + cause + "); every disk is on shared storage, so the VM is restarted from its own disk instead"
	if ierr := corrosion.InsertVMEvent(ctx, c.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm.Name, HostName: c.hostName, Type: "vm.failover.restart_shared",
		Result: "ok", Severity: "warn", Detail: detail, Username: "failover-coordinator",
	}); ierr != nil {
		slog.Warn("failover: record the shared-disk restart event", "vm", vm.Name, "error", ierr)
	}
	return false
}

// vmNeedsFailover reports whether this VM is one the coordinator would ever try
// to move off a dead host.
//
// It answers only the PERMANENT question — is this workload a failover candidate
// at all — and deliberately not "can it move right now", which depends on
// quorum, gates, candidate hosts and this coordinator's lease term. A VM this
// returns false for stays on its dead host by design.
//
// Auto-promotion is checked by the caller, not here: the reschedule loop reaches
// AutoPromoteReplica BEFORE it consults on_host_failure, so a VM enrolled in
// replication with the default policy of "none" is still recoverable — by
// promotion rather than reschedule.
func vmNeedsFailover(vm corrosion.VMRecord, autoPromote bool) bool {
	return corrosion.VMRecoverableOnHostFailure(vm, autoPromote)
}

// containerNeedsFailover is the container half of vmNeedsFailover.
func containerNeedsFailover(ct corrosion.ContainerRecord) bool {
	return corrosion.ContainerRecoverableOnHostFailure(ct)
}

// strandedByHost counts, per host in state 'fenced' or 'offline', the workloads
// still assigned to it that the coordinator would move off a dead host; a host
// with none is absent.
//
// It measures exactly that and claims nothing more. It is NOT a count of
// post-fence refusals, and the difference matters because the two sets are not
// the same. A refusal inside recoverWorkloads does land here — the host is
// already marked down when the refusal happens. But three ordinary paths reach
// those states with their workloads intact and no refusal anywhere:
//
//   - `lv host fence` marks a host 'offline' unconditionally and never
//     enumerates workloads (see FenceHost's own comment), so it counts a live
//     host's VMs until recoverHosts clears the state.
//   - `lv host fence-confirm` writes 'fenced' on any host with no precondition.
//   - failover itself writes 'offline' and RETURNS above recoverWorkloads when a
//     safe-fence or manual fence is unconfirmed, or the fence failed. For a
//     manual-strategy host that is a documented NORMAL state, awaiting an
//     operator's confirmation — and it is the likeliest real non-zero.
//
// So a non-zero value means "workloads are sitting on a host the cluster
// considers down", which is worth an operator's attention however it arose, and
// the remedy depends on which of the above it is. docs/operating-model.md
// branches on that; a blanket `lv host undrain` is wrong for the third case,
// where the fence was never confirmed and undraining is the split-brain move the
// gate refused to make.
//
// Two limits are inherent to deriving this from hosts.state. A host whose state
// write failed after a successful fence is invisible here even with work
// stranded on it (the write logs and does not return, by design, so the fence
// still counts). And a workload counted here may have an owner: containers with
// a live relocate-restore marker are excluded for that reason, but a VM the
// operator is restoring by hand is not distinguishable.
//
// It REPORTS and does not act. Every refusal inside recoverWorkloads happens
// after the fence, because the checks that can refuse are deliberately as late
// as possible — they close races, and moving them earlier would make them staler
// than the writes they guard. That window is structural and cannot be reordered
// away. Automatic recovery from it was attempted and withdrawn: acting safely
// requires proving the host was POWERED OFF, and no evidence available to a
// coordinator supports that. hosts.state records only that somebody decided it,
// while health quorum proves unreachability — equally true of a partitioned host
// still running its VMs. Evacuating on either produces two writers on one disk.
// Proving it needs a fence proof bound to the current outage, which the schema
// does not carry today. Until it does, this surfaces the condition in seconds
// instead of whenever somebody notices VMs are down, and the recovery stays a
// decision an operator makes with commands they already have.
//
// Returns an error rather than a partial count: a number the caller publishes as
// a gauge must be measured, not guessed. A read failure leaves the previous
// value in place and reports through the error metric instead, because "0"
// during a store outage is the all-clear on the one signal an operator alerts on.
func (c *Coordinator) strandedByHost(ctx context.Context) (map[string]int, error) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return nil, err
	}
	// Read ONCE per cycle, not once per down host: ListBackupSchedules has no
	// host or vm_name predicate (a full scan), and the map it builds is keyed by
	// VM name across the whole fleet, so it is byte-identical for every host.
	enrolled, err := c.autoPromoteEnrolled(ctx)
	if err != nil {
		return nil, err
	}
	total := map[string]int{}
	for _, h := range hosts {
		if h.State != "fenced" && h.State != "offline" {
			continue
		}
		n, err := c.strandedOn(ctx, h.Name, enrolled)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			total[h.Name] = n
		}
	}
	return total, nil
}

// strandedOn counts the recoverable workloads still recorded on host
// (strandedByHost's per-host count).
func (c *Coordinator) strandedOn(ctx context.Context, host string, enrolled map[string]bool) (int, error) {
	names, err := c.strandedNamesOn(ctx, host, enrolled)
	return len(names), err
}

// strandedNamesOn names strandedOn's workloads: "vm/<name>" and
// "container/<name>".
func (c *Coordinator) strandedNamesOn(ctx context.Context, host string, enrolled map[string]bool) ([]string, error) {
	var names []string
	vms, err := corrosion.ListVMs(ctx, c.db, "", host)
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		if vmNeedsFailover(vm, enrolled[vm.Name]) {
			// A VM that stopped without anyone asking is recovered only on
			// shared storage; with a host-local disk it stays by design
			// (recoverWorkloads), so it is not stranded.
			if vm.State == "stopped" {
				disks, derr := corrosion.GetVMDisks(ctx, c.db, vm.Name)
				if derr != nil {
					return nil, derr
				}
				if corrosion.VMHasHostLocalDisk(disks) {
					continue
				}
			}
			names = append(names, "vm/"+vm.Name)
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, host)
	if err != nil {
		return nil, err
	}
	for _, ct := range cts {
		if containerNeedsFailover(ct) {
			names = append(names, "container/"+ct.Name)
		}
	}
	return names, nil
}

// heldNamesNote is ", held: <names>" for the stall alert of host, at most
// heldNamesMax of them; "" when they cannot be read.
func (c *Coordinator) heldNamesNote(ctx context.Context, host string) string {
	enrolled, err := c.autoPromoteEnrolled(ctx)
	if err != nil {
		return ""
	}
	names, err := c.strandedNamesOn(ctx, host, enrolled)
	if err != nil || len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	more := ""
	if len(names) > heldNamesMax {
		more = fmt.Sprintf(" and %d more", len(names)-heldNamesMax)
		names = names[:heldNamesMax]
	}
	return "; held: " + strings.Join(names, ", ") + more
}

// heldNamesMax bounds the workloads one stall alert names.
const heldNamesMax = 20

// withHeldClaimRetries adds to byHost, for the stall alert only, each host
// whose owed claim retry is held because it is neither fenced nor offline
// (claimRetryHeld) and that is a fence candidate this cycle, with the
// workloads still recorded on it. Such a host is
// not counted as stranded (strandedByHost), but its hold must still reach an
// operator. A read error leaves the host out for this cycle.
func (c *Coordinator) withHeldClaimRetries(ctx context.Context, byHost map[string]int) map[string]int {
	if len(c.claimRetryHeld) == 0 {
		return byHost
	}
	enrolled, err := c.autoPromoteEnrolled(ctx)
	if err != nil {
		return byHost
	}
	out := make(map[string]int, len(byHost)+len(c.claimRetryHeld))
	for h, n := range byHost {
		out[h] = n
	}
	for host := range c.claimRetryHeld {
		// Only while a quorum still fails it: a held host that answers is up
		// and runs its own workloads.
		if _, ok := out[host]; ok || !c.cycleCandidates[host] {
			continue
		}
		if n, err := c.strandedOn(ctx, host, enrolled); err == nil && n > 0 {
			out[host] = n
		}
	}
	return out
}

// autoPromoteEnrolled is every VM with an auto-promote replication schedule.
// The c.Promoter guard mirrors the reschedule loop's, so a VM is treated as
// promotable exactly when that loop would try to promote it.
func (c *Coordinator) autoPromoteEnrolled(ctx context.Context) (map[string]bool, error) {
	enrolled := map[string]bool{}
	if c.Promoter == nil {
		return enrolled, nil
	}
	rows, err := corrosion.ListBackupSchedules(ctx, c.db)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Type == "replication" && r.AutoPromote {
			enrolled[r.VMName] = true
		}
	}
	return enrolled, nil
}

// vmFailurePolicy extracts on_host_failure from a VM's spec JSON.
func vmFailurePolicy(vm corrosion.VMRecord) string { return corrosion.VMFailurePolicy(vm) }

// vmUsesFirmwareState reports whether a VM uses Secure Boot or a vTPM — i.e. has
// host-local firmware state (NVRAM + swtpm) that can't survive its host dying (G1).
func vmUsesFirmwareState(vm corrosion.VMRecord) bool { return corrosion.VMUsesFirmwareState(vm) }

// containerReplicaHost is the host holding the replica of ct that a failover may
// promote: the target of its enabled, auto-promote, container-scoped replication
// schedule, when that host is one of the healthy candidates. "" when ct is not
// replicated that way, or no restorer is wired to use a replica.
func (c *Coordinator) containerReplicaHost(ctx context.Context, ct corrosion.ContainerRecord, candidates []corrosion.HostRecord) string {
	if c.Restorer == nil {
		return ""
	}
	rows, err := corrosion.ListBackupSchedules(ctx, c.db)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if r.Type != "replication" || !r.Enabled || !r.AutoPromote || r.TargetHost == "" ||
			!corrosion.ContainerScheduleIs(r, ct.Project, ct.Name) {
			continue
		}
		for _, h := range candidates {
			if h.Name == r.TargetHost {
				return r.TargetHost
			}
		}
	}
	return ""
}
