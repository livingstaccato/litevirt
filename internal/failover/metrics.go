package failover

// Metrics is the optional, nil-safe observability sink for the failover
// coordinator. It is defined here (not imported from internal/metrics) so the
// failover package stays free of a Prometheus dependency and tests can use a
// trivial fake. *metrics.FailoverMetrics satisfies it structurally.
type Metrics interface {
	// Attempt records a decision point: a failover phase reaching a result,
	// optionally with a bounded error class.
	Attempt(phase, result, errorClass string)
	// VMAction records a per-VM failover action outcome (promote, reschedule).
	VMAction(action, result, errorClass string)
	// ContainerAction records a per-container failover action outcome (relocate).
	ContainerAction(action, result, errorClass string)
	// StrandedWorkloads reports how many workloads are still assigned to a host
	// in state 'fenced' or 'offline' that failover would move off a dead host. A
	// GAUGE, not a counter: it is a current condition an operator resolves, not
	// an event rate.
	//
	// It is the LEASE HOLDER's view — every node calls this, and a node that is
	// not driving failover reports 0 (see stepDownGauges), so a fleet-wide alert
	// must take the max across instances or join on litevirt_failover_leader
	// rather than averaging. Zero is the normal value; a sustained non-zero needs
	// a human, and what they should do depends on WHY the host is down — see
	// strandedWorkloads.
	StrandedWorkloads(n int)
	// RegionsWithoutQuorum reports how many regions hold at least one worker
	// but have fewer than corrosion.MinRegionVoters voters, so cannot fence
	// one of their own hosts while failover is region-scoped. A GAUGE, the
	// lease holder's view like StrandedWorkloads; 0 under the cluster scope.
	RegionsWithoutQuorum(n int)
}

// Phases, results, actions, and error classes are a CLOSED vocabulary kept as
// constants so a typo can't mint a stray Prometheus series and the label
// cardinality stays bounded (a few × a few × a few).
const (
	PhaseLease      = "lease"
	PhaseQuorum     = "quorum"
	PhaseHealth     = "health-query"
	PhaseSkip       = "skip"
	PhaseFence      = "fence"
	PhaseSplitBrain = "split-brain-guard"
	PhaseRecovery   = "recovery"
	// PhaseClaim is a recovery claim (docs/design/recovery-claims.md §5.4):
	// the certificate a reschedule, promote or relocate needs before it is
	// minted. Its results are ok, lost, no_majority, owner_reachable,
	// source_mismatch and superseded.
	PhaseClaim = "claim"

	ResultOK        = "ok"
	ResultSkipped   = "skipped"
	ResultSuccess   = "success"
	ResultPartial   = "partial"
	ResultRefused   = "refused"
	ResultError     = "error"
	ResultRecovered = "recovered"
	// Claim results (PhaseClaim).
	ResultLost           = "lost"            // another value was decided for the key
	ResultNoMajority     = "no_majority"     // no majority promised or accepted
	ResultOwnerReachable = "owner_reachable" // voters reached the recorded owner and refused
	ResultSourceMismatch = "source_mismatch" // voters' settled row names another owner
	ResultSuperseded     = "superseded"      // the key moved to attempt+1 on supersede evidence

	ActionPromote    = "promote"
	ActionReschedule = "reschedule"
	ActionRelocate   = "relocate"

	// errClassNone is the empty error class (a clean outcome).
	errClassNone = ""

	ErrNoQuorum        = "no_quorum"
	ErrDestUngated     = "dest_ungated" // target no longer advertises the split-brain gate
	ErrSelfFenced      = "self_fenced"  // this coordinator self-fenced; skips driving failover until reboot
	ErrLeaseLost       = "lease_lost"
	ErrStaleLeaseTerm  = "stale_lease_term" // still named holder locally, but a peer's term has superseded ours
	ErrNotLeader       = "not_leader"
	ErrTerminalState   = "terminal_state"
	ErrAlreadyFenced   = "already_fenced"
	ErrUpgrading       = "upgrading"
	ErrRecentlyFenced  = "recently_fenced"
	ErrRecoveryResumed = "recovery_resumed" // recovery picked up from a fence a previous leader recorded
	// ErrRefenceFailed: a successor re-fenced a host whose recorded verified
	// fence was aged or in doubt, the re-fence failed, and the recovery was
	// left for an operator's `lv host fence-confirm`.
	ErrRefenceFailed = "refence_failed"
	// recovery picked up from an operator confirmation of a host whose recovery
	// was refused for lack of one
	ErrConfirmationResumed = "confirmation_resumed"
	ErrFirmwareState       = "firmware_state_missing"
	ErrPolicyNone          = "policy_none"
	ErrNoCandidates        = "no_candidates"
	ErrPlacementFailed     = "placement_failed"
	ErrFenceFailed         = "fence_failed"
	ErrManualUnconfirmed   = "manual_unconfirmed"
	ErrBestEffort          = "best_effort"
	ErrManualConfirmed     = "manual_confirmed"
	ErrNonRepullable       = "non_repullable_image"
	ErrDBError             = "db_error"
	ErrFenceLogWrite       = "fence_log_write_failed"
	ErrPromoteFailed       = "promote_failed"
	ErrStorageUnverified   = "storage_unverified" // shared-disk transfer with no proof-grade fence
	ErrRelocateFailed      = "relocate_failed"
	ErrOwnershipDispute    = "ownership_dispute" // active ownership condition on the workload; recovery refused
	ErrRestoreUnknown      = "restore_unknown"
	// ErrLocalStall: quorum agreed a host failed, but this coordinator itself
	// stopped running within health.StallGrace, so the fence is deferred.
	ErrLocalStall = "local_stall"
	// ErrRegionTooSmall: under region-scoped failover, a host the cluster-wide
	// count would fence was not, because its region has too few voters to
	// fence one of its own.
	ErrRegionTooSmall = "region_too_small"
	// ErrRegionScoped: under region-scoped failover, a host the cluster-wide
	// count would fence was not, because the observations came from voters
	// outside its region. A site partition looks like this.
	ErrRegionScoped = "region_scoped"
	// ErrClaimStranded: a recovery claim decided a destination that has since
	// failed before acting; the workload waits for it to return or be removed
	// for good (`lv host rm --dead`).
	ErrClaimStranded = "recovery_claim_stranded"
	// ErrPartitionPauseWait: a best-effort fence did not reach the host and
	// the coordinator relies on its partition pause, so recovery waits out
	// health.PartitionPauseWaitFor (docs/design/partition-pause.md §4).
	ErrPartitionPauseWait = "partition_pause_wait"
	// ErrQuorumRegain: quorum agreed a host failed, but this coordinator was
	// itself cut off from the majority within health.QuorumRegainGrace.
	ErrQuorumRegain = "quorum_regain"
	// ErrConfirmationFence: an operator confirmed a host off during the outage
	// in progress and no fence had run for it, so the coordinator fenced it
	// afresh rather than leaving it terminal with nothing to fence it.
	ErrConfirmationFence = "confirmation_fence"
)

// nil-safe wrappers so the coordinator can increment unconditionally.
func (c *Coordinator) mAttempt(phase, result, errClass string) {
	if c.Metrics != nil {
		c.Metrics.Attempt(phase, result, errClass)
	}
}

func (c *Coordinator) mVM(action, result, errClass string) {
	if c.Metrics != nil {
		c.Metrics.VMAction(action, result, errClass)
	}
}

func (c *Coordinator) mCt(action, result, errClass string) {
	if c.Metrics != nil {
		c.Metrics.ContainerAction(action, result, errClass)
	}
}

// mStranded reports the stranded-workload gauge (nil-safe, like the rest).
func (c *Coordinator) mStranded(n int) {
	if c.Metrics != nil {
		c.Metrics.StrandedWorkloads(n)
	}
}

// mRegionsWithoutQuorum reports the regions-without-quorum gauge (nil-safe).
func (c *Coordinator) mRegionsWithoutQuorum(n int) {
	if c.Metrics != nil {
		c.Metrics.RegionsWithoutQuorum(n)
	}
}
