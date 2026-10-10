package failover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/placement"
)

// Recovery claims at the mint sites (docs/design/recovery-claims.md §3.13,
// colonelpanik/litevirt#250).
//
// Under recovery_claim_v1 a coordinator does not mint an ownership-transfer
// proof on its own authority. It proposes the proof as the value of a claim
// keyed by (kind, name, owner_epoch, attempt) — and, once claim_incarnation_v1
// has latched, by the workload row's incarnation (its created_at), so a
// workload re-created under the same name never meets the decision of the one
// before it (docs/design/recovery-claims.md §10 item 37) — and writes a proof only once a
// majority of the voter set has signed an accept for one value: its own, or —
// when another coordinator got there first — the other one's, which it
// re-materializes byte for byte and which names the other destination. The
// loser of a duel therefore writes no pending row and no proof naming itself,
// and two coordinators that each believe they hold the lease can never both
// authorize a destination.

// claimTimeout bounds one claim (§3.13 step 3). It leaves room for one
// claimProbeTimeout inside phase 2.
const claimTimeout = 5 * time.Second

// RecoveryClaimer decides recovery claims. *grpcapi.Server implements it: its
// proposer reaches every member of the adopted voter generation over the claim
// RPCs, and its own voter directly.
type RecoveryClaimer interface {
	// DecideRecoveryClaim drives one claim; ev is the supersede evidence a
	// key past attempt 0 needs (§3.12).
	DecideRecoveryClaim(ctx context.Context, key corrosion.ClaimKey, proposal corrosion.ClaimValue, startRound uint64, ev *corrosion.SupersedeEvidence) (claims.Outcome, error)
	// RequestAbandonment asks host to sign that it has not executed, and never
	// will, proofID at key, returning the encoded abandonment.
	RequestAbandonment(ctx context.Context, host string, key corrosion.ClaimKey, proofID, reason string) (string, error)
	// ClaimKeyFor is the attempt-0 key a recovery of the workload row whose
	// created_at is incarnation, leaving owner epoch epoch, is claimed under
	// here: scoped to the incarnation once claim_incarnation_v1 has latched,
	// the legacy key before (§10 item 37).
	ClaimKeyFor(ctx context.Context, kind, name string, epoch int64, incarnation string) corrosion.ClaimKey
	// RequestForeignAbandonment asks host to sign, from its own database,
	// that proofID is not the decision of the incarnation key names and will
	// never run (corrosion.AbandonForeignProof), returning the encoded
	// abandonment. It refuses whatever host cannot show.
	RequestForeignAbandonment(ctx context.Context, host string, key corrosion.ClaimKey, proofID, reason string) (string, error)
	// NoteLegacyHeld (re-)raises ha.claim.legacy_held for key's workload,
	// held behind the decided value v. Idempotent: it writes nothing while
	// the condition is already open for that decision.
	NoteLegacyHeld(ctx context.Context, key corrosion.ClaimKey, v corrosion.ClaimValue, why string)
}

// maxClaimAttempts bounds how far one claimRecovery walks a key's attempts.
// Each step needs supersede evidence, so a real key rarely passes 1.
const maxClaimAttempts = 8

// claimsEnforced is the enforcement predicate, read from the server so the
// coordinator and the executors on one node cannot disagree about it: the
// flag AND the recovery_claim_v1 latch AND an adopted voter generation.
func (c *Coordinator) claimsEnforced(ctx context.Context) bool {
	return c.RecoveryClaimEnforced != nil && c.RecoveryClaimEnforced(ctx)
}

// ClaimRefusedError is a claim that formed no certificate, with the gate
// refusal reason it is counted under and every refusing voter's detail.
type ClaimRefusedError struct {
	Key    corrosion.ClaimKey
	Reason string // health.ReasonClaim*
	Result string // PhaseClaim result
	Detail string
	Err    error
}

func (e *ClaimRefusedError) Error() string {
	return fmt.Sprintf("claim %s: %s: %s", e.Key, e.Reason, e.Detail)
}

func (e *ClaimRefusedError) Unwrap() error { return e.Err }

// classifyClaimError names why a claim formed no certificate (§5.4). An
// owner-probe refusal from any voter wins over the rest, because it is the
// one that says the source is UP — nothing is contending, and the operator
// needs to know which voters still reach it.
func classifyClaimError(key corrosion.ClaimKey, err error) *ClaimRefusedError {
	out := &ClaimRefusedError{Key: key, Reason: health.ReasonClaimNoMajority, Result: ResultNoMajority,
		Detail: err.Error(), Err: err}
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) {
		return out
	}
	var owner, mismatch []string
	for _, r := range nm.Refusals {
		switch r.Reason {
		case corrosion.RefusalOwnerReachable:
			owner = append(owner, r.Detail)
		case corrosion.RefusalSourceMismatch:
			mismatch = append(mismatch, r.Detail)
		}
	}
	switch {
	case len(owner) > 0:
		sort.Strings(owner)
		out.Reason, out.Result = health.ReasonClaimOwnerReachable, ResultOwnerReachable
		out.Detail = strings.Join(owner, "; ")
	case len(mismatch) > 0:
		sort.Strings(mismatch)
		out.Reason, out.Result = health.ReasonClaimSourceMismatch, ResultSourceMismatch
		out.Detail = strings.Join(mismatch, "; ")
	}
	return out
}

// claimedProof is the outcome of claiming one proof: the proof to write — ours,
// or the decided value someone else proposed — with its certificate.
type claimedProof struct {
	Proof corrosion.ActionProof
	Key   corrosion.ClaimKey
	Ours  bool
}

// claimRecovery runs one claim for proposal, a fully built proof this
// coordinator would otherwise mint, whose owner being left is source, for the
// incarnation of the workload row it was built from (that row's created_at).
//
// It never falls back to an uncertified proof: without a certificate it
// returns a *ClaimRefusedError and the caller mints nothing (§3.13 step 6).
//
// A key's attempt starts at 0 and moves on only past a decided value whose
// destination provably will never execute it (§3.12): this coordinator's own
// promote that failed before StartDomain, abandoned by its destination, or a
// value decided for a destination that has since been removed for good. Each
// step carries the evidence, and every voter checks it before it promises.
func (c *Coordinator) claimRecovery(ctx context.Context, proposal corrosion.ActionProof, source, incarnation string) (claimedProof, error) {
	return c.claimRecoveryFor(ctx, proposal, source, incarnation, nil)
}

// claimRecoveryFor is claimRecovery with fits, the site's own placement check
// of a destination this coordinator did not pick (nil: none beyond the host
// checks every site gets). See adoptedDestProblem.
func (c *Coordinator) claimRecoveryFor(ctx context.Context, proposal corrosion.ActionProof, source, incarnation string,
	fits func(corrosion.HostRecord) string) (claimedProof, error) {
	epoch, err := strconv.ParseInt(proposal.OwnerEpoch, 10, 64)
	if err != nil {
		return claimedProof{}, fmt.Errorf("proof %s for %s/%s carries owner epoch %q: a claim key needs one",
			proposal.ID, proposal.TargetKind, proposal.TargetName, proposal.OwnerEpoch)
	}
	key := corrosion.ClaimKey{TargetKind: proposal.TargetKind, TargetName: proposal.TargetName, OwnerEpoch: epoch}
	if c.Claimer != nil {
		key = c.Claimer.ClaimKeyFor(ctx, proposal.TargetKind, proposal.TargetName, epoch, incarnation)
	}
	if c.Claimer == nil {
		// Enforcement on with nothing to claim through is a wiring fault, and
		// it fails closed: nothing is minted.
		return claimedProof{Key: key}, &ClaimRefusedError{Key: key, Reason: health.ReasonClaimNoMajority,
			Result: ResultNoMajority, Detail: "no recovery claimer is wired on " + c.hostName}
	}
	var ev *corrosion.SupersedeEvidence
	for attempt := int64(0); attempt < maxClaimAttempts; attempt++ {
		key.Attempt = attempt
		cl, out, err := c.claimAttempt(ctx, key, proposal, source, ev)
		if err != nil || cl.Ours {
			return cl, err
		}
		next := c.supersedeEvidence(ctx, key, out, cl.Proof, proposal)
		if next == nil {
			if key.Incarnation != "" && c.proofSpent(ctx, cl.Proof.ID) {
				// Decided, and its proof can never run again: a decision the
				// legacy-key bridge adopted because its destination could not
				// show in time that it was another incarnation's (§10 item
				// 37). Writing it would point the workload at a proof that
				// never executes, off its failed host and out of every later
				// recovery; refuse, and the next tick asks the destination
				// again.
				err := &ClaimRefusedError{Key: key, Reason: health.ReasonClaimLost, Result: ResultLost,
					Detail: fmt.Sprintf("%s decided proof %s, which has already run or failed; waiting for %s to show it "+
						"was not this incarnation's (ha.claim.legacy_held)", key, cl.Proof.ID, cl.Proof.DestHost)}
				// Re-asserted on every refusal: the bridge that raised the
				// condition never runs again for a key that has decided, so
				// a raise whose write failed is retried only from here.
				c.Claimer.NoteLegacyHeld(ctx, key, out.Value, fmt.Sprintf("the claim decided proof %s, which has "+
					"already run or failed, and %s has not shown it is another incarnation's", cl.Proof.ID, cl.Proof.DestHost))
				return claimedProof{Key: key}, err
			}
			problem, perr := c.adoptedDestProblem(ctx, cl, proposal, source, fits)
			if perr != nil {
				return claimedProof{Key: key}, &ClaimRefusedError{Key: key, Reason: health.ReasonClaimLost, Result: ResultLost,
					Detail: fmt.Sprintf("%s decided %s for %s, which could not be checked: %v", key, cl.Proof.ID, cl.Proof.DestHost, perr),
					Err:    perr}
			}
			if problem == "" {
				return cl, nil
			}
			// The decided value stands at this key and cannot be swapped
			// (§3.16), and writing it would send the workload where it cannot
			// go. Its destination's signed abandonment moves the claim on
			// (§3.12): that host records it before signing, so the proof can
			// never run there, and only that host could run it.
			dest := cl.Proof.DestHost
			ab, aerr := c.Claimer.RequestAbandonment(ctx, dest, key, cl.Proof.ID,
				"the decided destination cannot take the workload: "+problem)
			if aerr != nil {
				return claimedProof{Key: key}, &ClaimRefusedError{Key: key, Reason: health.ReasonClaimLost, Result: ResultLost,
					Detail: fmt.Sprintf("%s decided %s for %s, which %s; %s has not abandoned it (%v)",
						key, cl.Proof.ID, dest, problem, dest, aerr), Err: aerr}
			}
			if next = c.priorEvidence(out); next == nil {
				return claimedProof{Key: key}, &ClaimRefusedError{Key: key, Reason: health.ReasonClaimLost, Result: ResultLost,
					Detail: fmt.Sprintf("%s decided %s for %s: its certificate does not encode", key, cl.Proof.ID, dest)}
			}
			next.Abandonment = ab
			slog.Warn("failover: a decided recovery names a destination that cannot take the workload; it abandoned the "+
				"proof, moving the claim to the next attempt", "claim", key.String(), "decided_dest", dest,
				"decided_proof", cl.Proof.ID, "problem", problem, "own_pick", proposal.DestHost)
			c.mAttempt(PhaseClaim, ResultSuperseded, "")
			ev = next
			continue
		}
		slog.Warn("failover: a decided recovery will never execute; moving the claim to the next attempt",
			"claim", key.String(), "decided_dest", cl.Proof.DestHost, "decided_proof", cl.Proof.ID,
			"evidence", map[bool]string{true: "abandonment", false: "destination removed"}[next.Abandonment != ""])
		c.mAttempt(PhaseClaim, ResultSuperseded, "")
		ev = next
	}
	return claimedProof{Key: key}, &ClaimRefusedError{Key: key, Reason: health.ReasonClaimNoMajority, Result: ResultNoMajority,
		Detail: fmt.Sprintf("%d attempts of %s were each superseded", maxClaimAttempts, key)}
}

// supersedeEvidence is the evidence that the value decided at key will never
// execute, or nil when there is none and the decided value stands (§3.12).
func (c *Coordinator) supersedeEvidence(ctx context.Context, key corrosion.ClaimKey, out claims.Outcome, decided corrosion.ActionProof, proposal corrosion.ActionProof) *corrosion.SupersedeEvidence {
	ev := c.priorEvidence(out)
	if ev == nil {
		return nil
	}
	dest := decided.DestHost
	// This coordinator's own promote, and it is not promoting now: the promote
	// failed and it fell back. Only the destination can say it never started,
	// and it signs that or refuses. Another coordinator's promote is never
	// abandoned from here — it may be building its disk as this runs.
	if decided.Action == corrosion.ActionPromote && decided.Coordinator == c.hostName && proposal.Action != corrosion.ActionPromote {
		ab, err := c.Claimer.RequestAbandonment(ctx, dest, key, decided.ID,
			"the promote failed before StartDomain; the coordinator is falling back to a reschedule")
		if err != nil {
			slog.Warn("failover: the decided promote's destination did not abandon it", "claim", key.String(),
				"dest", dest, "proof", decided.ID, "error", err)
			return nil
		}
		ev.Abandonment = ab
		return ev
	}
	// A decided proof that is already spent, at an incarnation-scoped key: it
	// can never run again, and the legacy-key bridge may have adopted it from
	// a previous incarnation of the name (§10 item 37). The destination that
	// ran or failed it can show, from its own database, that it did not move
	// this incarnation; it signs that, and the claim moves on.
	if key.Incarnation != "" && c.proofSpent(ctx, decided.ID) {
		ab, err := c.Claimer.RequestForeignAbandonment(ctx, dest, key, decided.ID,
			"a spent decision that is not "+key.String()+"'s")
		if err == nil {
			ev.Abandonment = ab
			return ev
		}
		slog.Warn("failover: the destination of a spent decided proof did not show it is another incarnation's",
			"claim", key.String(), "dest", dest, "proof", decided.ID, "error", err)
	}
	// A destination removed for good (`lv host rm --dead`): voters check the
	// fence, the removal and the revocation in their own replicas.
	if h, err := corrosion.GetHost(ctx, c.db, dest); err == nil && h == nil {
		return ev
	}
	return nil
}

// priorEvidence is the half of supersede evidence every kind shares: the
// certificate that decided out's attempt and the value it decided. nil when
// the certificate does not encode.
func (c *Coordinator) priorEvidence(out claims.Outcome) *corrosion.SupersedeEvidence {
	cert, err := out.Certificate.Encode()
	if err != nil {
		return nil
	}
	value := out.Value
	return &corrosion.SupersedeEvidence{PriorCertificate: cert, PriorValue: &value}
}

// adoptedDestProblem says why the destination of a decided value this
// coordinator did NOT propose cannot take the workload now, or "" when it can.
// The coordinator's own pick passed placement and the gate checks before it
// was proposed; an adopted value -- another coordinator's, or one a voter
// accepted in an earlier attempt that never formed a certificate and that a
// forced reconfiguration imported -- passed them, if ever, against another
// moment's cluster. On the lab such a value named a host removed for good,
// and the machine re-added under its name was still joining when the value
// was adopted and minted for it (drill 6 on main-b3368d7c).
//
// The value names its destination by host name only, so the checks are the
// ones a fresh pick of that name gets now: an active host row, the split-brain
// gate advertised, and fits, the site's own placement check. A value decided
// for the source itself is not judged here (noteClaimStranded), and neither
// is a host with no row (supersedeEvidence moves past a removed one) or a
// value for another action (the site defers to it).
func (c *Coordinator) adoptedDestProblem(ctx context.Context, cl claimedProof, proposal corrosion.ActionProof, source string,
	fits func(corrosion.HostRecord) string) (string, error) {
	d := cl.Proof
	if cl.Ours || d.Action != proposal.Action || d.DestHost == "" || d.DestHost == source || d.DestHost == proposal.DestHost {
		return "", nil
	}
	h, err := corrosion.GetHost(ctx, c.db, d.DestHost)
	if err != nil {
		return "", err
	}
	if h == nil {
		return "", nil
	}
	if h.State != "active" {
		return fmt.Sprintf("is %s, not active", h.State), nil
	}
	if !c.destAdvertisesGate(ctx, h.Name) {
		return "does not advertise the split-brain gate", nil
	}
	if fits != nil {
		if p := fits(*h); p != "" {
			return p, nil
		}
	}
	return "", nil
}

// vmFitsOn is the reschedule site's placement check of one destination for
// vm, recovered off failed: the same request and inputs the batch placement
// of the coordinator's own pick uses, against that host alone. A pin is not
// applied: the destination is the one decided, not one being chosen.
func (c *Coordinator) vmFitsOn(ctx context.Context, vm corrosion.VMRecord, failed string, h corrosion.HostRecord) string {
	req := buildFailoverPlacementRequest(vm, failed, c.capacity, func(string) bool { return true })
	req.RequireRegion = c.vmRecoveryRegion(failed, vm)
	allVMs, err := corrosion.ListVMs(ctx, c.db, "", "")
	if err != nil {
		return "its placement could not be checked: " + err.Error()
	}
	ctMem, err := corrosion.SumContainerMemoryByHost(ctx, c.db)
	if err != nil {
		ctMem = nil
	}
	observations, err := corrosion.ListHostCapacityObservations(ctx, c.db)
	if err != nil {
		observations = nil
	}
	res, err := placement.SelectBatch([]corrosion.HostRecord{h}, allVMs, nil, ctMem, observations, c.now(),
		[]placement.Request{req})
	if err != nil {
		return "fails placement: " + err.Error()
	}
	if r := res[vm.Name]; r.Host != h.Name {
		if r.Err != nil {
			return "fails placement: " + r.Err.Error()
		}
		return "fails placement"
	}
	return ""
}

// proofSpent reports whether this replica holds proofID completed or failed:
// single use, so it never executes again.
func (c *Coordinator) proofSpent(ctx context.Context, proofID string) bool {
	pr, ok, err := corrosion.GetActionProof(ctx, c.db, proofID)
	return err == nil && ok && (pr.Status == corrosion.ProofCompleted || pr.Status == corrosion.ProofFailed)
}

// claimAttempt runs one claim at key (attempt included).
func (c *Coordinator) claimAttempt(ctx context.Context, key corrosion.ClaimKey, proposal corrosion.ActionProof, source string, ev *corrosion.SupersedeEvidence) (claimedProof, claims.Outcome, error) {
	if prev, ok := c.claimRetryProposals[key]; ok && sameClaimIntent(prev, proposal) {
		// The value the voters refused last time, not a fresh one: the same
		// round then carries the same value.
		proposal.ID, proposal.RelocationToken = prev.ID, prev.RelocationToken
	}
	binding := proposal
	binding.ClaimCertificate = ""
	value := corrosion.ClaimValue{Proof: &binding, SourceHost: source}

	cctx, cancel := context.WithTimeout(ctx, c.claimDeadline(ctx))
	defer cancel()
	out, err := c.Claimer.DecideRecoveryClaim(cctx, key, value, c.claimRound(), ev)
	if err != nil {
		ce := classifyClaimError(key, err)
		c.mAttempt(PhaseClaim, ce.Result, "")
		if ce.Result == ResultOwnerReachable || ce.Result == ResultSourceMismatch {
			if c.claimRetryProposals == nil {
				c.claimRetryProposals = map[corrosion.ClaimKey]corrosion.ActionProof{}
			}
			c.claimRetryProposals[key] = proposal
		} else {
			delete(c.claimRetryProposals, key)
		}
		return claimedProof{Key: key}, out, ce
	}
	delete(c.claimRetryProposals, key)
	if out.Value.Proof == nil {
		return claimedProof{Key: key}, out, fmt.Errorf("claim %s decided a value with no proof", key)
	}
	decided := *out.Value.Proof
	if out.Ours {
		decided = proposal // keep the evidence fields the binding does not carry
	}
	cert, err := out.Certificate.Encode()
	if err != nil {
		return claimedProof{Key: key}, out, err
	}
	decided.ClaimCertificate = cert
	result := ResultOK
	if !out.Ours {
		result = ResultLost
	}
	c.mAttempt(PhaseClaim, result, "")
	return claimedProof{Proof: decided, Key: out.Certificate.Key, Ours: out.Ours}, out, nil
}

// sameClaimIntent reports whether two proposals for one key would be the same
// decision but for the IDs a fresh mint draws: same action, destination,
// coordinator, fence and lease stamp.
func sameClaimIntent(a, b corrosion.ActionProof) bool {
	return a.Action == b.Action && a.DestHost == b.DestHost && a.Coordinator == b.Coordinator &&
		a.FenceEpoch == b.FenceEpoch && a.OwnerEpoch == b.OwnerEpoch &&
		a.LeaseTerm == b.LeaseTerm && a.LeaseKey == b.LeaseKey &&
		(a.RelocationToken == "") == (b.RelocationToken == "")
}

// claimRound seeds the ballot round with the lease term (§3.2), so a newer
// lease incarnation outranks an older one without any extra message.
func (c *Coordinator) claimRound() uint64 {
	if t := c.LeaseTerm(); t > 0 {
		return uint64(t)
	}
	return 1
}

// claimDeadline is claimTimeout, cut to the lease this coordinator still
// holds less the fence margin when that is shorter (§3.13 step 3).
func (c *Coordinator) claimDeadline(ctx context.Context) time.Duration {
	d := claimTimeout
	if left, ok := c.leaseRemaining(ctx); ok && left-leaseFenceMargin > 0 && left-leaseFenceMargin < d {
		d = left - leaseFenceMargin
	}
	return d
}

// noteClaimRefused records a refused claim at a mint site: the gate-refusal
// observer, the per-workload metric, one log line naming every refusing voter,
// and a retry of the host's recovery on the next tick — a fenced host is
// otherwise processed once, and a refused claim must not strand its workloads.
func (c *Coordinator) noteClaimRefused(ctx context.Context, action, kind, name, host string, err error) {
	reason, detail := health.ReasonClaimNoMajority, err.Error()
	var ce *ClaimRefusedError
	if errors.As(err, &ce) {
		reason, detail = ce.Reason, ce.Detail
	}
	c.noteGateRefused(action, reason)
	switch kind {
	case "container":
		c.mCt(ActionRelocate, ResultRefused, reason)
	default:
		c.mVM(action, ResultRefused, reason)
	}
	slog.Warn("failover: recovery claim formed no certificate; minting nothing, retrying next tick",
		"kind", kind, "name", name, "from", host, "reason", reason, "detail", detail)
	c.noteHold(host, kind+" "+name+": its recovery claim formed no certificate ("+reason+": "+detail+"); retried next tick")
	c.retryClaimsFor(host)
}

// noteClaimLost records a claim whose decided value is not one this site can
// execute (another coordinator's promote, say): nothing is minted here, and
// the host's recovery is retried next tick.
func (c *Coordinator) noteClaimLost(action, kind, name, host string, decided corrosion.ActionProof) {
	c.noteGateRefused(action, health.ReasonClaimLost)
	if kind == "container" {
		c.mCt(ActionRelocate, ResultRefused, health.ReasonClaimLost)
	} else {
		c.mVM(action, ResultRefused, health.ReasonClaimLost)
	}
	slog.Warn("failover: another coordinator's recovery was decided for this workload; deferring to it",
		"kind", kind, "name", name, "from", host, "decided_action", decided.Action,
		"decided_dest", decided.DestHost, "decided_by", decided.Coordinator, "proof", decided.ID)
	c.noteHold(host, kind+" "+name+": another coordinator's recovery was decided for it ("+decided.Action+" to "+
		decided.DestHost+" by "+decided.Coordinator+"); deferring to it")
	c.retryClaimsFor(host)
}

// claimContainerRelocation claims a container relocation before its proof is
// minted, and writes the proof that was decided. It returns the proof to act
// on and whether to act now.
//
// When the decided value is ANOTHER coordinator's, this one writes that proof
// (idempotent by ID) and, ordinarily, stops there: the other coordinator is
// driving the relocation — perhaps a restore it is already streaming — and a
// second driver on the same decision would only race it. If the decision then
// stands unexecuted for RelocateRestoreTimeout — the other coordinator died
// after deciding — this one carries it out itself, as the decided value says:
// same proof, same token, same destination (§3.13 step 5).
func (c *Coordinator) claimContainerRelocation(ctx context.Context, h *corrosion.HostRecord, ct corrosion.ContainerRecord, proposal corrosion.ActionProof) (corrosion.ActionProof, bool) {
	// An adopted destination that already runs a container of this name can
	// never take it (the relocation refuses to clobber one, and skips): its
	// decided proof is abandoned there and the claim moves on, rather than
	// being written and left live for a host it will never run on.
	cl, err := c.claimRecoveryFor(ctx, proposal, h.Name, ct.CreatedAt, func(hr corrosion.HostRecord) string {
		if c.targetHasLiveContainer(ctx, hr.Name, ct.Name) {
			return "already runs a container named " + ct.Name
		}
		return ""
	})
	if err != nil {
		c.noteClaimRefused(ctx, ActionRelocate, "container", ct.Name, h.Name, err)
		return corrosion.ActionProof{}, false
	}
	if cl.Proof.Action != corrosion.ActionRelocate || cl.Proof.RelocationToken == "" {
		c.noteClaimLost(ActionRelocate, "container", ct.Name, h.Name, cl.Proof)
		return corrosion.ActionProof{}, false
	}
	if err := corrosion.WriteActionProof(ctx, c.db, cl.Proof); err != nil {
		slog.Warn("failover: write claimed relocation proof; deferring", "container", ct.Name, "error", err)
		c.mCt(ActionRelocate, ResultError, ErrDBError)
		c.retryClaimsFor(h.Name)
		return corrosion.ActionProof{}, false
	}
	if cl.Ours || cl.Proof.Coordinator == c.hostName {
		// Ours — or this host's own decision from an earlier process, which
		// nobody else is driving.
		return cl.Proof, true
	}
	if c.relocDeferred == nil {
		c.relocDeferred = map[string]time.Time{}
	}
	first, seen := c.relocDeferred[cl.Proof.ID]
	if !seen {
		c.relocDeferred[cl.Proof.ID] = c.now()
		c.noteClaimLost(ActionRelocate, "container", ct.Name, h.Name, cl.Proof)
		return corrosion.ActionProof{}, false
	}
	to := c.RelocateRestoreTimeout
	if to <= 0 {
		to = defaultRelocateRestoreTimeout
	}
	if c.now().Sub(first) < to {
		c.noteClaimLost(ActionRelocate, "container", ct.Name, h.Name, cl.Proof)
		return corrosion.ActionProof{}, false
	}
	slog.Warn("failover: a relocation another coordinator decided has not been carried out; completing it as decided",
		"container", ct.Name, "dest", cl.Proof.DestHost, "decided_by", cl.Proof.Coordinator, "proof", cl.Proof.ID)
	delete(c.relocDeferred, cl.Proof.ID)
	return cl.Proof, true
}

// noteClaimStranded records a recovery decided for the very host being
// recovered: it died after the decision and before it acted, no abandonment
// can be had from it, and it might return and execute its valid certificate.
// So the workload stays, deliberately, until the host returns or is removed
// for good (§3.12); ha.claim.stranded names it with the command.
func (c *Coordinator) noteClaimStranded(kind, name, host string, decided corrosion.ActionProof) {
	c.noteHold(host, kind+" "+name+": its recovery was decided for this host before it failed; stranded until the host returns or `lv host rm --dead`")
	if kind == "container" {
		c.mCt(ActionRelocate, ResultRefused, ErrClaimStranded)
	} else {
		c.mVM(ActionReschedule, ResultRefused, ErrClaimStranded)
	}
	slog.Warn("failover: this recovery was decided for the host that failed, before it acted; it is stranded until "+
		"that host returns or is removed for good", "kind", kind, "name", name, "host", host, "proof", decided.ID,
		"fix", "if "+host+" is gone for good: lv host rm --dead "+host+" (--dry-run first)")
	c.retryClaimsFor(host)
}

// recoverRemovedHosts recovers the workloads still recorded on hosts that
// have been removed for good, under recovery claims only (§3.12). Their
// claims move to the next attempt on the removal evidence — fenced
// proof-grade, no live hosts row, revoked — which every voter checks in its
// own replica; until all three have replicated the voters refuse and this
// retries next tick. Without claims the pre-claim behaviour stands: a removed
// host's rows are only ever there because an operator forced the removal.
func (c *Coordinator) recoverRemovedHosts(ctx context.Context) {
	if !c.claimsEnforced(ctx) {
		return
	}
	rows, err := c.db.Query(ctx, `SELECT DISTINCT host_name FROM (
			SELECT host_name FROM vms WHERE deleted_at IS NULL
			UNION SELECT host_name FROM containers WHERE deleted_at IS NULL)
		WHERE host_name != '' AND host_name NOT IN (SELECT name FROM hosts WHERE deleted_at IS NULL)`)
	if err != nil {
		slog.Warn("failover: list workloads on removed hosts", "error", err)
		return
	}
	for _, r := range rows {
		host := r.String("host_name")
		if !c.holdLease(ctx) {
			return
		}
		if _, fenced, err := corrosion.HostProofGradeFence(ctx, c.db, host); err != nil || !fenced {
			// Removed without a proof-grade fence (a pre-claims `lv host rm
			// --force`): not removed for good as far as the claims can tell,
			// and the voters would refuse its supersede anyway.
			slog.Debug("failover: workloads on a removed host with no proof-grade fence are left", "host", host)
			continue
		}
		slog.Info("failover: recovering workloads recorded on a host removed for good", "host", host)
		c.recoverWorkloads(ctx, &corrosion.HostRecord{Name: host, State: "removed"})
	}
}

// recertifyReplaced re-certifies, at the current voter generation, every
// pending proof whose certificate is at a generation a FORCED reconfiguration
// replaced (§4.6 "Replaced generations certify nothing"). A destination
// refuses such a certificate; the value it certified was imported by every
// survivor, so a claim at the new generation learns it and certifies it again
// with the same proof ID, as a lagging coordinator would (§3.12). A key whose
// new decision is a DIFFERENT value — the one case a forced change cannot
// rule out — keeps its old proof, which then never executes.
func (c *Coordinator) recertifyReplaced(ctx context.Context) {
	if !c.claimsEnforced(ctx) || c.Claimer == nil {
		return
	}
	rows, err := c.db.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE deleted_at IS NULL AND status = 'prepared' AND claim_certificate != ''`)
	if err != nil {
		return
	}
	for _, r := range rows {
		pr, ok, err := corrosion.GetActionProof(ctx, c.db, r.String("id"))
		if err != nil || !ok {
			continue
		}
		cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
		if err != nil {
			continue
		}
		if forced, err := corrosion.ReplacedByForcedGeneration(ctx, c.db, cert.ConfigGeneration); err != nil || forced == 0 {
			continue
		}
		proposal := pr.ActionProof
		proposal.ClaimCertificate = ""
		key := cert.Key
		if key.Incarnation == "" {
			// Certified at the legacy key before claim_incarnation_v1
			// latched: re-decide it at its incarnation-scoped key once that is
			// the format, which re-proposes the same value through the legacy
			// bridge (§10 item 37).
			if inc, ok, err := corrosion.WorkloadIncarnation(ctx, c.db, key.TargetKind, key.TargetName); err == nil && ok {
				scoped := c.Claimer.ClaimKeyFor(ctx, key.TargetKind, key.TargetName, key.OwnerEpoch, inc)
				scoped.Attempt = key.Attempt
				key = scoped
			}
		}
		cl, out, err := c.claimAttempt(ctx, key, proposal, cert.SourceHost, nil)
		if err != nil {
			slog.Warn("failover: could not re-certify a proof its forced voter generation replaced; retrying next tick",
				"proof", pr.ID, "claim", cert.Key.String(), "error", err)
			continue
		}
		if out.Digest != cert.ValueDigest {
			slog.Error("failover: a forced voter generation decided a DIFFERENT value for a certified recovery; "+
				"the old proof will never execute", "proof", pr.ID, "claim", cert.Key.String())
			continue
		}
		re := pr.ActionProof
		re.ClaimCertificate = cl.Proof.ClaimCertificate
		if err := corrosion.SetProofClaimCertificate(ctx, c.db, re); err != nil && !errors.Is(err, corrosion.ErrNoRowsAffected) {
			slog.Warn("failover: record a re-certified proof", "proof", pr.ID, "error", err)
			continue
		}
		slog.Info("failover: re-certified a recovery at the forced voter generation", "proof", pr.ID,
			"claim", cert.Key.String(), "generation", out.Certificate.ConfigGeneration)
	}
}

// certifyUncertified claims, for its OWN value, every pending proof minted
// without a certificate before recovery claims were enforced
// (corrosion.UncertifiedPendingProofs). The claim is the one a coordinator
// would have run before minting it: key (workload, the proof's owner epoch,
// attempt 0), the proof as the value, and its fenced old owner
// (corrosion.UncertifiedProofSource) as the source every voter probes. When
// it decides this proof, the certificate is attached the way a
// re-certification is (SetProofClaimCertificate), and the destination runs it
// on its next pass. When another value was decided for the key it is handled
// as recovery_claim_lost: a decided reschedule is written in its place, and
// this proof never executes. A refusal writes nothing and is retried next
// tick. Nothing is grandfathered: without a certificate a proof does not run.
func (c *Coordinator) certifyUncertified(ctx context.Context) {
	if !c.claimsEnforced(ctx) || c.Claimer == nil {
		return
	}
	pending, err := corrosion.UncertifiedPendingProofs(ctx, c.db)
	if err != nil {
		return
	}
	for _, pr := range pending {
		source, ok := corrosion.UncertifiedProofSource(pr.ActionProof)
		if !ok {
			continue // reported by ha.claim.uncertified; nothing to probe
		}
		action := ActionReschedule
		if pr.Action == corrosion.ActionRelocate {
			action = ActionRelocate
		}
		key, err := corrosion.ClaimKeyForProof(pr.ActionProof, 0)
		if err != nil {
			continue
		}
		if inc, ok, err := corrosion.WorkloadIncarnation(ctx, c.db, pr.TargetKind, pr.TargetName); err == nil && ok {
			key = c.Claimer.ClaimKeyFor(ctx, key.TargetKind, key.TargetName, key.OwnerEpoch, inc)
		}
		cl, _, err := c.claimAttempt(ctx, key, pr.ActionProof, source, nil)
		if err != nil {
			c.noteClaimRefused(ctx, action, pr.TargetKind, pr.TargetName, source, err)
			continue
		}
		if cl.Proof.ID != pr.ID || !corrosion.ProofBindingEqual(cl.Proof, pr.ActionProof) {
			c.noteClaimLost(action, pr.TargetKind, pr.TargetName, source, cl.Proof)
			if pr.TargetKind == "vm" && cl.Proof.Action == corrosion.ActionReschedule {
				if err := corrosion.WriteVMRescheduleProof(ctx, c.db, cl.Proof, pr.TargetName, cl.Proof.DestHost); err != nil &&
					!errors.Is(err, corrosion.ErrNoRowsAffected) && !errors.Is(err, corrosion.ErrWorkloadStopped) {
					slog.Warn("failover: write the decided reschedule in place of an uncertified one", "vm", pr.TargetName,
						"proof", cl.Proof.ID, "error", err)
				}
			}
			continue
		}
		re := pr.ActionProof
		re.ClaimCertificate = cl.Proof.ClaimCertificate
		if err := corrosion.SetProofClaimCertificate(ctx, c.db, re); err != nil && !errors.Is(err, corrosion.ErrNoRowsAffected) {
			slog.Warn("failover: record the certificate of a proof minted before recovery claims were enforced",
				"proof", pr.ID, "error", err)
			continue
		}
		slog.Info("failover: certified a recovery minted before recovery claims were enforced", "proof", pr.ID,
			"kind", pr.TargetKind, "name", pr.TargetName, "dest", pr.DestHost, "source", source)
	}
}

// retryClaimsFor marks host's recovery to be re-run on the next tick.
func (c *Coordinator) retryClaimsFor(host string) {
	if c.claimRetry == nil {
		c.claimRetry = map[string]bool{}
	}
	c.claimRetry[host] = true
}

// retryClaims re-runs the recovery of a fenced host whose claims were refused
// on an earlier tick. recoverWorkloads is idempotent — it re-derives its work
// from the rows still pointing at the host — so re-running it only picks up
// what is still there. Reports whether it ran.
func (c *Coordinator) retryClaims(ctx context.Context, target string) bool {
	if !c.claimRetry[target] {
		return false
	}
	h, err := corrosion.GetHost(ctx, c.db, target)
	if err != nil || h == nil {
		return false
	}
	delete(c.claimRetry, target)
	if !c.holdLease(ctx) {
		c.claimRetry[target] = true
		return true
	}
	slog.Info("failover: retrying the recovery claims refused on an earlier tick", "host", target)
	c.recoverWorkloads(ctx, h)
	return true
}
