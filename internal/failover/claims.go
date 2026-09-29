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
)

// Recovery claims at the mint sites (docs/design/recovery-claims.md §3.13,
// colonelpanik/litevirt#250).
//
// Under recovery_claim_v1 a coordinator does not mint an ownership-transfer
// proof on its own authority. It proposes the proof as the value of a claim
// keyed by (kind, name, owner_epoch, attempt), and writes a proof only once a
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
	DecideRecoveryClaim(ctx context.Context, key corrosion.ClaimKey, proposal corrosion.ClaimValue, startRound uint64) (claims.Outcome, error)
}

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
// coordinator would otherwise mint, whose owner being left is source.
//
// It never falls back to an uncertified proof: without a certificate it
// returns a *ClaimRefusedError and the caller mints nothing (§3.13 step 6).
func (c *Coordinator) claimRecovery(ctx context.Context, proposal corrosion.ActionProof, source string) (claimedProof, error) {
	epoch, err := strconv.ParseInt(proposal.OwnerEpoch, 10, 64)
	if err != nil {
		return claimedProof{}, fmt.Errorf("proof %s for %s/%s carries owner epoch %q: a claim key needs one",
			proposal.ID, proposal.TargetKind, proposal.TargetName, proposal.OwnerEpoch)
	}
	key := corrosion.ClaimKey{TargetKind: proposal.TargetKind, TargetName: proposal.TargetName, OwnerEpoch: epoch}
	if c.Claimer == nil {
		// Enforcement on with nothing to claim through is a wiring fault, and
		// it fails closed: nothing is minted.
		return claimedProof{Key: key}, &ClaimRefusedError{Key: key, Reason: health.ReasonClaimNoMajority,
			Result: ResultNoMajority, Detail: "no recovery claimer is wired on " + c.hostName}
	}
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
	out, err := c.Claimer.DecideRecoveryClaim(cctx, key, value, c.claimRound())
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
		return claimedProof{Key: key}, ce
	}
	delete(c.claimRetryProposals, key)
	if out.Value.Proof == nil {
		return claimedProof{Key: key}, fmt.Errorf("claim %s decided a value with no proof", key)
	}
	decided := *out.Value.Proof
	if out.Ours {
		decided = proposal // keep the evidence fields the binding does not carry
	}
	cert, err := out.Certificate.Encode()
	if err != nil {
		return claimedProof{Key: key}, err
	}
	decided.ClaimCertificate = cert
	result := ResultOK
	if !out.Ours {
		result = ResultLost
	}
	c.mAttempt(PhaseClaim, result, "")
	return claimedProof{Proof: decided, Key: out.Certificate.Key, Ours: out.Ours}, nil
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
	cl, err := c.claimRecovery(ctx, proposal, h.Name)
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
