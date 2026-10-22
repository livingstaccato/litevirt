package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	lv "github.com/litevirt/litevirt/internal/libvirt"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Layer 3 of partition pause: settle on return
// (docs/design/partition-pause.md §6).
//
// selfFence's non-destruction guard refuses to stop a live or resumable local
// domain on the strength of the DB host_name alone, because an equal-updated_at
// LWW tie can converge that column to the wrong host and a converged-wrong row
// must not be able to kill a live VM. That guard lacks positive proof, and so
// it left drill 1's superseded copy running forever.
//
// A decided recovery claim IS that proof: a majority of voters, each unable to
// reach this host when it accepted, signed that exactly this incarnation at
// exactly this owner epoch moves to another host. So a local copy is stopped —
// destroyed, which keeps its definition, disks and NVRAM — when, and only when:
//
//   - its row names another host, and is the SAME incarnation as the local copy;
//   - the local copy's incarnation and owner epoch are known from evidence on
//     THIS host (the partition-pause record, else the managed stamp's
//     incarnation and the owner-epoch marker), never from the row;
//   - a live ownership-transfer proof for it names the row's host as
//     destination and carries a certificate that verifies here
//     (corrosion.VerifyClaimCertificate), at an incarnation-scoped key of the
//     local copy's incarnation (or a legacy key), at an owner epoch at least
//     the local copy's;
//   - that proof completed on its destination, whose own runtime reports the
//     VM running — or, for a copy this host's partition pause holds paused,
//     merely is live (settleDecide): a paused QEMU keeps a shared disk's image
//     lock, so the replacement cannot run until the paused copy is gone.
//
// It writes an audit row and the vm_settled condition, retried until both are
// written (settle_pending.go), and leaves the shut-off domain to the existing
// leftover cleanup. It deletes nothing.

// SettleVerifier verifies a proof's recovery-claim certificate
// (grpcapi.Server.VerifySettleProof).
type SettleVerifier func(ctx context.Context, p corrosion.ActionProof) (corrosion.ClaimCertificate, error)

// PauseSettleGuard runs destroy for the VM rec describes only while the
// pauser cannot resume it: under its mark lock, with the domain still paused
// by rec (PartitionPauser.SettleDestroy). It returns errPauseChanged when it
// declined.
type PauseSettleGuard func(rec PauseRecord, destroy func() error) error

// SetPauseGuard wires the pauser's guard for the destroy of a paused copy.
// Without one, the paused state settle decided on is not re-checked at the
// destroy.
func (r *Reconciler) SetPauseGuard(fn PauseSettleGuard) { r.pauseGuard = fn }

// errPauseChanged: the paused copy settle decided on changed before the
// destroy (resumed, or a mark write or resume in flight); this pass declines.
var errPauseChanged = errors.New("the paused copy changed before the destroy")

// SetSettleVerifier wires Layer 3. nil (the default) settles nothing: without
// a verifier there is no proof, and the guard stands as before.
func (r *Reconciler) SetSettleVerifier(fn SettleVerifier) { r.settleVerify = fn }

// localCopyID is what THIS host knows of its own copy of a workload.
type localCopyID struct {
	Incarnation string
	Epoch       int64
	EpochKnown  bool
	Source      string
	// SelfPaused: this host's partition pause record still describes the
	// domain, which is paused now (recordStillDescribes). Such a copy runs
	// nothing, so stopping it cannot take away a running copy (settleDecide).
	SelfPaused bool
	// Record is the pause record SelfPaused rests on.
	Record PauseRecord
}

// localVMIdentity reads the local copy's identity from host-local evidence.
// The pause record counts only while the domain is still the one it paused —
// paused, and the same domain UUID — since a record can outlive what it
// described. The incarnation is the record's or the managed stamp's (both
// known and different is no answer at all); the epoch is the HIGHEST any
// source reports, so a stale source can never make the local copy look older
// than it is.
func (r *Reconciler) localVMIdentity(name string) localCopyID {
	var id localCopyID
	var sources []string
	if rec, ok, err := ReadPauseRecord(r.dataDir, PauseKindVM, name); err == nil && ok && rec.Incarnation != "" && r.recordStillDescribes(rec) {
		id.Incarnation, id.Epoch, id.EpochKnown, id.SelfPaused, id.Record = rec.Incarnation, rec.OwnerEpoch, true, true, rec
		sources = append(sources, "partition-pause record")
	}
	if inc, ok, err := r.virt.GetDomainManagedIncarnation(name); err == nil && ok && inc != "" {
		if id.Incarnation != "" && id.Incarnation != inc {
			return localCopyID{Source: "the pause record and the managed stamp disagree about the incarnation"}
		}
		id.Incarnation = inc
		sources = append(sources, "managed stamp")
	}
	note := func(e int64) {
		if !id.EpochKnown || e > id.Epoch {
			id.Epoch = e
		}
		id.EpochKnown = true
	}
	if e, ok, err := r.virt.GetDomainOwnerEpoch(name); err == nil && ok {
		note(e)
		sources = append(sources, "owner-epoch metadata")
	}
	if r.dataDir != "" {
		if e, ok, err := ReadVMOwnerEpochMarker(r.dataDir, name); err == nil && ok {
			note(e)
			sources = append(sources, "owner-epoch marker")
		}
	}
	id.Source = strings.Join(sources, "+")
	return id
}

// recordStillDescribes reports whether rec is still about the local domain:
// paused, and the same domain UUID. A record without a UUID (its DumpXML read
// failed at pause time) cannot show it is about THIS domain rather than one
// defined under the same name since, so it is not evidence.
func (r *Reconciler) recordStillDescribes(rec PauseRecord) bool {
	st, err := r.virt.DomainStateReason(rec.Name)
	if err != nil || st.Reason != "paused" {
		return false
	}
	if rec.DomainUUID == "" {
		return false
	}
	xml, err := r.virt.DumpXMLInactive(rec.Name)
	if err != nil {
		return false
	}
	return lv.UUIDFromXML(xml) == rec.DomainUUID
}

// settleDecide is the decision of §6, separate so every clause is testable.
// It returns the proof and certificate that authorise stopping the local copy,
// or why there is none.
func settleDecide(self string, row *corrosion.VMRecord, local localCopyID, proofs []corrosion.ProofRecord,
	verify func(corrosion.ActionProof) (corrosion.ClaimCertificate, error),
	destRuns func(dest string) (bool, string)) (corrosion.ProofRecord, corrosion.ClaimCertificate, string) {
	none := corrosion.ProofRecord{}
	switch {
	case row == nil || row.HostName == "" || row.HostName == self:
		return none, corrosion.ClaimCertificate{}, "the row does not name another host"
	case local.Incarnation == "":
		return none, corrosion.ClaimCertificate{}, "the local copy's incarnation is unknown (no pause record, no managed-stamp incarnation)"
	case !local.EpochKnown:
		return none, corrosion.ClaimCertificate{}, "the local copy's owner epoch is unknown (no pause record, no owner-epoch marker)"
	case corrosion.IncarnationOf(row.CreatedAt) != local.Incarnation:
		return none, corrosion.ClaimCertificate{}, "the row is another incarnation of the name"
	case verify == nil:
		return none, corrosion.ClaimCertificate{}, "no certificate verifier"
	case destRuns == nil:
		return none, corrosion.ClaimCertificate{}, "no destination runtime check"
	}
	why := fmt.Sprintf("no verified recovery-claim certificate gives this incarnation to %s at owner epoch >= %d", row.HostName, local.Epoch)
	initial, uncertified := why, ""
	for _, p := range proofs {
		if p.TargetKind != corrosion.ClaimKindVM || p.TargetName != row.Name || p.DestHost != row.HostName || p.DestHost == self {
			continue
		}
		// Minted while recovery claims were not enforced (a derived voter
		// set): no majority certified it, and settle acts on nothing weaker
		// (F9). It is named as such — a remedy that stops the local copy —
		// only when it can be THIS copy's move: live, completed by its
		// destination, at an owner epoch at least the local copy's. Any other
		// uncertified proof is no evidence either way and says nothing.
		if p.ClaimCertificate == "" {
			if e, err := strconv.ParseInt(p.OwnerEpoch, 10, 64); err == nil && e >= local.Epoch && !p.Tombstoned {
				if _, ok := proofExecutedByDest(p); ok {
					uncertified = fmt.Sprintf("proof %s completed on %s but carries no recovery-claim certificate "+
						"(minted while recovery claims were not enforced, as on a derived voter set)", p.ID, p.DestHost)
				}
			}
			continue
		}
		// A decided claim is not yet a running replacement: the proof must
		// have been EXECUTED, by its destination. A prepared or failed one
		// leaves the local copy the only one running.
		//
		// Unless the local copy runs nothing: one this host's partition pause
		// holds paused. Stopping it cannot leave zero running copies, and
		// waiting for the replacement to run first can wait forever, because
		// a paused QEMU keeps its image locks on shared storage and the
		// replacement cannot start until they are released (lab 2, B4). Its
		// RAM belongs to the copy the decided claim superseded either way: the
		// pauser never resumes a workload a decided claim moved. So a live
		// proof the destination may still execute is enough; a failed one, or
		// one another host took, is not.
		if why2, ok := proofExecutedByDest(p); !ok && (!local.SelfPaused || !proofLiveForDest(p)) {
			why = why2
			continue
		}
		cert, err := verify(p.ActionProof)
		if err != nil {
			why = "proof " + p.ID + ": " + err.Error()
			continue
		}
		if cert.Key.TargetKind != corrosion.ClaimKindVM || cert.Key.TargetName != row.Name {
			continue
		}
		if cert.Key.Incarnation != "" && cert.Key.Incarnation != local.Incarnation {
			why = "proof " + p.ID + "'s certificate decides another incarnation"
			continue
		}
		if cert.Key.OwnerEpoch < local.Epoch {
			why = fmt.Sprintf("proof %s's certificate decides owner epoch %d, older than the local copy's %d",
				p.ID, cert.Key.OwnerEpoch, local.Epoch)
			continue
		}
		// And the replacement must be running there NOW, by the destination's
		// own runtime, not by any row: the last line before stopping what may
		// otherwise be the only copy. A copy this host holds paused is not
		// one, and the replacement may be waiting for it to go (above).
		if local.SelfPaused {
			return p, cert, ""
		}
		if ok, rwhy := destRuns(p.DestHost); !ok {
			why = "proof " + p.ID + ": " + rwhy
			continue
		}
		return p, cert, ""
	}
	// Only when no certified proof gave a reason of its own: a certified
	// proof's failure is the one an operator must see.
	if why == initial && uncertified != "" {
		why = uncertified
	}
	return none, corrosion.ClaimCertificate{}, why
}

// proofExecutedByDest reports whether p completed, executed by its own
// destination.
func proofExecutedByDest(p corrosion.ProofRecord) (string, bool) {
	if p.Status != corrosion.ProofCompleted {
		return fmt.Sprintf("proof %s is %s, not completed: no replacement is known to run", p.ID, p.Status), false
	}
	if p.ExecutorHost != p.DestHost {
		return fmt.Sprintf("proof %s was executed by %q, not its destination %s", p.ID, p.ExecutorHost, p.DestHost), false
	}
	return "", true
}

// proofLiveForDest reports whether p can still be, or has been, executed by
// its own destination: prepared and unclaimed, in progress on its destination,
// or completed by it. A failed proof, or one another host claimed, is not.
func proofLiveForDest(p corrosion.ProofRecord) bool {
	switch p.Status {
	case corrosion.ProofPrepared:
		return p.ExecutorHost == "" || p.ExecutorHost == p.DestHost
	case corrosion.ProofInProgress, corrosion.ProofCompleted:
		return p.ExecutorHost == p.DestHost
	default:
		return false
	}
}

// destRunsVia asks dest's own runtime whether it runs name, through check
// (the peer runtime inventory). nil, an error or any answer but running is
// "no".
func destRunsVia(ctx context.Context, check func(ctx context.Context, host, name string) (string, error), name string) func(string) (bool, string) {
	if check == nil {
		return nil
	}
	return func(dest string) (bool, string) {
		pctx, cancel := context.WithTimeout(ctx, peerRuntimeProbeTimeout)
		defer cancel()
		state, err := check(pctx, dest, name)
		if err != nil {
			return false, "destination " + dest + " unreachable: " + err.Error()
		}
		if state != RuntimeRunning {
			return false, "destination " + dest + " reports it " + state + ", not running"
		}
		return true, ""
	}
}

// settleCertifiedMove stops domName's local copy when a certified claim gave
// it away (the decision above). It reports whether it did, and if not, why and
// what this host knows of its copy (for the decline report, settle_declined.go).
func (r *Reconciler) settleCertifiedMove(ctx context.Context, domName string, vm *corrosion.VMRecord) (bool, string, localCopyID) {
	local := r.localVMIdentity(domName)
	if r.settleVerify == nil {
		return false, "no certificate verifier wired", local
	}
	lister := r.settleProofs
	if lister == nil {
		lister = corrosion.TransferProofs
	}
	proofs, err := lister(ctx, r.db, corrosion.ClaimKindVM, domName)
	if err != nil {
		return false, "proofs unreadable: " + err.Error(), local
	}
	p, cert, why := settleDecide(r.hostName, vm, local, proofs, func(ap corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
		return r.settleVerify(ctx, ap)
	}, destRunsVia(ctx, r.checkPeerRuntime, domName))
	if why != "" {
		return false, why, local
	}
	// The record of what is about to happen goes to disk first: the destroy
	// cannot be undone, and once the copy is shut off no later pass settles
	// it again, so a record written only after it would be lost with the
	// daemon or with one failed write (settle_pending.go).
	w := r.settleRec()
	detail := fmt.Sprintf("stopped the local copy (%s: incarnation %s, owner epoch %d): superseded by proof %s for %s, "+
		"certified at voter generation %d for owner epoch %d; definition and disks kept",
		local.Source, local.Incarnation, local.Epoch, p.ID, p.DestHost, cert.ConfigGeneration, cert.Key.OwnerEpoch)
	rec := w.newPending(PauseKindVM, domName, detail, p, cert, local.Incarnation, local.Epoch, local.Source)
	destroy := func() error { return r.virt.DestroyDomain(domName) }
	if local.SelfPaused && r.pauseGuard != nil {
		// Decided on a copy that is paused: destroyed only while it still is,
		// under the pauser's mark lock, so no resume lands between the two.
		guarded := destroy
		destroy = func() error { return r.pauseGuard(local.Record, guarded) }
	}
	if err := w.stopRecorded(ctx, rec, destroy); err != nil {
		if errors.Is(err, errPauseChanged) {
			return false, err.Error(), local
		}
		return false, "destroy failed: " + err.Error(), local
	}
	slog.Warn("partition-settle: stopped a local copy that a certified recovery claim gave to another host",
		"vm", domName, "host", r.hostName, "dest", p.DestHost, "proof", p.ID,
		"claim_epoch", cert.Key.OwnerEpoch, "local_epoch", local.Epoch, "evidence", local.Source)
	w.dropMatchingPause(rec)
	return true, "", local
}

type settledEvidence struct {
	Proof            string             `json:"proof"`
	Dest             string             `json:"dest"`
	Key              corrosion.ClaimKey `json:"key"`
	ConfigGeneration int64              `json:"config_generation"`
	Local            map[string]any     `json:"local"`
	Detail           string             `json:"detail"`
}

// resolveSettled resolves this host's vm_settled conditions that no longer
// hold. One says this host holds a stopped copy of a VM that a certified
// claim gave to another host, so it holds while a domain of that name is
// defined here AND the VM's row names another host. It resolves when the
// domain is gone from localDomains (the leftover cleanup undefined it, or an
// operator did), or when the row names this host again (the VM came back,
// and the domain is its own). A row that cannot be read keeps it open.
//
// Only this host's own: its domain list says nothing about another host's
// copy. localDomains must come from a successful list. An open row is
// written once, so a resolved one is never rewritten.
func (r *Reconciler) resolveSettled(ctx context.Context, localDomains []string) {
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, r.db, corrosion.PartitionPauseEvaluator, corrosion.CondVMSettled)
	if err != nil || len(open) == 0 {
		return
	}
	defined := make(map[string]bool, len(localDomains))
	for _, d := range localDomains {
		defined[d] = true
	}
	suffix := "@" + r.hostName
	for _, row := range open {
		if row.SubjectKind != "vm" || !strings.HasSuffix(row.SubjectID, suffix) {
			continue
		}
		name := strings.TrimSuffix(row.SubjectID, suffix)
		why := ""
		if !defined[name] {
			why = "the stopped copy is no longer defined on this host"
		} else if vm, err := corrosion.GetVM(ctx, r.db, name); err == nil && vm != nil && vm.HostName == r.hostName {
			why = "the VM's row names this host again, so the domain here is its own"
		}
		if why == "" {
			continue
		}
		ts := r.now().UTC().Format(time.RFC3339)
		row.Lifecycle, row.ResolvedAt, row.LastSeen = corrosion.ConditionResolved, ts, ts
		row.ObserveCount, row.CleanCount, row.Reporter = 0, 1, r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("partition-settle: could not resolve vm_settled", "vm", name, "error", err)
			continue
		}
		slog.Info("partition-settle: vm_settled resolved — "+why, "vm", name, "host", r.hostName)
	}
}

// settleContainer is Layer 3 for a container this host paused: its own row is
// gone (a relocation tombstones it) and the container's one live row names
// another host, at the recorded incarnation, with a live relocate proof whose
// certificate verifies here at an owner epoch at least the recorded one. Then
// the frozen local copy is stopped (its rootfs kept), with a partition.settle
// audit row and ct_settled, retried until written (settle_pending.go). It
// reports whether it settled, and if not, why.
//
// Everything it does ends by deadline, the end of its step in the resume
// pass: the stop is abandoned there, and is not started at all with less
// than settleStopMin left (short), so the next pass starts with it.
func (p *PartitionPauser) settleContainer(ctx context.Context, rec PauseRecord, deadline time.Time) (settled bool, why string, short bool) {
	if p.settle == nil || p.cts == nil {
		return false, "", false
	}
	rows, err := p.db.Query(ctx, `SELECT host_name FROM containers WHERE name = ? AND deleted_at IS NULL AND host_name != ?`,
		rec.Name, p.host)
	if err != nil {
		return false, "container rows unreadable: " + err.Error(), false
	}
	if len(rows) != 1 {
		return false, fmt.Sprintf("%d live rows for the container on other hosts, not one", len(rows)), false
	}
	dest := rows[0].String("host_name")
	row, err := corrosion.GetContainer(ctx, p.db, dest, rec.Name)
	if err != nil || row == nil {
		return false, "the destination row is unreadable", false
	}
	if corrosion.IncarnationOf(row.CreatedAt) != rec.Incarnation {
		return false, "the live row is another incarnation", false
	}
	lister := p.settleProofs
	if lister == nil {
		lister = corrosion.CertifiedTransferProofs
	}
	proofs, err := lister(ctx, p.db, corrosion.ClaimKindContainer, rec.Name)
	if err != nil {
		return false, "proofs unreadable: " + err.Error(), false
	}
	pr, cert, why := settleDecideContainer(p.host, dest, rec, proofs, func(ap corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
		return p.settle(ctx, ap)
	}, destRunsVia(ctx, p.peerRuntime, rec.Name))
	if why != "" {
		return false, why, false
	}
	detail := fmt.Sprintf("stopped the frozen local copy (incarnation %s, owner epoch %d): superseded by proof %s for %s, "+
		"certified at voter generation %d for owner epoch %d; rootfs kept", rec.Incarnation, rec.OwnerEpoch, pr.ID, dest,
		cert.ConfigGeneration, cert.Key.OwnerEpoch)
	left := time.Until(deadline)
	if left < settleStopMin {
		return false, fmt.Sprintf("%v of this pass left, too little to stop it; a later pass does", left.Round(time.Millisecond)), true
	}
	// lxc-stop waits this long for the container to act on its SIGPWR before
	// it kills it; a frozen one never acts on it, so no more than the step has.
	grace := min(10, max(1, int((left-500*time.Millisecond)/time.Second)))
	w := p.settleRec()
	pending := w.newPending(PauseKindContainer, rec.Name, detail, pr, cert, rec.Incarnation, rec.OwnerEpoch, "partition-pause record")
	if err := w.stopRecorded(ctx, pending, func() error {
		name := rec.Name
		return p.callWithin(rec.Key(), time.Until(deadline), false, func() error {
			sctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			return p.cts.Stop(sctx, name, grace)
		}, nil)
	}); err != nil {
		return false, "stop failed: " + err.Error(), false
	}
	slog.Warn("partition-settle: stopped a local copy that a certified recovery claim gave to another host",
		"ct", rec.Name, "host", p.host, "dest", dest, "proof", pr.ID, "claim_epoch", cert.Key.OwnerEpoch, "local_epoch", rec.OwnerEpoch)
	w.dropMatchingPause(pending)
	return true, "", false
}

// settleDecideContainer is settleDecide for a container: the record is the
// local copy's identity.
func settleDecideContainer(self, dest string, rec PauseRecord, proofs []corrosion.ProofRecord,
	verify func(corrosion.ActionProof) (corrosion.ClaimCertificate, error),
	destRuns func(dest string) (bool, string)) (corrosion.ProofRecord, corrosion.ClaimCertificate, string) {
	if destRuns == nil {
		return corrosion.ProofRecord{}, corrosion.ClaimCertificate{}, "no destination runtime check"
	}
	why := fmt.Sprintf("no verified recovery-claim certificate relocates this incarnation to %s at owner epoch >= %d", dest, rec.OwnerEpoch)
	for _, pr := range proofs {
		if pr.TargetKind != corrosion.ClaimKindContainer || pr.TargetName != rec.Name || pr.DestHost != dest || dest == self {
			continue
		}
		if why2, ok := proofExecutedByDest(pr); !ok {
			why = why2
			continue
		}
		cert, err := verify(pr.ActionProof)
		if err != nil {
			why = "proof " + pr.ID + ": " + err.Error()
			continue
		}
		if cert.Key.TargetKind != corrosion.ClaimKindContainer || cert.Key.TargetName != rec.Name {
			continue
		}
		if cert.Key.Incarnation != "" && cert.Key.Incarnation != rec.Incarnation {
			why = "proof " + pr.ID + "'s certificate decides another incarnation"
			continue
		}
		if cert.Key.OwnerEpoch < rec.OwnerEpoch {
			why = fmt.Sprintf("proof %s's certificate decides owner epoch %d, older than the local copy's %d", pr.ID, cert.Key.OwnerEpoch, rec.OwnerEpoch)
			continue
		}
		if ok, rwhy := destRuns(pr.DestHost); !ok {
			why = "proof " + pr.ID + ": " + rwhy
			continue
		}
		return pr, cert, ""
	}
	return corrosion.ProofRecord{}, corrosion.ClaimCertificate{}, why
}

// auditSettle writes the partition.settle audit row, the one writer both
// settle paths share (signed like every audit row; see
// TestAuditWriter_SettleRowsAreSigned). id is the caller's, so a retry of
// the same settle writes no second row.
func auditSettle(ctx context.Context, db *corrosion.Client, host, target, detail, id string) error {
	return corrosion.InsertAuditLog(ctx, db, corrosion.AuditRecord{
		ID: id, Username: "system", HostName: host,
		Action: "partition.settle", Target: target, Detail: detail, Result: "ok",
	})
}

// auditSystem writes one audit row as the system on host (signed through
// InsertAuditLog on the daemon's client): for the health loops' replication
// direction switches (corrosion.ReverseReplicationAudited).
func auditSystem(ctx context.Context, db *corrosion.Client, host, action, target, detail, result string) {
	_ = corrosion.InsertAuditLog(ctx, db, corrosion.AuditRecord{
		ID: randid.New(), Username: "system", HostName: host,
		Action: action, Target: target, Detail: detail, Result: result,
	})
}

// SettleDestroy is the reconciler's PauseSettleGuard: it runs destroy for
// rec's VM under the VM's mark lock, the lock every resume takes (resume)
// before it clears the mark, and only while no abandoned resume of it is out,
// the domain is still paused, and it still carries rec's mark. A resume can
// then begin only after the destroy, and finds no domain to resume. Never
// waiting on the lock: a mark write or a resume holding it declines this
// pass, and settle decides again on the next.
//
// Lock order as everywhere else: the mark lock, then p.mu briefly
// (resumeInFlight); the capture registry is not touched here.
func (p *PartitionPauser) SettleDestroy(rec PauseRecord, destroy func() error) error {
	if p.vms == nil {
		return fmt.Errorf("%w: no libvirt backend on the pauser", errPauseChanged)
	}
	l := p.markLock(rec.Name)
	if !l.TryLock() {
		return fmt.Errorf("%w: a write of its partition-pause mark, or its resume, is in flight", errPauseChanged)
	}
	defer l.Unlock()
	if p.resumeInFlight(rec.Key()) {
		return fmt.Errorf("%w: an abandoned resume of it has not returned", errPauseChanged)
	}
	st, err := p.vms.DomainStateReason(rec.Name)
	if err != nil {
		return fmt.Errorf("%w: its state is unreadable: %v", errPauseChanged, err)
	}
	if st.Reason != "paused" {
		return fmt.Errorf("%w: it is %s now", errPauseChanged, st.Reason)
	}
	if rec.Token != "" {
		tok, ok, err := p.vms.PartitionPauseMark(rec.Name)
		switch {
		case err != nil:
			return fmt.Errorf("%w: its partition-pause mark is unreadable: %v", errPauseChanged, err)
		case !ok || tok != rec.Token:
			return fmt.Errorf("%w: it no longer carries this pause's mark", errPauseChanged)
		}
	}
	return destroy()
}
