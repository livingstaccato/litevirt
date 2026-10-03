package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
//     the local copy's.
//
// It writes an audit row and the vm_settled condition, and leaves the shut-off
// domain to the existing leftover cleanup. It deletes nothing.

// SettleVerifier verifies a proof's recovery-claim certificate
// (grpcapi.Server.VerifySettleProof).
type SettleVerifier func(ctx context.Context, p corrosion.ActionProof) (corrosion.ClaimCertificate, error)

// SetSettleVerifier wires Layer 3. nil (the default) settles nothing: without
// a verifier there is no proof, and the guard stands as before.
func (r *Reconciler) SetSettleVerifier(fn SettleVerifier) { r.settleVerify = fn }

// localCopyID is what THIS host knows of its own copy of a workload.
type localCopyID struct {
	Incarnation string
	Epoch       int64
	EpochKnown  bool
	Source      string
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
		id.Incarnation, id.Epoch, id.EpochKnown = rec.Incarnation, rec.OwnerEpoch, true
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
	for _, p := range proofs {
		if p.TargetKind != corrosion.ClaimKindVM || p.TargetName != row.Name || p.DestHost != row.HostName || p.DestHost == self {
			continue
		}
		// A decided claim is not yet a running replacement: the proof must
		// have been EXECUTED, by its destination. A prepared or failed one
		// leaves the local copy the only one running.
		if why2, ok := proofExecutedByDest(p); !ok {
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
		// otherwise be the only copy.
		if ok, rwhy := destRuns(p.DestHost); !ok {
			why = "proof " + p.ID + ": " + rwhy
			continue
		}
		return p, cert, ""
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
		lister = corrosion.CertifiedTransferProofs
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
	if err := r.virt.DestroyDomain(domName); err != nil {
		return false, "destroy failed: " + err.Error(), local
	}
	detail := fmt.Sprintf("stopped the local copy (%s: incarnation %s, owner epoch %d): superseded by proof %s for %s, "+
		"certified at voter generation %d for owner epoch %d; definition and disks kept",
		local.Source, local.Incarnation, local.Epoch, p.ID, p.DestHost, cert.ConfigGeneration, cert.Key.OwnerEpoch)
	slog.Warn("partition-settle: stopped a local copy that a certified recovery claim gave to another host",
		"vm", domName, "host", r.hostName, "dest", p.DestHost, "proof", p.ID,
		"claim_epoch", cert.Key.OwnerEpoch, "local_epoch", local.Epoch, "evidence", local.Source)
	auditSettle(ctx, r.db, r.hostName, domName, detail)
	r.raiseSettled(ctx, domName, p, cert, local)
	if err := RemovePauseRecord(r.dataDir, PauseKindVM, domName); err != nil {
		slog.Warn("partition-settle: could not drop the pause record", "vm", domName, "error", err)
	}
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

func (r *Reconciler) raiseSettled(ctx context.Context, name string, p corrosion.ProofRecord, cert corrosion.ClaimCertificate, local localCopyID) {
	ts := r.now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(settledEvidence{Proof: p.ID, Dest: p.DestHost, Key: cert.Key, ConfigGeneration: cert.ConfigGeneration,
		Local:  map[string]any{"incarnation": local.Incarnation, "owner_epoch": local.Epoch, "evidence": local.Source},
		Detail: "this host came back holding a copy a decided recovery claim gave to another host; it stopped its copy (definition and disks kept)"})
	if err := corrosion.UpsertHealthCondition(ctx, r.db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondVMSettled,
		SubjectKind: "vm", SubjectID: name + "@" + r.hostName,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		Hosts: []string{r.hostName, p.DestHost}, Evidence: string(b), ObserveCount: 1,
		FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: r.hostName,
	}); err != nil {
		slog.Warn("partition-settle: could not record vm_settled", "vm", name, "error", err)
	}
}

// settleContainer is Layer 3 for a container this host paused: its own row is
// gone (a relocation tombstones it) and the container's one live row names
// another host, at the recorded incarnation, with a live relocate proof whose
// certificate verifies here at an owner epoch at least the recorded one. Then
// the frozen local copy is stopped (its rootfs kept), with a partition.settle
// audit row and ct_settled. It reports whether it settled, and if not, why.
func (p *PartitionPauser) settleContainer(ctx context.Context, rec PauseRecord) (bool, string) {
	if p.settle == nil || p.cts == nil {
		return false, ""
	}
	rows, err := p.db.Query(ctx, `SELECT host_name FROM containers WHERE name = ? AND deleted_at IS NULL AND host_name != ?`,
		rec.Name, p.host)
	if err != nil {
		return false, "container rows unreadable: " + err.Error()
	}
	if len(rows) != 1 {
		return false, fmt.Sprintf("%d live rows for the container on other hosts, not one", len(rows))
	}
	dest := rows[0].String("host_name")
	row, err := corrosion.GetContainer(ctx, p.db, dest, rec.Name)
	if err != nil || row == nil {
		return false, "the destination row is unreadable"
	}
	if corrosion.IncarnationOf(row.CreatedAt) != rec.Incarnation {
		return false, "the live row is another incarnation"
	}
	lister := p.settleProofs
	if lister == nil {
		lister = corrosion.CertifiedTransferProofs
	}
	proofs, err := lister(ctx, p.db, corrosion.ClaimKindContainer, rec.Name)
	if err != nil {
		return false, "proofs unreadable: " + err.Error()
	}
	pr, cert, why := settleDecideContainer(p.host, dest, rec, proofs, func(ap corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
		return p.settle(ctx, ap)
	}, destRunsVia(ctx, p.peerRuntime, rec.Name))
	if why != "" {
		return false, why
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = p.cts.Stop(sctx, rec.Name, 10)
	cancel()
	if err != nil {
		return false, "stop failed: " + err.Error()
	}
	detail := fmt.Sprintf("stopped the frozen local copy (incarnation %s, owner epoch %d): superseded by proof %s for %s, "+
		"certified at voter generation %d for owner epoch %d; rootfs kept", rec.Incarnation, rec.OwnerEpoch, pr.ID, dest,
		cert.ConfigGeneration, cert.Key.OwnerEpoch)
	slog.Warn("partition-settle: stopped a local copy that a certified recovery claim gave to another host",
		"ct", rec.Name, "host", p.host, "dest", dest, "proof", pr.ID, "claim_epoch", cert.Key.OwnerEpoch, "local_epoch", rec.OwnerEpoch)
	auditSettle(ctx, p.db, p.host, "container/"+rec.Name, detail)
	ts := p.now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(settledEvidence{Proof: pr.ID, Dest: dest, Key: cert.Key, ConfigGeneration: cert.ConfigGeneration,
		Local:  map[string]any{"incarnation": rec.Incarnation, "owner_epoch": rec.OwnerEpoch, "evidence": "partition-pause record"},
		Detail: "this host came back holding a container a decided recovery claim relocated; it stopped its copy (rootfs kept)"})
	if err := corrosion.UpsertHealthCondition(ctx, p.db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondCTSettled,
		SubjectKind: "container", SubjectID: rec.Name + "@" + p.host,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		Hosts: []string{p.host, dest}, Evidence: string(b), ObserveCount: 1,
		FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: p.host,
	}); err != nil {
		slog.Warn("partition-settle: could not record ct_settled", "ct", rec.Name, "error", err)
	}
	if err := p.store.remove(rec.Kind, rec.Name); err != nil {
		slog.Warn("partition-settle: could not drop the pause record", "ct", rec.Name, "error", err)
	}
	return true, ""
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
// TestAuditWriter_SettleRowsAreSigned).
func auditSettle(ctx context.Context, db *corrosion.Client, host, target, detail string) {
	_ = corrosion.InsertAuditLog(ctx, db, corrosion.AuditRecord{
		ID: randid.New(), Username: "system", HostName: host,
		Action: "partition.settle", Target: target, Detail: detail, Result: "ok",
	})
}
