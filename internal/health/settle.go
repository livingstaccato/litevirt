package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

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
func (r *Reconciler) localVMIdentity(name string) localCopyID {
	if rec, ok, err := ReadPauseRecord(r.dataDir, PauseKindVM, name); err == nil && ok && rec.Incarnation != "" {
		return localCopyID{Incarnation: rec.Incarnation, Epoch: rec.OwnerEpoch, EpochKnown: true, Source: "partition-pause record"}
	}
	var id localCopyID
	if inc, ok, err := r.virt.GetDomainManagedIncarnation(name); err == nil && ok {
		id.Incarnation, id.Source = inc, "managed stamp"
	}
	if e, ok, err := r.virt.GetDomainOwnerEpoch(name); err == nil && ok {
		id.Epoch, id.EpochKnown = e, true
	} else if r.dataDir != "" {
		if e, ok, err := ReadVMOwnerEpochMarker(r.dataDir, name); err == nil && ok {
			id.Epoch, id.EpochKnown = e, true
		}
	}
	return id
}

// settleDecide is the decision of §6, separate so every clause is testable.
// It returns the proof and certificate that authorise stopping the local copy,
// or why there is none.
func settleDecide(self string, row *corrosion.VMRecord, local localCopyID, proofs []corrosion.ProofRecord,
	verify func(corrosion.ActionProof) (corrosion.ClaimCertificate, error)) (corrosion.ProofRecord, corrosion.ClaimCertificate, string) {
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
	}
	why := fmt.Sprintf("no verified recovery-claim certificate gives this incarnation to %s at owner epoch >= %d", row.HostName, local.Epoch)
	for _, p := range proofs {
		if p.TargetKind != corrosion.ClaimKindVM || p.TargetName != row.Name || p.DestHost != row.HostName || p.DestHost == self {
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
		return p, cert, ""
	}
	return none, corrosion.ClaimCertificate{}, why
}

// settleCertifiedMove stops domName's local copy when a certified claim gave
// it away (the decision above). It reports whether it did.
func (r *Reconciler) settleCertifiedMove(ctx context.Context, domName string, vm *corrosion.VMRecord) (bool, string) {
	if r.settleVerify == nil {
		return false, "no certificate verifier wired"
	}
	local := r.localVMIdentity(domName)
	lister := r.settleProofs
	if lister == nil {
		lister = corrosion.CertifiedTransferProofs
	}
	proofs, err := lister(ctx, r.db, corrosion.ClaimKindVM, domName)
	if err != nil {
		return false, "proofs unreadable: " + err.Error()
	}
	p, cert, why := settleDecide(r.hostName, vm, local, proofs, func(ap corrosion.ActionProof) (corrosion.ClaimCertificate, error) {
		return r.settleVerify(ctx, ap)
	})
	if why != "" {
		return false, why
	}
	if err := r.virt.DestroyDomain(domName); err != nil {
		return false, "destroy failed: " + err.Error()
	}
	detail := fmt.Sprintf("stopped the local copy (%s: incarnation %s, owner epoch %d): superseded by proof %s for %s, "+
		"certified at voter generation %d for owner epoch %d; definition and disks kept",
		local.Source, local.Incarnation, local.Epoch, p.ID, p.DestHost, cert.ConfigGeneration, cert.Key.OwnerEpoch)
	slog.Warn("partition-settle: stopped a local copy that a certified recovery claim gave to another host",
		"vm", domName, "host", r.hostName, "dest", p.DestHost, "proof", p.ID,
		"claim_epoch", cert.Key.OwnerEpoch, "local_epoch", local.Epoch, "evidence", local.Source)
	_ = corrosion.InsertAuditLog(ctx, r.db, corrosion.AuditRecord{
		ID: randid.New(), Username: "system", HostName: r.hostName,
		Action: "partition.settle", Target: domName, Detail: detail, Result: "ok",
	})
	r.raiseSettled(ctx, domName, p, cert, local)
	if err := RemovePauseRecord(r.dataDir, PauseKindVM, domName); err != nil {
		slog.Warn("partition-settle: could not drop the pause record", "vm", domName, "error", err)
	}
	return true, ""
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
