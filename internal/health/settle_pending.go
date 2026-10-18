package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
)

// The pending-settle record keeps a VM settle's audit row and vm_settled
// condition from being lost.
//
// Settle destroys the local copy first, and the destroy cannot be undone. Once
// it has happened the domain is shut off, so no later pass settles it again: a
// record written only once, after the destroy, is lost for good if that write
// fails or the daemon dies before making it. So settleCertifiedMove writes this
// file BEFORE the destroy, holding everything the record needs, and each
// reconcile pass retries what it has not yet written. The file goes only once
// both are written.
//
// A file and not a row for the pause record's reason: it is a statement about
// what THIS host did to its own runtime, it must survive a restart, and it is
// never replicated. One file per VM under <data_dir>/settle-pending/vm-<name>.json.

// settlePendingDir is the record directory under the daemon's data dir.
const settlePendingDir = "settle-pending"

// Pending-settle phases.
const (
	// settlePhaseStopping: written before the destroy. A crash may have come
	// before it, so a retry asks the runtime whether the copy stopped.
	settlePhaseStopping = "stopping"
	// settlePhaseStopped: the destroy returned success.
	settlePhaseStopped = "stopped"
)

// settlePending is one VM settle whose record is not yet complete.
type settlePending struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Phase string `json:"phase"`
	// AuditID is the partition.settle row's id, fixed before the first try,
	// so a retry after a crash that came after the insert writes no second
	// row (InsertAuditLog ignores a known id).
	AuditID string `json:"audit_id"`
	Detail  string `json:"detail"`
	// At is when the settle stopped the copy (RFC3339): the condition's time,
	// whenever it is written.
	At               string             `json:"at"`
	Proof            string             `json:"proof"`
	Dest             string             `json:"dest"`
	Key              corrosion.ClaimKey `json:"key"`
	ConfigGeneration int64              `json:"config_generation"`
	LocalIncarnation string             `json:"local_incarnation"`
	LocalEpoch       int64              `json:"local_epoch"`
	LocalEvidence    string             `json:"local_evidence"`
	Audited          bool               `json:"audited"`
	Raised           bool               `json:"raised"`
}

type settlePendingStore struct{ dir string }

func newSettlePendingStore(dataDir string) settlePendingStore {
	if dataDir == "" {
		return settlePendingStore{}
	}
	return settlePendingStore{dir: filepath.Join(dataDir, settlePendingDir)}
}

func settlePendingFile(name string) (string, error) {
	if err := safename.ValidateVMName(name); err != nil {
		return "", err
	}
	return "vm-" + name + ".json", nil
}

// put writes rec durably: temp file, fsync, rename, directory fsync.
func (s settlePendingStore) put(rec settlePending) error {
	if s.dir == "" {
		return errors.New("partition settle: no data directory to record the settle in")
	}
	fn, err := settlePendingFile(rec.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", s.dir, err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "."+fn+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, fn)); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// remove deletes name's record. Absent is success.
func (s settlePendingStore) remove(name string) error {
	if s.dir == "" {
		return nil
	}
	fn, err := settlePendingFile(name)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.dir, fn)); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return syncDir(s.dir)
}

// list returns every record, sorted by name. A file that does not parse is
// skipped loudly and kept for whoever investigates: it names no settle this
// code can complete, and failing the whole list on it would stop every other
// record from being written.
func (s settlePendingStore) list() ([]settlePending, error) {
	if s.dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(s.dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []settlePending
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var rec settlePending
		if err := json.Unmarshal(b, &rec); err != nil || rec.Name == "" || rec.AuditID == "" {
			slog.Error("partition-settle: unreadable pending-settle record; its audit row and vm_settled will not be written",
				"file", path, "error", err)
			continue
		}
		if fn, err := settlePendingFile(rec.Name); err != nil || fn != e.Name() {
			slog.Error("partition-settle: pending-settle record does not match its file name; ignored", "file", path)
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// newSettlePending is the record of stopping domName's local copy on proof p.
func (r *Reconciler) newSettlePending(domName string, p corrosion.ProofRecord, cert corrosion.ClaimCertificate, local localCopyID) settlePending {
	return settlePending{
		Name: domName, Host: r.hostName, Phase: settlePhaseStopping, AuditID: randid.New(),
		Detail: fmt.Sprintf("stopped the local copy (%s: incarnation %s, owner epoch %d): superseded by proof %s for %s, "+
			"certified at voter generation %d for owner epoch %d; definition and disks kept",
			local.Source, local.Incarnation, local.Epoch, p.ID, p.DestHost, cert.ConfigGeneration, cert.Key.OwnerEpoch),
		At:    r.now().UTC().Format(time.RFC3339),
		Proof: p.ID, Dest: p.DestHost, Key: cert.Key, ConfigGeneration: cert.ConfigGeneration,
		LocalIncarnation: local.Incarnation, LocalEpoch: local.Epoch, LocalEvidence: local.Source,
	}
}

// settleWriteFault is a test seam: called before each record write with
// "audit" or "raise"; an error stands in for that write failing.
func (r *Reconciler) settleWriteFault(step string) error {
	if r.settleFault == nil {
		return nil
	}
	return r.settleFault(step)
}

// writeSettleRecord writes what rec has not yet written — the audit row, then
// vm_settled — saving progress to the store after each, and reports whether
// both are now written. stored says whether rec is in the store.
func (r *Reconciler) writeSettleRecord(ctx context.Context, store settlePendingStore, rec *settlePending, stored bool) bool {
	save := func() {
		if !stored {
			return
		}
		if err := store.put(*rec); err != nil {
			slog.Warn("partition-settle: could not save pending-settle progress", "vm", rec.Name, "error", err)
		}
	}
	if !rec.Audited {
		err := r.settleWriteFault("audit")
		if err == nil {
			err = auditSettle(ctx, r.db, r.hostName, rec.Name, rec.Detail, rec.AuditID)
		}
		if err != nil {
			slog.Warn("partition-settle: could not write the partition.settle audit row; retrying next pass",
				"vm", rec.Name, "error", err)
		} else {
			rec.Audited = true
			save()
		}
	}
	if !rec.Raised {
		err := r.settleWriteFault("raise")
		if err == nil {
			err = r.raiseSettled(ctx, *rec)
		}
		if err != nil {
			slog.Warn("partition-settle: could not record vm_settled; retrying next pass", "vm", rec.Name, "error", err)
		} else {
			rec.Raised = true
			save()
		}
	}
	return rec.Audited && rec.Raised
}

// retryPendingSettles completes the record of every settle a past pass or a
// past run of the daemon began and did not finish. localDomains is this pass's
// successful domain list.
//
// A record still in the stopping phase may predate a destroy that never
// happened (the daemon died between the two). If the copy is still live it was
// not stopped: the record is dropped, and the settle pass decides again. A copy
// that is shut off, or no longer defined (the leftover cleanup undefines a
// stopped copy), was stopped, and its record is written. A runtime that cannot
// be read keeps the record for the next pass.
func (r *Reconciler) retryPendingSettles(ctx context.Context, localDomains []string) {
	store := newSettlePendingStore(r.dataDir)
	recs, err := store.list()
	if err != nil {
		slog.Warn("partition-settle: pending-settle records unreadable", "error", err)
		return
	}
	if len(recs) == 0 {
		return
	}
	defined := make(map[string]bool, len(localDomains))
	for _, d := range localDomains {
		defined[d] = true
	}
	for i := range recs {
		rec := &recs[i]
		if rec.Host != "" && rec.Host != r.hostName {
			continue
		}
		if rec.Phase != settlePhaseStopped && defined[rec.Name] {
			st, err := r.virt.DomainStateReason(rec.Name)
			if err != nil {
				continue
			}
			if st.State == RuntimeRunning || st.Reason == "paused" || st.Reason == "pmsuspended" {
				slog.Warn("partition-settle: a settle begun before a restart never stopped its copy; the settle pass decides again",
					"vm", rec.Name, "state", st.State, "reason", st.Reason)
				if err := store.remove(rec.Name); err != nil {
					slog.Warn("partition-settle: could not drop the pending-settle record", "vm", rec.Name, "error", err)
				}
				continue
			}
		}
		if !r.writeSettleRecord(ctx, store, rec, true) {
			continue
		}
		slog.Info("partition-settle: wrote the record of an earlier settle", "vm", rec.Name, "proof", rec.Proof, "stopped_at", rec.At)
		if err := RemovePauseRecord(r.dataDir, PauseKindVM, rec.Name); err != nil {
			slog.Warn("partition-settle: could not drop the pause record", "vm", rec.Name, "error", err)
		}
		if err := store.remove(rec.Name); err != nil {
			slog.Warn("partition-settle: could not drop the pending-settle record", "vm", rec.Name, "error", err)
		}
	}
}
