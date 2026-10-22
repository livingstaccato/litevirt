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
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/randid"
)

// The pending-settle record keeps a settle's partition.settle audit row and
// its vm_settled / ct_settled condition from being lost.
//
// Settle stops the local copy first, and the stop cannot be undone. Once it has
// happened the copy is shut off, so no later pass settles it again: a record
// written only once, after the stop, is lost for good if that write fails or
// the daemon dies before making it. So both settle paths write this file
// BEFORE the stop, holding everything the record needs, and each pass retries
// what it has not yet written. The file goes only once both are written.
//
// A file and not a row for the pause record's reason: it is a statement about
// what THIS host did to its own runtime, it must survive a restart, and it is
// never replicated. One file per settle under
// <data_dir>/settle-pending/<kind>-<name>-<audit id>.json, so a second settle
// of the same name never overwrites a first whose record is still pending.

// settlePendingDir is the record directory under the daemon's data dir.
const settlePendingDir = "settle-pending"

// Pending-settle phases.
const (
	// settlePhaseStopping: written before the stop. The daemon may have died
	// before it, or the stop may have failed or taken effect despite an
	// error, so a retry asks the runtime whether the copy is shut off.
	settlePhaseStopping = "stopping"
	// settlePhaseStopped: the stop returned success, or a retry proved the
	// copy shut off.
	settlePhaseStopped = "stopped"
)

// settlePending is one settle whose record is not yet complete.
type settlePending struct {
	Kind  string `json:"kind"` // PauseKindVM | PauseKindContainer
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

func (rec settlePending) auditTarget() string {
	if rec.Kind == PauseKindContainer {
		return "container/" + rec.Name
	}
	return rec.Name
}

type settlePendingStore struct{ dir string }

func newSettlePendingStore(dataDir string) settlePendingStore {
	if dataDir == "" {
		return settlePendingStore{}
	}
	return settlePendingStore{dir: filepath.Join(dataDir, settlePendingDir)}
}

// settlePendingFile is rec's file name. The audit id is the randid hex this
// package mints; anything else is refused, so a name can never reach outside
// the directory.
func settlePendingFile(rec settlePending) (string, error) {
	base, err := pauseFileName(rec.Kind, rec.Name)
	if err != nil {
		return "", err
	}
	if rec.AuditID == "" || strings.Trim(rec.AuditID, "0123456789abcdef") != "" {
		return "", fmt.Errorf("partition settle: audit id %q is not a hex id", rec.AuditID)
	}
	return strings.TrimSuffix(base, ".json") + "-" + rec.AuditID + ".json", nil
}

// put writes rec durably: temp file, fsync, rename, directory fsync.
func (s settlePendingStore) put(rec settlePending) error {
	if s.dir == "" {
		return errors.New("partition settle: no data directory to record the settle in")
	}
	fn, err := settlePendingFile(rec)
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

// remove deletes rec's file. Absent is success.
func (s settlePendingStore) remove(rec settlePending) error {
	if s.dir == "" {
		return nil
	}
	fn, err := settlePendingFile(rec)
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

// list returns kind's records, sorted by name then time. A file that does not
// parse is skipped loudly and kept for whoever investigates: it names no
// settle this code can complete, and failing the whole list on it would stop
// every other record from being written.
func (s settlePendingStore) list(kind string) ([]settlePending, error) {
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
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasPrefix(e.Name(), kind+"-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var rec settlePending
		if err := json.Unmarshal(b, &rec); err != nil {
			slog.Error("partition-settle: unreadable pending-settle record; its audit row and condition will not be written",
				"file", path, "error", err)
			continue
		}
		if fn, err := settlePendingFile(rec); err != nil || fn != e.Name() || rec.Kind != kind {
			slog.Error("partition-settle: pending-settle record does not match its file name; ignored", "file", path)
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].At < out[j].At
	})
	return out, nil
}

// settleCopyState is what the runtime shows of a copy a stopping-phase record
// describes.
type settleCopyState int

const (
	// copyUnproven: neither live nor positively shut off (in transition,
	// crashed with its process kept, no state, unreadable): decide later.
	copyUnproven settleCopyState = iota
	// copyLive: running, or paused/suspended with its memory: the stop never
	// took effect.
	copyLive
	// copyStopped: positively shut off, or no longer defined.
	copyStopped
)

// settleRecorder writes and retries pending-settle records for one host. The
// reconciler (VMs) and the partition pauser (containers) each hold one.
type settleRecorder struct {
	db      *corrosion.Client
	host    string
	dataDir string
	now     func() time.Time
	// fault is a test seam: called before each record write with "phase",
	// "audit" or "raise"; an error stands in for that write failing.
	fault func(step string) error
	// foreignLogged rate-limits the line for a record another host name wrote
	// (file name → last logged).
	foreignLogged sync.Map
	// captures is the host's memory snapshot registry: dropping a VM's
	// pause record drops the pauser's hold with it.
	captures *lv.CaptureRegistry
	// waitLogged rate-limits the line for a record waiting on a copy that is
	// neither live nor shut off (file name → last logged).
	waitLogged sync.Map
	// provenStopped holds the records (file name: one per settle → the
	// detail as proven) whose copy this run saw stopped, so a stopped phase
	// that could not be saved does not let a later live copy of the name drop
	// the record.
	provenStopped sync.Map
	// retryCursor (kind → record file) is where the last budgeted retry pass
	// stopped; the next starts after it. Only the owning loop touches it.
	retryCursor map[string]string
}

// settleWaitLogEvery is how often a record still waiting on its copy is
// reported again.
const settleWaitLogEvery = 10 * time.Minute

// noteWaiting reports, at most once per settleWaitLogEvery per record, a
// stopping-phase record whose copy is neither live nor positively shut off,
// so an operator can see why its audit row has not arrived.
func (w *settleRecorder) noteWaiting(rec settlePending, seen string) {
	fn, _ := settlePendingFile(rec)
	now := w.now()
	if last, ok := w.waitLogged.Load(fn); ok && now.Sub(last.(time.Time)) < settleWaitLogEvery {
		return
	}
	w.waitLogged.Store(fn, now)
	slog.Warn("partition-settle: a settle's audit row and condition wait until its copy is positively shut off or gone",
		"kind", rec.Kind, "name", rec.Name, "observed", seen, "proof", rec.Proof, "audit_id", rec.AuditID)
}

// foreignRecordLogEvery is how often a record left under another host name is
// reported again.
const foreignRecordLogEvery = time.Hour

func (w *settleRecorder) store() settlePendingStore { return newSettlePendingStore(w.dataDir) }

// newPending is the record of a settle of kind/name on proof p.
func (w *settleRecorder) newPending(kind, name, detail string, p corrosion.ProofRecord, cert corrosion.ClaimCertificate,
	incarnation string, epoch int64, evidence string) settlePending {
	return settlePending{
		Kind: kind, Name: name, Host: w.host, Phase: settlePhaseStopping, AuditID: randid.New(), Detail: detail,
		At:    w.now().UTC().Format(time.RFC3339),
		Proof: p.ID, Dest: p.DestHost, Key: cert.Key, ConfigGeneration: cert.ConfigGeneration,
		LocalIncarnation: incarnation, LocalEpoch: epoch, LocalEvidence: evidence,
	}
}

// stopRecorded saves rec, runs stop, and on success writes the record. A
// record that cannot be saved does not hold the stop back: the copy is
// superseded either way, and the record is then written once. A stop that
// returns an error keeps the saved record: the stop may have taken effect,
// and the retry asks the runtime. It returns stop's error.
func (w *settleRecorder) stopRecorded(ctx context.Context, rec settlePending, stop func() error) error {
	store := w.store()
	stored := true
	if err := store.put(rec); err != nil {
		stored = false
		slog.Warn("partition-settle: could not save the pending-settle record; the settle's audit row and condition "+
			"are written once and not retried", "kind", rec.Kind, "name", rec.Name, "error", err)
	}
	if err := stop(); err != nil {
		return err
	}
	rec.Phase = settlePhaseStopped
	if stored {
		w.markProven(rec)
		if err := w.putStopped(store, rec); err != nil {
			slog.Warn("partition-settle: could not mark the pending-settle record stopped", "kind", rec.Kind, "name", rec.Name, "error", err)
		}
	}
	if w.write(ctx, store, &rec, stored) && stored {
		w.dropRecord(store, rec)
	}
	return nil
}

// markProven notes that this run saw rec's copy stopped.
func (w *settleRecorder) markProven(rec settlePending) {
	if fn, err := settlePendingFile(rec); err == nil {
		w.provenStopped.Store(fn, rec.Detail)
	}
}

// provenThisRun reports whether this run saw rec's copy stopped, and the
// record's detail as it was then.
func (w *settleRecorder) provenThisRun(rec settlePending) (string, bool) {
	fn, err := settlePendingFile(rec)
	if err != nil {
		return "", false
	}
	d, ok := w.provenStopped.Load(fn)
	if !ok {
		return "", false
	}
	return d.(string), true
}

// dropRecord removes rec's file, and its in-run proof once the file is gone.
func (w *settleRecorder) dropRecord(store settlePendingStore, rec settlePending) {
	if err := store.remove(rec); err != nil {
		slog.Warn("partition-settle: could not drop the pending-settle record", "kind", rec.Kind, "name", rec.Name, "error", err)
		return
	}
	if fn, err := settlePendingFile(rec); err == nil {
		w.provenStopped.Delete(fn)
	}
}

// putStopped saves rec in the stopped phase.
func (w *settleRecorder) putStopped(store settlePendingStore, rec settlePending) error {
	if err := w.injected("phase"); err != nil {
		return err
	}
	return store.put(rec)
}

func (w *settleRecorder) injected(step string) error {
	if w.fault == nil {
		return nil
	}
	return w.fault(step)
}

// write writes what rec has not yet written — the audit row, then the
// condition — saving progress after each, and reports whether both are now
// written. stored says whether rec is in the store.
func (w *settleRecorder) write(ctx context.Context, store settlePendingStore, rec *settlePending, stored bool) bool {
	save := func() {
		if !stored {
			return
		}
		if err := store.put(*rec); err != nil {
			slog.Warn("partition-settle: could not save pending-settle progress", "kind", rec.Kind, "name", rec.Name, "error", err)
		}
	}
	if !rec.Audited {
		err := w.injected("audit")
		if err == nil {
			err = auditSettle(ctx, w.db, w.host, rec.auditTarget(), rec.Detail, rec.AuditID)
		}
		if err != nil {
			slog.Warn("partition-settle: could not write the partition.settle audit row; retrying next pass",
				"kind", rec.Kind, "name", rec.Name, "error", err)
		} else {
			rec.Audited = true
			save()
		}
	}
	if !rec.Raised {
		err := w.injected("raise")
		if err == nil {
			err = w.raise(ctx, *rec)
		}
		if err != nil {
			slog.Warn("partition-settle: could not raise the settled condition; retrying next pass",
				"kind", rec.Kind, "name", rec.Name, "error", err)
		} else {
			rec.Raised = true
			save()
		}
	}
	return rec.Audited && rec.Raised
}

// raise raises rec's vm_settled or ct_settled, dated when the copy stopped.
func (w *settleRecorder) raise(ctx context.Context, rec settlePending) error {
	ts := rec.At
	if ts == "" {
		ts = w.now().UTC().Format(time.RFC3339)
	}
	code, kind := corrosion.CondVMSettled, "vm"
	detail := "this host came back holding a copy a decided recovery claim gave to another host; it stopped its copy (definition and disks kept)"
	if rec.Kind == PauseKindContainer {
		code, kind = corrosion.CondCTSettled, "container"
		detail = "this host came back holding a container a decided recovery claim relocated; it stopped its copy (rootfs kept)"
	}
	b, _ := json.Marshal(settledEvidence{Proof: rec.Proof, Dest: rec.Dest, Key: rec.Key, ConfigGeneration: rec.ConfigGeneration,
		Local:  map[string]any{"incarnation": rec.LocalIncarnation, "owner_epoch": rec.LocalEpoch, "evidence": rec.LocalEvidence},
		Detail: detail})
	return corrosion.UpsertHealthCondition(ctx, w.db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: code,
		SubjectKind: kind, SubjectID: rec.Name + "@" + w.host,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		Hosts: []string{w.host, rec.Dest}, Evidence: string(b), ObserveCount: 1,
		FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: w.host,
	})
}

// retry completes the record of every kind settle a past pass or a past run
// of the daemon began and did not finish. state classifies a copy for a
// stopping-phase record, with what was observed when it is not the settle's
// own stop (for the audit row).
//
// A stopping-phase record completes only on POSITIVE proof the copy is shut
// off, as cleanableLeftover decides: a live copy was not stopped, so its
// record is dropped and the settle decides again; anything else waits. Once
// proven, the record is saved in the stopped phase before anything is
// written, so a later live copy of the name never drops a stop that happened;
// a stop this run proved counts even when that save failed, and the save is
// retried on every pass until it holds. A stopping-phase
// record that already wrote part of its record was proven then.
//
// more, when not nil, is asked before each record and stops the pass when it
// says no; the records not reached wait for the next pass. When it says yes
// it gives the record's deadline: everything the record does runs under a
// context that ends then (a partition-pause pass bounds each step, §4.1 R).
func (w *settleRecorder) retry(ctx context.Context, kind string, state func(ctx context.Context, name string) (settleCopyState, string),
	more func() (time.Time, bool)) {
	store := w.store()
	recs, err := store.list(kind)
	if err != nil {
		slog.Warn("partition-settle: pending-settle records unreadable", "kind", kind, "error", err)
		return
	}
	if more != nil {
		// A budgeted pass starts where the last one stopped, so one record
		// that is slow on every pass cannot starve the rest.
		sort.Slice(recs, func(i, j int) bool { return settleKey(recs[i]) < settleKey(recs[j]) })
		if cur := w.retryCursor[kind]; cur != "" {
			k := sort.Search(len(recs), func(i int) bool { return settleKey(recs[i]) > cur })
			recs = append(append([]settlePending{}, recs[k:]...), recs[:k]...)
		}
	}
	for i := range recs {
		if more == nil {
			w.retryOne(ctx, store, &recs[i], state)
			continue
		}
		deadline, ok := more()
		if !ok {
			return
		}
		if w.retryCursor == nil {
			w.retryCursor = map[string]string{}
		}
		w.retryCursor[kind] = settleKey(recs[i])
		rctx, cancel := context.WithDeadline(ctx, deadline)
		w.retryOne(rctx, store, &recs[i], state)
		cancel()
	}
}

// retryOne is retry for one record.
func (w *settleRecorder) retryOne(ctx context.Context, store settlePendingStore, rec *settlePending,
	state func(ctx context.Context, name string) (settleCopyState, string)) {
	if rec.Host != w.host {
		w.noteForeign(*rec)
		return
	}
	proven := rec.Phase == settlePhaseStopped || rec.Audited || rec.Raised
	if detail, ok := w.provenThisRun(*rec); ok && !proven {
		// The stopped-phase save failed when this run proved the stop;
		// retry it now, since the in-run proof dies with the daemon.
		rec.Phase, rec.Detail, proven = settlePhaseStopped, detail, true
		if err := w.putStopped(store, *rec); err != nil {
			slog.Warn("partition-settle: could not mark the pending-settle record stopped", "kind", rec.Kind, "name", rec.Name, "error", err)
		}
	}
	if !proven {
		st, seen := state(ctx, rec.Name)
		switch st {
		case copyLive:
			slog.Warn("partition-settle: a settle begun before a restart or a failed stop never stopped its copy; "+
				"the settle decides again", "kind", rec.Kind, "name", rec.Name)
			if err := store.remove(*rec); err != nil {
				slog.Warn("partition-settle: could not drop the pending-settle record", "kind", rec.Kind, "name", rec.Name, "error", err)
			}
			return
		case copyUnproven:
			w.noteWaiting(*rec, seen)
			return
		}
		if seen != "" && !strings.Contains(rec.Detail, "; found ") {
			rec.Detail += "; found " + seen + " after a restart or a failed stop, so the settle's own stop may not be what stopped it"
		}
		rec.Phase = settlePhaseStopped
		w.markProven(*rec)
		if err := w.putStopped(store, *rec); err != nil {
			slog.Warn("partition-settle: could not mark the pending-settle record stopped", "kind", rec.Kind, "name", rec.Name, "error", err)
		}
	}
	if !w.write(ctx, store, rec, true) {
		return
	}
	slog.Info("partition-settle: wrote the record of an earlier settle", "kind", rec.Kind, "name", rec.Name,
		"proof", rec.Proof, "stopped_at", rec.At)
	w.dropMatchingPause(*rec)
	w.dropRecord(store, *rec)
}

// dropMatchingPause drops the pause record of the copy rec settled, and only
// that one: a later pause of the same name (the workload came back and was
// paused again) is another incarnation or a later owner epoch, and its record
// is what resumes it.
func (w *settleRecorder) dropMatchingPause(rec settlePending) {
	pr, ok, err := ReadPauseRecord(w.dataDir, rec.Kind, rec.Name)
	if err != nil || !ok {
		return
	}
	if pr.Incarnation != rec.LocalIncarnation || pr.OwnerEpoch != rec.LocalEpoch {
		return
	}
	if err := RemovePauseRecord(w.dataDir, rec.Kind, rec.Name); err != nil {
		slog.Warn("partition-settle: could not drop the pause record", "kind", rec.Kind, "name", rec.Name, "error", err)
		return
	}
	if rec.Kind == PauseKindVM {
		w.captures.Release(rec.Name)
	}
}

// noteForeign reports, at most once an hour per file, a record another host
// name wrote here (a renamed host): this host cannot write a record in
// another host's name, so it stays until an operator removes it.
func (w *settleRecorder) noteForeign(rec settlePending) {
	fn, _ := settlePendingFile(rec)
	now := w.now()
	if last, ok := w.foreignLogged.Load(fn); ok && now.Sub(last.(time.Time)) < foreignRecordLogEvery {
		return
	}
	w.foreignLogged.Store(fn, now)
	slog.Warn("partition-settle: a pending-settle record names another host; it is not written from here and stays until removed",
		"file", filepath.Join(w.store().dir, fn), "record_host", rec.Host, "host", w.host, "kind", rec.Kind, "name", rec.Name)
}

// vmSettleCopyState classifies a VM copy: not defined, or shut off for a
// reason that keeps no memory, is stopped; running, paused, pmsuspended is
// live; a managed-save image, a transition, a crash with its process kept,
// no state or an unreadable state is unproven.
func vmSettleCopyState(defined map[string]bool, stateOf func(string) (lv.DomainStatus, error), name string) (settleCopyState, string) {
	if !defined[name] {
		return copyStopped, "no longer defined"
	}
	st, err := stateOf(name)
	if err != nil {
		return copyUnproven, "state unreadable: " + err.Error()
	}
	switch {
	case st.State == RuntimeRunning || st.Reason == "paused" || st.Reason == "pmsuspended":
		return copyLive, ""
	case st.State == "stopped" && st.Reason != "saved":
		if st.Reason == "destroyed" {
			return copyStopped, ""
		}
		return copyStopped, "shut off (reason " + st.Reason + ")"
	}
	return copyUnproven, st.State + "/" + st.Reason
}

// retryPendingSettles completes this host's VM settle records
// (settleRecorder.retry). localDomains is this pass's successful domain list.
func (r *Reconciler) retryPendingSettles(ctx context.Context, localDomains []string) {
	defined := make(map[string]bool, len(localDomains))
	for _, d := range localDomains {
		defined[d] = true
	}
	r.settleRec().retry(ctx, PauseKindVM, func(_ context.Context, name string) (settleCopyState, string) {
		return vmSettleCopyState(defined, r.virt.DomainStateReason, name)
	}, nil)
}

// settleRec is the reconciler's settle recorder, built on first use.
func (r *Reconciler) settleRec() *settleRecorder {
	r.settleRecOnce.Do(func() {
		r.settleRecorder = &settleRecorder{db: r.db, host: r.hostName, dataDir: r.dataDir, now: func() time.Time { return r.now() },
			captures: r.captures,
			fault: func(step string) error {
				if r.settleFault == nil {
					return nil
				}
				return r.settleFault(step)
			}}
	})
	return r.settleRecorder
}

// settleRec is the pauser's settle recorder, built on first use.
func (p *PartitionPauser) settleRec() *settleRecorder {
	p.settleRecOnce.Do(func() {
		p.settleRecorder = &settleRecorder{db: p.db, host: p.host, dataDir: p.dataDir, now: func() time.Time { return p.now() },
			captures: p.captures,
			fault: func(step string) error {
				if p.settleFault == nil {
					return nil
				}
				return p.settleFault(step)
			}}
	})
	return p.settleRecorder
}

// ctSettleCopyState classifies a container copy: absent from a successful
// listing, or stopped, is stopped; running (frozen folds into running) is
// live; anything else, or a runtime that cannot be asked, is unproven.
func (p *PartitionPauser) ctSettleCopyState(ctx context.Context, name string) (settleCopyState, string) {
	if p.cts == nil {
		return copyUnproven, "no container runtime"
	}
	names, err := p.cts.List(ctx)
	if err != nil {
		return copyUnproven, "runtime listing failed: " + err.Error()
	}
	listed := false
	for _, n := range names {
		if n == name {
			listed = true
			break
		}
	}
	if !listed {
		return copyStopped, "no longer listed by the runtime"
	}
	st, err := p.cts.State(ctx, name)
	if err != nil {
		return copyUnproven, "state unreadable: " + err.Error()
	}
	switch st {
	case lxc.StateRunning:
		return copyLive, ""
	case lxc.StateStopped:
		return copyStopped, "stopped"
	}
	return copyUnproven, "state " + string(st)
}

// retryPendingSettles completes this host's container settle records
// (settleRecorder.retry), each a step of the resume pass.
func (p *PartitionPauser) retryPendingSettles(ctx context.Context, pass *resumePass) {
	first := true
	p.settleRec().retry(ctx, PauseKindContainer, func(sctx context.Context, name string) (settleCopyState, string) {
		return p.ctSettleCopyState(sctx, name)
	}, func() (time.Time, bool) {
		st, ok := pass.step(first)
		first = false
		return st.deadline, ok
	})
}

// settleKey orders pending-settle records for a budgeted pass.
func settleKey(r settlePending) string {
	if fn, err := settlePendingFile(r); err == nil {
		return fn
	}
	return r.Kind + "/" + r.Name + "/" + r.AuditID
}
