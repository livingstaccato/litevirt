package corrosion

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
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// The pending-audit journal is how an action taken while the daemon is DOWN
// still reaches the audit log, signed and in its place in the host's chain.
//
// Nothing outside the daemon may write audit_log. Each host's rows form a
// sub-chain that only its daemon extends, and the daemon keeps the tail of that
// chain in memory (chainState). A row appended by a second process forks it: the
// daemon's next row links to the tail it remembers, reuses the sequence number
// the other process already took, and `lv audit verify` reports a broken link
// and a sequence gap on every node. The second process also has no signing key
// wired, so under a signing contract its row is reported as an unsigned row
// from a host that promised to sign. Both read as tampering, on a log nobody
// tampered with. TestAudit_SecondProcessRowForksTheChain pins that.
//
// So a process that is not the daemon records what it did HERE, in a
// host-local directory under the data dir, and the daemon folds each entry into
// the chain itself — at start, and on a short timer after that — signed with its
// own key, at the time the action actually happened. The directory is not
// replicated. An entry is removed only once its row is in audit_log, and a
// re-fold after a crash between the two finds the row by id and only removes
// the file, so an entry is folded once.
//
// The journal is not a general side door into the audit log. The daemon folds
// only the actions in pendingAuditActions, attributes them to root on this host
// whatever the entry says, and moves anything else aside as .rejected.

// PendingAuditDirName is the journal's directory under the daemon's data dir.
const PendingAuditDirName = "pending-audit"

// pendingAuditLockName serialises the journal. A writer holds it exclusively
// for the whole of the action it is recording, so the daemon never folds an
// entry whose outcome is still being decided; flock is released by the kernel
// when the writer exits, so a writer that crashed leaves its last word behind
// and the next fold takes it.
const pendingAuditLockName = ".lock"

// pendingAuditActions is the closed set of actions the daemon will fold.
var pendingAuditActions = map[string]bool{
	"user.reset-admin": true,
}

// PendingAuditEntry is one journalled action.
type PendingAuditEntry struct {
	ID string `json:"id"`
	// Timestamp is when the action happened, RFC3339 UTC. It is stored on the
	// folded row verbatim, which is the point: the row says when the password
	// changed, not when the daemon next started.
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	Result    string `json:"result"`
}

// PendingAuditJournal is a writer's handle on the journal, holding its lock.
type PendingAuditJournal struct {
	dir  string
	lock *os.File
}

// OpenPendingAuditJournal creates the journal under dataDir if needed and takes
// its lock, waiting for a fold in progress to finish.
func OpenPendingAuditJournal(dataDir string) (*PendingAuditJournal, error) {
	dir := filepath.Join(dataDir, PendingAuditDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create pending-audit journal %s: %w", dir, err)
	}
	lf, err := os.OpenFile(filepath.Join(dir, pendingAuditLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open pending-audit lock: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		lf.Close()
		return nil, fmt.Errorf("lock pending-audit journal: %w", err)
	}
	return &PendingAuditJournal{dir: dir, lock: lf}, nil
}

// Record writes e durably, replacing any earlier version with the same id. An
// empty ID or Timestamp is filled in and written back into e, so a caller can
// record an intent first and its outcome later under the same id.
func (j *PendingAuditJournal) Record(e *PendingAuditEntry) error {
	if e.ID == "" {
		e.ID = randid.New()
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(nowTSLayout)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := secretfile.Write(filepath.Join(j.dir, e.ID+".json"), data, 0o600); err != nil {
		return fmt.Errorf("write pending-audit entry: %w", err)
	}
	// The rename is durable only once the directory is.
	d, err := os.Open(j.dir)
	if err != nil {
		return fmt.Errorf("open pending-audit journal: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync pending-audit journal: %w", err)
	}
	return nil
}

// Close releases the journal lock.
func (j *PendingAuditJournal) Close() error {
	if j.lock == nil {
		return nil
	}
	err := j.lock.Close() // closing the descriptor releases the flock
	j.lock = nil
	return err
}

// FoldPendingAudit appends every journalled entry under dataDir to hostName's
// audit chain through c, and returns how many rows it wrote. Only the daemon
// calls it: c must be the client that owns hostName's chain.
//
// A journal that a writer is holding is left for the next fold rather than
// waited on, so a slow `lv` never stalls the daemon.
func FoldPendingAudit(ctx context.Context, c *Client, dataDir, hostName string) (int, error) {
	dir := filepath.Join(dataDir, PendingAuditDirName)
	lf, err := os.OpenFile(filepath.Join(dir, pendingAuditLockName), os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil // nothing was ever journalled here
	}
	if err != nil {
		return 0, fmt.Errorf("open pending-audit lock: %w", err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return 0, nil
		}
		return 0, fmt.Errorf("lock pending-audit journal: %w", err)
	}

	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return 0, err
	}
	type pending struct {
		path string
		e    PendingAuditEntry
		at   time.Time
	}
	var todo []pending
	for _, path := range names {
		if strings.HasPrefix(filepath.Base(path), ".") {
			continue // a writer's temp file
		}
		e, at, reason := readPendingAuditEntry(path)
		if reason != "" {
			rejectPendingAudit(path, reason)
			continue
		}
		todo = append(todo, pending{path: path, e: e, at: at})
	}
	// In the order they happened, so a burst of entries folds as it occurred.
	sort.Slice(todo, func(i, k int) bool {
		if !todo[i].at.Equal(todo[k].at) {
			return todo[i].at.Before(todo[k].at)
		}
		return todo[i].e.ID < todo[k].e.ID
	})

	folded := 0
	for _, p := range todo {
		// Already folded, and the file outlived a crash: remove it and move on.
		// Inserting again would be ignored by id, and InsertAuditLog advances its
		// cached tail whether or not the row took.
		rows, err := c.Query(ctx, `SELECT id FROM audit_log WHERE id = ?`, p.e.ID)
		if err != nil {
			return folded, fmt.Errorf("check pending-audit entry %s: %w", p.e.ID, err)
		}
		if len(rows) == 0 {
			if err := InsertAuditLog(ctx, c, AuditRecord{
				ID:        p.e.ID,
				Timestamp: p.at.UTC().Format(nowTSLayout),
				// Root on this host is the only party that can write the journal,
				// so that is who the row names, whatever the entry claims.
				Username: "root@" + hostName,
				HostName: hostName,
				Action:   p.e.Action,
				Target:   p.e.Target,
				Detail:   strings.TrimSpace(p.e.Detail + " recorded_by=pending-audit-journal"),
				Result:   p.e.Result,
			}); err != nil {
				return folded, fmt.Errorf("fold pending-audit entry %s: %w", p.e.ID, err)
			}
			folded++
		}
		if err := os.Remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return folded, fmt.Errorf("remove folded pending-audit entry %s: %w", p.e.ID, err)
		}
	}
	return folded, nil
}

// readPendingAuditEntry parses one journal file, returning a non-empty reason
// when it is not something the daemon will fold.
func readPendingAuditEntry(path string) (PendingAuditEntry, time.Time, string) {
	var e PendingAuditEntry
	fi, err := os.Lstat(path)
	if err != nil {
		return e, time.Time{}, "unreadable: " + err.Error()
	}
	if !fi.Mode().IsRegular() {
		return e, time.Time{}, "not a regular file"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return e, time.Time{}, "unreadable: " + err.Error()
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return e, time.Time{}, "not a journal entry: " + err.Error()
	}
	if e.ID == "" || filepath.Base(path) != e.ID+".json" {
		return e, time.Time{}, "entry id does not match its file name"
	}
	if !pendingAuditActions[e.Action] {
		return e, time.Time{}, fmt.Sprintf("action %q is not one the journal records", e.Action)
	}
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return e, time.Time{}, "timestamp does not parse: " + err.Error()
	}
	return e, at, ""
}

// rejectPendingAudit moves a file the daemon will not fold out of the journal's
// way, loudly, and keeps it for whoever investigates.
func rejectPendingAudit(path, reason string) {
	slog.Error("pending-audit journal: entry not folded into the audit log; it is kept "+
		"beside the journal as .rejected", "file", path, "reason", reason)
	if err := os.Rename(path, strings.TrimSuffix(path, ".json")+".rejected"); err != nil {
		slog.Error("pending-audit journal: could not set a rejected entry aside",
			"file", path, "error", err)
	}
}
