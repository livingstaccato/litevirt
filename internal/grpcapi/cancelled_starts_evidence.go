package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A libvirt daemon keeps its queue of jobs, a start waiting behind another
// job among them, in its own memory: a daemon that restarted has none of the
// jobs its predecessor had queued. The qemu driver lives in libvirtd (the
// monolithic daemon) or in virtqemud (the modular one); a host runs one of
// them. Its identity is its pid with the start time /proc gives the process
// (clock ticks since boot), which no later process of the same boot shares.
// When exactly one such process is found its identity is that; otherwise
// ("", none or both found, /proc unreadable) the daemon cannot be told, and
// nothing is concluded from it.
var libvirtDaemonNames = map[string]bool{"libvirtd": true, "virtqemud": true}

// libvirtdIdentityFromStat parses a /proc/<pid>/stat line into
// "<pid>:<starttime>".
func libvirtdIdentityFromStat(stat string) (string, bool) {
	lp, rp := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if lp <= 0 || rp < lp {
		return "", false
	}
	pid := strings.TrimSpace(stat[:lp])
	if _, err := strconv.Atoi(pid); err != nil {
		return "", false
	}
	// Fields after the command: state is field 3, starttime field 22.
	f := strings.Fields(stat[rp+1:])
	if len(f) < 20 {
		return "", false
	}
	if _, err := strconv.ParseUint(f[19], 10, 64); err != nil {
		return "", false
	}
	return pid + ":" + f[19], true
}

// readLibvirtdID is the running libvirt daemon's identity, or "".
func (s *Server) readLibvirtdID() string {
	if s.libvirtdID != nil {
		return s.libvirtdID()
	}
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	found := ""
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", d.Name(), "comm"))
		if err != nil || !libvirtDaemonNames[strings.TrimSpace(string(comm))] {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", d.Name(), "stat"))
		if err != nil {
			return ""
		}
		id, ok := libvirtdIdentityFromStat(string(stat))
		if !ok || found != "" {
			return "" // unreadable, or two daemons: not told
		}
		found = id
	}
	return found
}

// libvirtdRestartedSince reports whether the libvirt daemon that held r's
// start has been replaced since: both identities told, and they differ.
func (s *Server) libvirtdRestartedSince(r cancelledStartRecord) bool {
	if r.Libvirtd == "" {
		return false
	}
	cur := s.readLibvirtdID()
	return cur != "" && cur != r.Libvirtd
}

const (
	// heldStartEvaluator raises this host's conditions about the starts
	// `lv stop --force` cancelled.
	heldStartEvaluator = "held_start"
	// condCancelledStartsUnreadable: <data_dir>/cancelled-starts.json
	// cannot be read.
	condCancelledStartsUnreadable = "cancelled_starts_unreadable"
	// condCancelledStartKept: a cancelled start's record has been kept
	// longer than cancelledStartKeptAge.
	condCancelledStartKept = "cancelled_start_kept"
	// cancelledStartKeptAge is how long a record is kept before it is named.
	cancelledStartKeptAge = time.Hour
)

// judgeCancelledStartConditions raises or resolves this host's held_start
// conditions after a sweep.
func (s *Server) judgeCancelledStartConditions(ctx context.Context) {
	s.cancelledStarts.mu.Lock()
	loadErr := s.cancelledStarts.loadErr
	everRead := s.cancelledStarts.everRead
	type kept struct {
		VM      string `json:"vm"`
		Row     string `json:"row"`
		Created string `json:"created"`
	}
	var old []kept
	for _, r := range s.cancelledStartsLocked() {
		created, err := time.Parse(time.RFC3339Nano, r.Created)
		if err != nil || time.Since(created) < cancelledStartKeptAge {
			continue
		}
		row := r.Row
		if row == "" {
			row = "stopped"
		}
		old = append(old, kept{VM: r.VM, Row: row, Created: r.Created})
	}
	s.cancelledStarts.mu.Unlock()
	sort.Slice(old, func(i, j int) bool { return old[i].VM < old[j].VM })

	var unreadable map[string]any
	if loadErr != nil {
		held := "the VMs its last good read names"
		if !everRead {
			held = "every VM on this host in error (and every one stopped by its operator)"
		}
		unreadable = map[string]any{
			"file": s.cancelledStartsPath(), "error": loadErr.Error(),
			"detail": fmt.Sprintf("the record of cancelled starts cannot be read: no start can be cancelled with `lv stop --force`, and %s are neither recorded running nor restarted by their restart policy until it reads. Fix or remove the file; the next reconcile pass (30 s) reads it again", held),
		}
	}
	s.setHeldStartCondition(ctx, condCancelledStartsUnreadable, unreadable)

	var keptEv map[string]any
	if len(old) > 0 {
		keptEv = map[string]any{
			"records": old,
			"detail":  "a start `lv stop --force` cancelled is still recorded here, and its domain is destroyed if libvirt starts it. Until the record ends, a VM in error is neither recorded running nor restarted by its restart policy. `lv start <vm>` ends it; so do deleting or moving the VM, a host boot, or a restart of the libvirt daemon",
		}
	}
	s.setHeldStartCondition(ctx, condCancelledStartKept, keptEv)
}

// setHeldStartCondition raises this host's held_start condition code with
// evidence, or resolves it when evidence is nil.
func (s *Server) setHeldStartCondition(ctx context.Context, code string, evidence map[string]any) {
	if s.db == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, heldStartEvaluator, code, "host", s.hostName)
	if err != nil {
		return
	}
	if evidence == nil {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("held start: resolve condition", "code", code, "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: heldStartEvaluator, Code: code,
			SubjectKind: "host", SubjectID: s.hostName, Lifecycle: corrosion.ConditionConfirmed,
			FirstSeen: now, ConfirmedAt: now}
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	ev, _ := json.Marshal(evidence)
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("held start: raise condition", "code", code, "error", err)
	}
}
