package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// condReplicaRemovalHeld is raised on a host, one per pool, while the removal
// of a replica in that pool — a schedule's prune, the orphan sweep or a pool
// content delete — is held because whether a disk reads the replica through
// its backing chain cannot be told (replicaChainUser): a disk's header, or
// the disk rows, cannot be read. The guard stays strict (another VM's disk
// may back on the replica), so while one disk in the pool cannot be read no
// replica there is removed, and they pile up; the condition says which disk.
const condReplicaRemovalHeld = "replica_removal_held"

// replicaRemovalEvaluator is the evaluator replica_removal_held is raised
// under.
const replicaRemovalEvaluator = "replica_prune"

// vmEventReplicaRemovalHeld is the event of the VM a held replica is of, at
// most once per replicaHoldRenotify for each disk that holds it.
const vmEventReplicaRemovalHeld = "vm.replica_removal_held"

// replicaHoldRenotify is how often a hold that continues is named again: the
// event of the VM, and the condition's evidence refreshed.
var replicaHoldRenotify = time.Hour

// replicaHoldSample is how many held replicas a hold's evidence names.
const replicaHoldSample = 10

// replicaHoldState is this host's holds, by pool directory, then by the file
// that could not be read ("" for the rows).
type replicaHoldState struct {
	mu    sync.Mutex
	pools map[string]*replicaPoolHolds
}

type replicaPoolHolds struct {
	holds   map[string]*replicaHold
	written time.Time
	// clean is set once the pool's condition is known resolved, so a pass
	// with nothing held does not read it again.
	clean bool
}

type replicaHold struct {
	Disk     string   `json:"disk"`
	VM       string   `json:"vm,omitempty"`
	DiskName string   `json:"disk_name,omitempty"`
	Error    string   `json:"error"`
	Since    string   `json:"since"`
	Held     int      `json:"replicas_held"`
	Replicas []string `json:"replicas"`
	notified time.Time
}

// held records that the removal of replica (a replica of vm) in poolDir was
// held by err, reading disk d ("" path: the rows), and names it: the
// condition when the holds change or have not been written for
// replicaHoldRenotify, and vm's event as often.
func (h *replicaHoldState) held(ctx context.Context, s *Server, poolDir, replica, vm string, d corrosion.DiskRecord, err error) {
	if poolDir == "" || s.db == nil {
		return
	}
	now := time.Now()
	key := filepath.Clean(poolDir)
	h.mu.Lock()
	if h.pools == nil {
		h.pools = map[string]*replicaPoolHolds{}
	}
	p := h.pools[key]
	if p == nil {
		p = &replicaPoolHolds{holds: map[string]*replicaHold{}}
		h.pools[key] = p
	}
	p.clean = false
	hd := p.holds[d.Path]
	changed := false
	if hd == nil {
		hd = &replicaHold{Disk: d.Path, VM: d.VMName, DiskName: d.DiskName, Since: now.UTC().Format(time.RFC3339)}
		p.holds[d.Path] = hd
		changed = true
	}
	hd.Error = err.Error()
	if !slices.Contains(hd.Replicas, replica) {
		hd.Held++
		if len(hd.Replicas) < replicaHoldSample {
			hd.Replicas = append(hd.Replicas, replica)
			changed = true
		}
	}
	write := changed || now.Sub(p.written) >= replicaHoldRenotify
	if write {
		p.written = now
	}
	notify := vm != "" && (hd.notified.IsZero() || now.Sub(hd.notified) >= replicaHoldRenotify)
	if notify {
		hd.notified = now
	}
	var holds []replicaHold
	if write {
		holds = p.snapshot()
	}
	h.mu.Unlock()

	if write {
		s.writeReplicaHoldCondition(ctx, key, holds)
	}
	if notify {
		what := "the disk records of this pool's VMs cannot be read"
		if d.Path != "" {
			what = fmt.Sprintf("the backing chain of %s (VM %s disk %s) cannot be read", d.Path, d.VMName, d.DiskName)
		}
		s.recordVMEventSeverity(ctx, vm, vmEventReplicaRemovalHeld, "held", "warn", fmt.Sprintf(
			"the removal of replica %s on %s is held: %s, so whether a disk reads the replica cannot be told (%v). "+
				"No replica in that pool is removed until it can be; fix or move that file. `lv health` names it under %s",
			replica, s.hostName, what, err, condReplicaRemovalHeld))
	}
}

// cleared records a judgement in poolDir that read every disk it asked:
// every disk in the pool and every disk of vms. The holds it answers go,
// and once none is left the pool's condition is resolved.
func (h *replicaHoldState) cleared(ctx context.Context, s *Server, poolDir string, vms []string) {
	if poolDir == "" || s.db == nil {
		return
	}
	key := filepath.Clean(poolDir)
	h.mu.Lock()
	if h.pools == nil {
		h.pools = map[string]*replicaPoolHolds{}
	}
	p := h.pools[key]
	if p == nil {
		p = &replicaPoolHolds{holds: map[string]*replicaHold{}}
		h.pools[key] = p
	}
	if p.clean {
		h.mu.Unlock()
		return
	}
	before := len(p.holds)
	for f, hd := range p.holds {
		if f == "" || slices.Contains(vms, hd.VM) || safename.Contains(key, f) || safename.Contains(resolvedOr(key), f) {
			delete(p.holds, f)
		}
	}
	left := len(p.holds)
	var holds []replicaHold
	if left > 0 && left != before {
		holds = p.snapshot()
		p.written = time.Now()
	}
	h.mu.Unlock()

	switch {
	case left > 0 && left != before:
		s.writeReplicaHoldCondition(ctx, key, holds)
	case left == 0:
		if s.resolveReplicaHoldCondition(ctx, key) {
			h.mu.Lock()
			if q := h.pools[key]; q != nil && len(q.holds) == 0 {
				q.clean = true
			}
			h.mu.Unlock()
		}
	}
}

func (p *replicaPoolHolds) snapshot() []replicaHold {
	out := make([]replicaHold, 0, len(p.holds))
	for _, hd := range p.holds {
		c := *hd
		c.Replicas = slices.Clone(hd.Replicas)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Disk < out[j].Disk })
	return out
}

// replicaHoldSubject is the condition's subject id for the pool at poolDir:
// <host>/<pool>, or <host>/<directory> when no pool of this host has it.
func (s *Server) replicaHoldSubject(ctx context.Context, poolDir string) (subject, pool string) {
	pool = poolDir
	if pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName); err == nil {
		for _, p := range pools {
			if !isFileBasedDriver(p.Driver) {
				continue
			}
			dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target})
			if err == nil && (filepath.Clean(dir) == poolDir || resolvedOr(dir) == resolvedOr(poolDir)) {
				pool = p.Name
				break
			}
		}
	}
	return s.hostName + "/" + pool, pool
}

func (s *Server) writeReplicaHoldCondition(ctx context.Context, poolDir string, holds []replicaHold) {
	subject, pool := s.replicaHoldSubject(ctx, poolDir)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, replicaRemovalEvaluator, condReplicaRemovalHeld, "host", subject)
	if err != nil {
		slog.Warn("replica removal held: read its condition", "pool", pool, "error", err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: replicaRemovalEvaluator, Code: condReplicaRemovalHeld,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	ev, _ := json.Marshal(map[string]any{
		"host": s.hostName, "pool": pool, "directory": poolDir, "holds": holds,
		"detail": fmt.Sprintf("no replica in pool %s on %s is pruned, swept or deleted while whether a disk reads it through its backing chain "+
			"cannot be told; each hold names the file that cannot be read (\"\" when the disk records cannot be) and the replicas it has kept. "+
			"Fix that file's header or its storage, or move it out of the pool; the next prune or sweep that can read it clears this", pool, s.hostName),
	})
	row.Evidence = string(ev)
	row.Hosts = []string{s.hostName}
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("replica removal held: raise its condition", "pool", pool, "error", err)
	}
}

// resolveReplicaHoldCondition resolves the pool's condition; true once it is
// known resolved (or was never raised).
func (s *Server) resolveReplicaHoldCondition(ctx context.Context, poolDir string) bool {
	subject, pool := s.replicaHoldSubject(ctx, poolDir)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, replicaRemovalEvaluator, condReplicaRemovalHeld, "host", subject)
	if err != nil {
		return false
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		return true
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("replica removal held: resolve its condition", "pool", pool, "error", err)
		return false
	}
	return true
}
