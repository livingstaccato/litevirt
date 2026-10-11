package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// Proving a ceph key at start. A start proves with `rbd info` that this
// host's key opens the VM's disks (ensureCephSecretsForVM). The proof is
// about the KEY: one success proves it for every disk of that pool, so it is
// remembered for cephKeyProofTTL per (litevirt pool, rbd pool, client, key
// fingerprint, conf, monitors). The VMs a failover starts after the first on
// a pool then need no probe, and are not deferred for want of time to prove
// what was just proven. A rotated keyring is a new fingerprint, proven again.
// A remembered proof never makes a start refuse: an image that is gone is
// still reported, by qemu, when the domain starts.

// cephKeyProofTTL is how long a proven key is taken as proven.
const cephKeyProofTTL = 2 * time.Minute

// cephKeyFailTTL is how long a probe that got no answer is remembered: about
// one reconcile pass (15 s), so a pool that does not answer is probed on
// every other pass, not by every VM on it in every pass. Only a reconcile
// walk consults it (health.InReconcilerWalk); an operator's start always
// probes.
const cephKeyFailTTL = 15 * time.Second

// cephProbeFloor is the least time a walk's first probe runs on: with less,
// rbd cannot even reach the monitors (client_mount_timeout), and the start is
// deferred for time instead.
const cephProbeFloor = 2 * time.Second

// cephProofNow is the proof cache's clock (tests move it).
var cephProofNow = time.Now

type cephKeyProofs struct {
	mu sync.Mutex
	at map[string]time.Time // cephProofKey → when it was proven
	// failed: cephProofKey → the last probe through it that got no answer,
	// and the VM it was for.
	failed map[string]cephProbeFailure
	// own: VM + cephProofKey → when that VM's OWN probe through the key got
	// no answer. A proof of the key another VM's probe made says nothing
	// about this VM's image (an inactive PG under it), so it does not skip
	// this VM's probe while the record lasts (cephKeyProofTTL); only this
	// VM's own answered probe clears it (Breaker R-1).
	own map[string]time.Time
}

func ownKey(vm, key string) string { return vm + "\x00" + key }

// ownFailed reports whether vm's own probe through key got no answer within
// cephKeyProofTTL.
func (c *cephKeyProofs) ownFailed(vm, key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.own[ownKey(vm, key)]
	return ok && cephProofNow().Sub(t) < cephKeyProofTTL
}

// provedFor records vm's own answered probe through key: the key is proven,
// and vm's own failure record is gone.
func (c *cephKeyProofs) provedFor(vm, key string) {
	c.put(key)
	c.mu.Lock()
	delete(c.own, ownKey(vm, key))
	c.mu.Unlock()
}

type cephProbeFailure struct {
	at time.Time
	vm string
}

func (c *cephKeyProofs) put(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at == nil {
		c.at = map[string]time.Time{}
	}
	now := cephProofNow()
	c.at[key] = now
	delete(c.failed, key)
	for k, t := range c.at {
		if now.Sub(t) >= cephKeyProofTTL {
			delete(c.at, k)
		}
	}
}

// fail remembers that a probe through key, for vm, got no answer.
func (c *cephKeyProofs) fail(key, vm string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed == nil {
		c.failed = map[string]cephProbeFailure{}
	}
	now := cephProofNow()
	c.failed[key] = cephProbeFailure{at: now, vm: vm}
	for k, f := range c.failed {
		if now.Sub(f.at) >= cephKeyFailTTL {
			delete(c.failed, k)
		}
	}
	if c.own == nil {
		c.own = map[string]time.Time{}
	}
	c.own[ownKey(vm, key)] = now
	for k, t := range c.own {
		if now.Sub(t) >= cephKeyProofTTL {
			delete(c.own, k)
		}
	}
}

// anyFailed reports whether some probe failure is still remembered.
func (c *cephKeyProofs) anyFailed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := cephProofNow()
	for _, f := range c.failed {
		if now.Sub(f.at) < cephKeyFailTTL {
			return true
		}
	}
	return false
}

// failedFor reports whether a remembered failure covers one of vm's probes,
// and whether one of those failures was vm's own probe.
func (c *cephKeyProofs) failedFor(vm string, probes []cephProbe) (failed, own bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := cephProofNow()
	for _, p := range probes {
		if f, ok := c.failed[p.key]; ok && p.key != "" && now.Sub(f.at) < cephKeyFailTTL {
			failed = true
			own = own || f.vm == vm
		}
	}
	return failed, own
}

func (c *cephKeyProofs) fresh(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.at[key]
	return ok && cephProofNow().Sub(t) < cephKeyProofTTL
}

// cephProofKey names what a successful probe through cfg proves for images
// in rbdPool; "" when the key cannot be read (never remembered).
func cephProofKey(cfg storage.Config, rbdPool string) string {
	fp, ok, err := storage.CephKeyFingerprintOf(cfg.Options)
	if err != nil || !ok {
		return ""
	}
	return strings.Join([]string{cfg.Name, rbdPool, clientOf(cfg), fp, cfg.Options["conf"], cfg.Options["mon_host"]}, "\x00")
}

// startDeferredError is a start that did not fail but has to wait — Ceph did
// not answer, or there was no time left to ask it. To a gRPC caller it is
// the Unavailable it wraps; to the reconciler it is health.ErrStartDeferred,
// which re-drives the start on a later pass rather than parking a proof-less
// one in error (deferPendingStart).
//
// kind says why, for the order of the reconciler's next walk: nil for want of
// time, health.ErrStartStorageDown or health.ErrStartProbeFailed when the
// storage did not answer.
type startDeferredError struct {
	err  error
	kind error
}

func (e *startDeferredError) Error() string { return e.err.Error() }

func (e *startDeferredError) Unwrap() []error {
	if e.kind != nil {
		return []error{e.err, health.ErrStartDeferred, e.kind}
	}
	return []error{e.err, health.ErrStartDeferred}
}

func (e *startDeferredError) GRPCStatus() *status.Status { return status.Convert(e.err) }

// deferStart marks a start-path error as a deferral, of the kind its ceph
// cause carries (cephDeferKind).
func deferStart(err error, kind error) error { return &startDeferredError{err: err, kind: kind} }

// CephStartDeferral reports, before the reconciler does any work for a VM
// (its lock, a proof's claim, the define), whether the VM's start would be
// deferred: it has a ceph disk whose key no remembered proof covers, and
//
//   - in a reconcile walk, a probe of that key got no answer within about
//     the last pass (health.ErrStartStorageDown, or ErrStartProbeFailed when
//     it was this VM's own) — deferred without asking again; or
//   - ctx has less than storage.ProbeBound left, and it is not the first
//     probe of the walk (which runs on what is left, down to cephProbeFloor).
//
// The reconciler then leaves the VM for its next pass, untouched. Any other
// answer, an error included, is the start's own to give.
func (s *Server) CephStartDeferral(ctx context.Context, vm *corrosion.VMRecord) error {
	if s.virt == nil || s.db == nil || vm == nil {
		return nil
	}
	walk := health.InReconcilerWalk(ctx)
	dl, hasDL := ctx.Deadline()
	left := time.Until(dl)
	short := hasDL && left < storage.ProbeBound
	if !short && !(walk && s.cephProofs.anyFailed()) {
		return nil
	}
	probes, err := s.cephStartPlan(ctx, vm, "")
	if err != nil || len(probes) == 0 {
		return nil
	}
	if walk {
		if failed, own := s.cephProofs.failedFor(vm.Name, probes); failed {
			return cephStorageDown(vm.Name, own)
		}
	}
	if !short || (walk && left >= cephProbeFloor && health.WalkProbeTurnFree(ctx)) {
		return nil
	}
	return deferStart(status.Errorf(codes.Unavailable,
		"start %q: proving this host's ceph key for its disks takes up to %v and the walk has %v left",
		vm.Name, storage.ProbeBound, left.Round(time.Millisecond)), nil)
}

// cephStorageDown is the deferral of a start whose ceph storage did not
// answer a probe within about the last pass (cephKeyFailTTL).
func cephStorageDown(vm string, own bool) error {
	kind := health.ErrStartStorageDown
	if own {
		kind = health.ErrStartProbeFailed
	}
	return deferStart(status.Errorf(codes.Unavailable,
		"start %q: Ceph did not answer a probe of its pool in the last %v; the start is retried", vm, cephKeyFailTTL), kind)
}

// condCephTrashLeftover names what in a ceph pool's trash needs an operator,
// or will: an image this host moved there (a delete, a rollback) and has not
// managed to purge, which still uses the pool's capacity; one HELD because a
// client has it open (it may be a running VM's disk: restore it); one a
// failed move left both in the trash and under its name; a purge queue file
// set aside as unreadable; and a litevirt image in a pool's trash that no
// purge here tracks.
const condCephTrashLeftover = "ceph_trash_leftover"

// CephTrashScanInterval is how often the ceph secret loop scans the pools'
// trash (ScanCephTrash), the first time when it starts.
const CephTrashScanInterval = 5 * time.Minute

// cephTrashScans is what the pools' trash held, untracked, at the last two
// scans: an entry is named only once two scans in a row saw it, so another
// host's purge in progress is not.
type cephTrashScans struct {
	mu       sync.Mutex
	prev     map[string]storage.CephTrashEntry // TrashRef → entry, the scan before
	repeated []storage.CephTrashEntry          // seen untracked by the last two scans
}

// ScanCephTrash lists each ceph pool's trash for litevirt images no purge on
// this host tracks (storage.UntrackedTrash), remembers the ones two scans in
// a row found for ceph_trash_leftover, and forgets held entries an operator
// has dealt with. A pool whose trash cannot be read keeps what the scan
// before saw of it.
func (s *Server) ScanCephTrash(ctx context.Context) {
	storage.RecheckHeldCephPurges(ctx)
	s.recheckKeptCephImages(ctx) // ceph_kept.go
	s.storagePoolsMu.RLock()
	pools := map[string]StoragePoolRef{}
	for n, p := range s.storagePools {
		if strings.EqualFold(p.Driver, "ceph") {
			pools[n] = p
		}
	}
	s.storagePoolsMu.RUnlock()
	seen := map[string]storage.CephTrashEntry{}
	s.cephTrash.mu.Lock()
	prev := s.cephTrash.prev
	s.cephTrash.mu.Unlock()
	scanned := map[string]bool{}
	for name, p := range pools {
		drv, err := storage.New(s.dataDir, storage.Config{Name: name, Driver: p.Driver, Source: p.Source, Target: p.Target, Options: p.Options})
		if err != nil {
			continue
		}
		sc, ok := drv.(storage.CephTrashScanner)
		if !ok {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		entries, err := sc.UntrackedTrash(cctx)
		cancel()
		if err != nil {
			slog.Warn("ceph: the pool's trash could not be scanned for leftovers", "pool", name, "error", err)
			continue
		}
		scanned[p.Source] = true
		for _, e := range entries {
			seen[e.TrashRef()] = e
		}
	}
	// A pool not scanned this time keeps what the last scan saw of it.
	for ref, e := range prev {
		if !scanned[e.Pool] {
			seen[ref] = e
		}
	}
	var repeated []storage.CephTrashEntry
	for ref, e := range seen {
		if _, ok := prev[ref]; ok {
			repeated = append(repeated, e)
		}
	}
	sort.Slice(repeated, func(i, j int) bool { return repeated[i].TrashRef() < repeated[j].TrashRef() })
	s.cephTrash.mu.Lock()
	s.cephTrash.prev, s.cephTrash.repeated = seen, repeated
	s.cephTrash.mu.Unlock()
}

// judgeCephTrash raises ceph_trash_leftover for this host while anything in
// a ceph pool's trash needs an operator (condCephTrashLeftover) — naming
// each image, its trash id, why, and the command that deals with it by hand
// — and resolves it once nothing does.
func (s *Server) judgeCephTrash(ctx context.Context) {
	var failing []storage.CephPurge
	for _, p := range storage.CephPendingPurges() {
		if p.LastError != "" {
			failing = append(failing, p)
		}
	}
	aside := storage.CephPurgeQueueSetAside()
	s.cephTrash.mu.Lock()
	untracked := append([]storage.CephTrashEntry(nil), s.cephTrash.repeated...)
	s.cephTrash.mu.Unlock()
	subject := s.hostName
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, cephPoolEvaluator, condCephTrashLeftover, "host", subject)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(failing) == 0 && len(aside) == 0 && len(untracked) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("ceph: resolve the trash leftover condition", "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: cephPoolEvaluator, Code: condCephTrashLeftover,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	type leftover struct {
		Trash     string `json:"trash"`
		Image     string `json:"image"`
		State     string `json:"state"`
		Since     string `json:"since,omitempty"`
		Attempts  int    `json:"attempts,omitempty"`
		LastError string `json:"last_error,omitempty"`
		// ByHand is the command that deals with it: a purge for a
		// failing one, a restore for one a client may still use.
		ByHand string `json:"by_hand"`
	}
	var list []leftover
	retrying, held := 0, 0
	for _, p := range failing {
		l := leftover{Trash: p.TrashRef(), Image: p.Pool + "/" + p.Image, Since: p.Since.Format(time.RFC3339),
			Attempts: p.Attempts, LastError: p.LastError}
		switch p.State {
		case storage.CephPurgeHeld, storage.CephPurgeHalfMoved:
			l.State, l.ByHand = p.State, "rbd trash restore "+p.TrashRef()
			held++
		case storage.CephPurgeMoving:
			// A move whose outcome is not settled: the image may still be
			// live under its name. Only the check, never a removal.
			l.State, l.ByHand = "settling", "rbd trash ls --all --long "+p.Pool+"; rbd info "+p.Pool+"/"+p.Image
			held++
		default:
			l.State, l.ByHand = "purge_failing", "rbd trash rm "+p.TrashRef()
			retrying++
		}
		list = append(list, l)
	}
	for _, e := range untracked {
		list = append(list, leftover{Trash: e.TrashRef(), Image: e.Pool + "/" + e.Name, State: "untracked",
			LastError: fmt.Sprintf("in the trash (source %s) and tracked by no purge on %s: another host may still be purging it, or hold it because a client has it open; "+
				"restoring it is never destructive, removing it may be", e.Source, s.hostName),
			ByHand: "rbd trash restore " + e.TrashRef()})
	}
	ev, _ := json.Marshal(map[string]any{
		"host": s.hostName, "leftovers": list, "unreadable_queue_files": aside,
		"detail": fmt.Sprintf("in the ceph pools' trash: %d image(s) moved there by %s and not purged yet (retried), %d held, or not yet settled, because a client may still use them (check, then restore them), "+
			"%d litevirt image(s) no purge here tracks; and %d purge queue file(s) set aside as unreadable, whose images are no longer tracked (check the pools' trash with rbd trash ls --all --long)",
			retrying, s.hostName, held, len(untracked), len(aside)),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("ceph: raise the trash leftover condition", "error", err)
	}
}
