package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// iSCSI sessions of this host's iscsi pools. A pool's LUN is a device only
// while the host has a session to its target, and a host reboot drops every
// session; with the node records at node.startup = manual (the usual), nothing
// logged back in until something prepared the pool again, while the pool kept
// reporting active. ReconcileISCSISessions, run by the daemon at start and
// every ISCSISessionReconcileInterval, checks each iscsi pool of this host and
// logs in when its session has been missing since this daemon started — after
// a reboot (storage.LoginISCSISession: through the existing node record, which
// holds any CHAP settings, never rewriting it). A session this daemon has seen
// up and that then disappeared was logged out on purpose (SAN maintenance, a
// LUN re-mapped on the array) and is left out: the pool is reported degraded
// with iscsiLoggedOutReason, and a VM start that uses the LUN, or a daemon
// restart, logs it back in. A pool whose session is missing is recorded as
// PoolStateDegraded on its own row and raises iscsi_session_missing (evaluator
// iscsi_pool, subject host/<pool>@<host>, warning) with the login's reason;
// both clear on the pass that finds the session. Nothing is refused on a
// degraded pool: the state and the condition are diagnostics.

const (
	iscsiPoolEvaluator      = "iscsi_pool"
	condISCSISessionMissing = "iscsi_session_missing"

	// PoolStateDegraded is the state of a pool whose backing storage this
	// host cannot reach now (an iscsi pool with no session).
	PoolStateDegraded = "degraded"

	// ISCSISessionReconcileInterval is how often the daemon checks the
	// sessions.
	ISCSISessionReconcileInterval = 30 * time.Second

	// iscsiLoggedOutReason is why a session seen up earlier in this daemon's
	// life is missing and not logged back in.
	iscsiLoggedOutReason = "logged out while the daemon ran; `lv start` of a VM using it or a daemon restart logs it back in"
)

// iscsiSessionMemory is what this daemon has seen of its iSCSI sessions,
// keyed by target and portal (iscsiSessionKey): which it has seen up (a
// later absence is a deliberate logout), and when a login last failed (a
// start does not retry one the pass saw fail moments ago).
type iscsiSessionMemory struct {
	mu     sync.Mutex
	seen   map[string]bool
	failed map[string]time.Time
}

func (m *iscsiSessionMemory) up(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	m.seen[key] = true
	delete(m.failed, key)
}

func (m *iscsiSessionMemory) wasUp(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[key]
}

func (m *iscsiSessionMemory) loginFailed(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed == nil {
		m.failed = map[string]time.Time{}
	}
	m.failed[key] = time.Now()
}

func (m *iscsiSessionMemory) failedWithin(key string, d time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.failed[key]
	return ok && time.Since(at) < d
}

// iscsiSessionKey names one session: a pool's target and portal.
func iscsiSessionKey(cfg storage.Config) string {
	portal := cfg.Options["portal"]
	if portal == "" {
		portal = "127.0.0.1"
	}
	return strings.ToLower(cfg.Source) + "|" + portal
}

// iscsiDeviceExists reports whether a LUN's by-path device is present
// (a test seam), and iscsiDeviceWait how long a start waits for udev to
// create it after a login.
var (
	iscsiDeviceExists = func(path string) bool { _, err := os.Stat(path); return err == nil }
	iscsiDeviceWait   = 10 * time.Second
)

// iscsiStartLoginBound bounds a start's own login attempt.
const iscsiStartLoginBound = 45 * time.Second

// ReconcileISCSISessions checks the session of every iscsi pool of this host,
// logs in where one is missing, and records the outcome on the pool's row and
// in iscsi_session_missing.
func (s *Server) ReconcileISCSISessions(ctx context.Context) {
	if s.db == nil {
		return
	}
	rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("iSCSI sessions: list this host's pools", "error", err)
		return
	}
	live := map[string]bool{}
	tried := map[string]error{} // per target and portal, within this pass
	for _, r := range rows {
		if !strings.EqualFold(r.Driver, "iscsi") {
			continue
		}
		live[r.Name] = true
		s.reconcileISCSIPool(ctx, r.Name, tried)
	}
	s.resolveGoneISCSIPoolConditions(ctx, live)
}

// iscsiPoolConfig is the driver config of one of this host's iscsi pool rows:
// the row's options, with a pool from the daemon config taking its options
// (its row is registered without them) from the config definition.
func (s *Server) iscsiPoolConfig(r corrosion.StoragePoolRecord) storage.Config {
	cfg := storage.Config{Name: r.Name, Driver: r.Driver, Source: r.Source, Target: r.Target, Options: r.Options}
	if r.Options["portal"] == "" {
		if ref, ok := s.lookupStoragePool(r.Name); ok && strings.EqualFold(ref.Driver, "iscsi") && ref.Source == r.Source {
			cfg.Options = ref.Options
		}
	}
	if cfg.Options["portal"] == "" {
		opts := make(map[string]string, len(cfg.Options)+1)
		for k, v := range cfg.Options {
			opts[k] = v
		}
		opts["portal"] = "127.0.0.1" // the driver's default
		cfg.Options = opts
	}
	return cfg
}

// reconcileISCSIPool checks one pool's session (once per target and portal in
// a pass: tried), logs in when it is missing, writes the pool's state (active,
// or degraded while the session cannot be had) on its row when it changed, and
// raises or resolves its condition. All of it under iscsiMu, which a pool
// create and delete of an iscsi pool also hold, from a fresh read of the row:
// a pool deleted meanwhile is neither logged back in nor written back.
func (s *Server) reconcileISCSIPool(ctx context.Context, pool string, tried map[string]error) {
	s.iscsiMu.Lock()
	defer s.iscsiMu.Unlock()
	rec, found, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, pool)
	if err != nil || !found || !strings.EqualFold(rec.Driver, "iscsi") {
		return
	}
	cfg := s.iscsiPoolConfig(rec)
	key := iscsiSessionKey(cfg)
	sessErr, done := tried[key]
	if !done {
		sessErr = s.checkISCSISession(ctx, pool, cfg, key)
		tried[key] = sessErr
	}
	if sessErr != nil {
		slog.Warn("iSCSI pool has no session; its LUN is not available on this host", "pool", pool, "error", sessErr)
	}
	want := rec.State
	switch {
	case sessErr != nil:
		want = PoolStateDegraded
	case rec.State == PoolStateDegraded:
		want = "active"
	}
	if want != rec.State {
		rec.State = want
		if err := corrosion.UpdateStoragePool(ctx, s.db, rec); err != nil {
			slog.Warn("iSCSI sessions: record the pool's state", "pool", pool, "error", err)
		}
	}
	s.judgeISCSISession(ctx, pool, sessErr)
}

// checkISCSISession is one pass's verdict on a session: nil when it is up
// (now, or after a login), else why not. Only a session missing since this
// daemon started is logged in.
func (s *Server) checkISCSISession(ctx context.Context, pool string, cfg storage.Config, key string) error {
	up, err := storage.ISCSISessionUp(ctx, cfg)
	switch {
	case err != nil:
		return err
	case up:
		s.iscsiMem.up(key)
		return nil
	case s.iscsiMem.wasUp(key):
		return fmt.Errorf("no session to iSCSI target %s through %s: %s", cfg.Source, cfg.Options["portal"], iscsiLoggedOutReason)
	}
	if err := storage.LoginISCSISession(ctx, cfg); err != nil {
		s.iscsiMem.loginFailed(key)
		return fmt.Errorf("%w; the login is retried every %v", err, ISCSISessionReconcileInterval)
	}
	s.iscsiMem.up(key)
	slog.Info("iSCSI session was missing since the daemon started; logged in", "pool", pool, "target", cfg.Source, "portal", cfg.Options["portal"])
	return nil
}

// judgeISCSISession raises iscsi_session_missing for pool on this host while
// sessErr, observed on the first pass and confirmed on the next, and resolves
// it once the session is there.
func (s *Server) judgeISCSISession(ctx context.Context, pool string, sessErr error) {
	subject := pool + "@" + s.hostName
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, iscsiPoolEvaluator, condISCSISessionMissing, "host", subject)
	if err != nil {
		return
	}
	if sessErr == nil {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("iSCSI sessions: resolve condition", "pool", pool, "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: iscsiPoolEvaluator, Code: condISCSISessionMissing,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	ev, _ := json.Marshal(map[string]any{
		"pool": pool, "host": s.hostName,
		"detail": fmt.Sprintf("iscsi pool %q on %s has no session, so its LUN's device is missing and a VM disk on it cannot open: %v. "+
			"The pool reports %s until the session is back",
			pool, s.hostName, sessErr, PoolStateDegraded),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("iSCSI sessions: raise condition", "pool", pool, "error", err)
	}
}

// resolveGoneISCSIPoolConditions resolves this host's open
// iscsi_session_missing conditions whose pool is no longer an iscsi pool here.
func (s *Server) resolveGoneISCSIPoolConditions(ctx context.Context, live map[string]bool) {
	conds, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		return
	}
	suffix := "@" + s.hostName
	for _, c := range conds {
		if c.Evaluator != iscsiPoolEvaluator || c.Code != condISCSISessionMissing || c.Lifecycle == corrosion.ConditionResolved ||
			!strings.HasSuffix(c.SubjectID, suffix) || live[strings.TrimSuffix(c.SubjectID, suffix)] {
			continue
		}
		s.judgeISCSISession(ctx, strings.TrimSuffix(c.SubjectID, suffix), nil)
	}
}

// ensureISCSISessionsForVM logs in, before a start on this host, the session
// of each of the VM's iSCSI disks whose device is missing, and waits briefly
// for udev to create it. It refuses nothing: a disk whose device is still
// missing fails the start where it always did, and the failure is logged here
// with its reason.
func (s *Server) ensureISCSISessionsForVM(ctx context.Context, vm *corrosion.VMRecord) {
	if s.db == nil {
		return
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return
	}
	for _, d := range disks {
		if _, ok := storage.FixedDeviceKeyOfPath(d.Path); !ok || iscsiDeviceExists(d.Path) {
			continue
		}
		cfg, err := s.resolveVolume(ctx, vm.StackName, d.StorageVolume)
		if err != nil || !strings.EqualFold(cfg.Driver, "iscsi") {
			continue
		}
		// The pool's own row (for a config pool, its configured portal) —
		// only when the disk's storage resolved to the pool, not to a stack
		// volume of the same name.
		if cfg.Name == d.StorageVolume {
			if r, ok, gerr := corrosion.GetStoragePool(ctx, s.db, s.hostName, d.StorageVolume); gerr == nil && ok && strings.EqualFold(r.Driver, "iscsi") {
				cfg = s.iscsiPoolConfig(r)
			}
		}
		key := iscsiSessionKey(cfg)
		if s.iscsiMem.failedWithin(key, ISCSISessionReconcileInterval) {
			slog.Warn("VM start: its iSCSI disk's device is missing, and a login to its target failed moments ago; not retried",
				"vm", vm.Name, "disk", d.DiskName, "device", d.Path, "target", cfg.Source)
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, iscsiStartLoginBound)
		in, lerr := storage.EnsureISCSISession(lctx, cfg)
		cancel()
		if lerr != nil {
			s.iscsiMem.loginFailed(key)
			slog.Warn("VM start: its iSCSI disk's device is missing and the session could not be logged in",
				"vm", vm.Name, "disk", d.DiskName, "device", d.Path, "error", lerr)
			continue
		}
		s.iscsiMem.up(key)
		if !in {
			continue // the session was there: the device's absence is not udev's lag
		}
		slog.Info("VM start: logged in the missing iSCSI session of its disk", "vm", vm.Name, "disk", d.DiskName, "target", cfg.Source)
		deadline := time.Now().Add(iscsiDeviceWait)
		for !iscsiDeviceExists(d.Path) && time.Now().Before(deadline) && ctx.Err() == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
}
