package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// haCacheRefresh is how often the HA policy cache re-reads this node's
// replica. A var so tests need not wait.
var haCacheRefresh = time.Second

// haCacheFailuresUnknown is how many consecutive failed loads make the cache
// unknown (Ready then answers ha_known=false, which every peer coordinator
// reads as a veto) and raise ha_policy_unreadable on this node.
const haCacheFailuresUnknown = 5

// haPolicyCache is this node's in-memory copy of the cluster HA policy row,
// which Ready answers from: the probe path never reads the database for it.
// known is false until the first successful load, and again while loads keep
// failing.
//
// It only moves forward. It has two writers, the periodic refresh and a local
// write, and a refresh that read the replica just before a local write must
// not install its older row after it: a peer coordinator's veto relies on this
// node's answer following the replica's last-writer-wins order.
type haPolicyCache struct {
	mu       sync.RWMutex
	known    bool
	disarmed bool
	policyAt string // the row's updated_at exactly as stored; "" when there is no row
	policy   corrosion.HAPolicy
	failures int
	loadErr  string

	// gauge, when set, is litevirt_ha_disarmed (SetHADisarmedGauge).
	gauge func(on bool)
	// The refresher's own conditions about this node, touched only by it.
	condDisarmed, condUnreadable *health.HACondition
}

// haForward reports whether a row stamped next may replace one stamped cur.
func haForward(cur, next string) bool {
	switch {
	case cur == "":
		return true
	case next == "":
		return false
	default:
		return next == cur || corrosion.LWWNewer(next, cur)
	}
}

// install takes p as the cache's value unless it is older than the value held.
func (h *haPolicyCache) install(p corrosion.HAPolicy) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !haForward(h.policyAt, p.UpdatedAt) {
		return false
	}
	h.known, h.disarmed, h.policyAt, h.policy = true, p.Disarmed(), p.UpdatedAt, p
	h.failures, h.loadErr = 0, ""
	return true
}

// failed records a failed load; after haCacheFailuresUnknown in a row the
// cache is unknown until a load succeeds.
func (h *haPolicyCache) failed(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures++
	h.loadErr = err.Error()
	if h.failures >= haCacheFailuresUnknown {
		h.known = false
	}
}

// snapshot is what Ready answers.
func (h *haPolicyCache) snapshot() (known, disarmed bool, policyAt string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.known, h.disarmed, h.policyAt
}

// haCacheState is the cache with its load status, for this node's conditions.
type haCacheState struct {
	known    bool
	policy   corrosion.HAPolicy
	failures int
	loadErr  string
}

func (h *haPolicyCache) state() haCacheState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return haCacheState{known: h.known, policy: h.policy, failures: h.failures, loadErr: h.loadErr}
}

// SetHADisarmedGauge wires litevirt_ha_disarmed: 1 while this node's replica
// says HA is disarmed, or its policy cannot be read.
func (s *Server) SetHADisarmedGauge(fn func(on bool)) {
	s.haCache.mu.Lock()
	s.haCache.gauge = fn
	s.haCache.mu.Unlock()
}

// RefreshHAPolicyCache reads the policy from this node's replica into the
// cache. An unreadable row is a successful load: it reads disarmed.
func (s *Server) RefreshHAPolicyCache(ctx context.Context) error {
	p, err := corrosion.GetHAPolicy(ctx, s.db)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableHAPolicy) {
		s.haCache.failed(err)
		return err
	}
	s.haCache.install(p)
	return nil
}

// RunHAPolicyCache keeps the cache within haCacheRefresh of the replica, and
// this node's ha_disarmed / ha_policy_unreadable conditions and its
// litevirt_ha_disarmed gauge with it, until ctx ends.
func (s *Server) RunHAPolicyCache(ctx context.Context) {
	t := time.NewTicker(haCacheRefresh)
	defer t.Stop()
	for {
		if err := s.RefreshHAPolicyCache(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("ha-disarm: could not load the HA policy", "error", err)
		}
		s.syncHAConditions(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncHAConditions brings this node's own HA conditions and gauge in line
// with its cache.
func (s *Server) syncHAConditions(ctx context.Context) {
	st := s.haCache.state()
	s.haCache.mu.Lock()
	if s.haCache.condDisarmed == nil {
		s.haCache.condDisarmed = &health.HACondition{DB: s.db, Host: s.hostName,
			Code: corrosion.CondHADisarmed, Severity: corrosion.SeverityWarning}
		s.haCache.condUnreadable = &health.HACondition{DB: s.db, Host: s.hostName,
			Code: corrosion.CondHAPolicyUnreadable, Severity: corrosion.SeverityCritical}
	}
	condDisarmed, condUnreadable, gauge := s.haCache.condDisarmed, s.haCache.condUnreadable, s.haCache.gauge
	s.haCache.mu.Unlock()

	failing := st.failures >= haCacheFailuresUnknown
	unreadable := ""
	switch {
	case failing:
		unreadable = fmt.Sprintf("HA cache load failing on %s: %s", s.hostName, st.loadErr)
	case st.known && st.policy.Unreadable:
		unreadable = fmt.Sprintf("%s cannot read its cluster HA policy row (set by %s at %s); "+
			"its failover coordinator decides nothing until the row is set again with lv cluster ha",
			s.hostName, st.policy.SetBy, st.policy.UpdatedAt)
	}
	condUnreadable.Sync(ctx, unreadable != "", unreadable)
	disarmed := st.known && !st.policy.Unreadable && st.policy.State == corrosion.HADisarmed
	evidence := ""
	if disarmed {
		evidence = fmt.Sprintf("HA is disarmed (set by %s at %s: %q): no host is fenced and no workload "+
			"recovered automatically until lv cluster ha arm", st.policy.SetBy, st.policy.UpdatedAt, st.policy.Reason)
	}
	condDisarmed.Sync(ctx, disarmed, evidence)
	if gauge != nil {
		gauge(disarmed || unreadable != "")
	}
}

// PeerHAAnswer is host's latest answer to this node's health probe about the
// HA policy, and false when it has none. The failover coordinator reads it
// (failover.Coordinator.PeerHAState, wired in the daemon).
func (s *Server) PeerHAAnswer(host string) (asked time.Time, known, disarmed bool, policyAt string, ok bool) {
	s.peerHA.mu.Lock()
	defer s.peerHA.mu.Unlock()
	a, ok := s.peerHA.m[host]
	return a.asked, a.known, a.disarmed, a.policyAt, ok
}
