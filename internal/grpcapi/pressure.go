package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pressure"
)

// Resource pressure, the observing phase (docs/configuration.md, "Resource
// pressure"): this host's sampler grades its own resources, Ready reports the
// grade beside the verdict, each node keeps every peer's latest answer, and
// the failover lease holder turns them into host.pressure conditions. Nothing
// is refused, paused or shed because of it, and nothing reads an absent
// answer as "ok".

const (
	// PressureEvaluator writes CondHostPressure.
	PressureEvaluator = "pressure"
	// CondHostPressure is a host whose resources are at warn or worse.
	CondHostPressure = "host.pressure"
	// PressureUnknown is the level of a host that did not say.
	PressureUnknown = "unknown"
	// pressureRefresh is how often an unchanged open condition is rewritten,
	// to keep its last_seen and its time-to-full projection current.
	pressureRefresh = 5 * time.Minute
	// pressureAnswerMaxAge is how old a peer's latest answer may be and still
	// be acted on. A host that stopped answering (down, cut off, in
	// maintenance, which the probe plan skips) keeps its condition exactly as
	// it was, rather than having an old answer re-asserted as current.
	pressureAnswerMaxAge = 2 * pressureRefresh
)

// PressureSource is this host's sampler (*pressure.Sampler).
type PressureSource interface {
	Report() pressure.Report
}

type pressureSourceBox struct{ src PressureSource }

// SetPressureSource wires this host's sampler; nil (pressure.enabled false)
// answers no pressure.
func (s *Server) SetPressureSource(src PressureSource) {
	if src == nil {
		s.pressureSrc.Store(nil)
		return
	}
	s.pressureSrc.Store(&pressureSourceBox{src: src})
}

// localPressure is this host's pressure for the wire, nil with no sampler.
// detail carries paths and sizes, so only a host-certificate caller gets it.
func (s *Server) localPressure(detail bool) *pb.HostPressure {
	box := s.pressureSrc.Load()
	if box == nil {
		return nil
	}
	return pressureToPB(box.src.Report(), detail)
}

func pressureToPB(r pressure.Report, detail bool) *pb.HostPressure {
	out := &pb.HostPressure{
		Level:         r.Level.String(),
		Resources:     r.Pressured(),
		Since:         rfc3339(r.Since),
		TimeToFullSec: int64(r.TimeToFull / time.Second),
		SampledAt:     rfc3339(r.SampledAt),
		Stale:         r.Stale,
	}
	if detail {
		for _, res := range r.Resources {
			out.Detail = append(out.Detail, &pb.PressureResource{
				Name: res.Name, Level: res.Level.String(), Since: rfc3339(res.Since),
				Free: res.Free, Total: res.Total, Unit: res.Unit, FreePct: res.FreePct,
				TimeToFullSec: int64(res.TimeToFull / time.Second), Error: res.Err,
			})
		}
	}
	return out
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// peerPressureAnswers is each peer's latest answer to the health probe about
// its own pressure.
type peerPressureAnswers struct {
	mu sync.Mutex
	m  map[string]PeerPressureView
}

// PeerPressureView is what this node knows of a peer's pressure.
type PeerPressureView struct {
	// Answered: a probe this run of the daemon reached the peer's daemon.
	Answered bool
	// Asked is when that probe was sent.
	Asked time.Time
	// Pressure is what it said; nil when it said nothing (an older build,
	// pressure.enabled false).
	Pressure *pb.HostPressure
}

// Level is the peer's level, PressureUnknown when it never said.
func (v PeerPressureView) Level() string {
	if v.Pressure == nil || v.Pressure.GetLevel() == "" {
		return PressureUnknown
	}
	return v.Pressure.GetLevel()
}

// record keeps p as host's answer unless a probe sent later already answered.
func (a *peerPressureAnswers) record(host string, asked time.Time, p *pb.HostPressure) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.m[host]; ok && prev.Asked.After(asked) {
		return
	}
	if a.m == nil {
		a.m = map[string]PeerPressureView{}
	}
	a.m[host] = PeerPressureView{Answered: true, Asked: asked, Pressure: p}
}

// PeerPressure is host's latest answer to this node's health probe about its
// resource pressure. It makes no RPC.
func (s *Server) PeerPressure(host string) PeerPressureView {
	s.peerPressure.mu.Lock()
	defer s.peerPressure.mu.Unlock()
	return s.peerPressure.m[host]
}

// pressureView is what this node knows of host's pressure: its own sampler
// for itself (always answered; nil with no sampler), the probe cache for a
// peer.
func (s *Server) pressureView(host string, detail bool) PeerPressureView {
	if host == s.hostName {
		return PeerPressureView{Answered: true, Pressure: s.localPressure(detail)}
	}
	return s.PeerPressure(host)
}

// inspectPressure fills Host.pressure and Host.pressure_observed_at.
func (s *Server) inspectPressure(host string) (*pb.HostPressure, string) {
	v := s.pressureView(host, true)
	if v.Pressure == nil {
		return &pb.HostPressure{Level: PressureUnknown}, rfc3339(v.Asked)
	}
	return v.Pressure, rfc3339(v.Asked)
}

// pressureCondMemo is the lease holder's last host.pressure content written
// per host, so an unchanged level is not rewritten every tick.
type pressureCondMemo struct {
	mu sync.Mutex
	m  map[string]pressureWritten
}

type pressureWritten struct {
	key string // level and resources
	at  time.Time
}

// PressureHealthTick writes host.pressure for every host from what this node
// knows (pressureView). Run by the failover lease holder once per cycle, so a
// host whose own disk is full is still described by a peer whose disk is
// fine. A host it has no answer from this run is left as it is; one that
// answered with no pressure, or at ok, is resolved.
func (s *Server) PressureHealthTick(ctx context.Context) {
	if s.db == nil {
		return
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		slog.Warn("resource pressure: list hosts", "error", err)
		return
	}
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, PressureEvaluator, CondHostPressure)
	if err != nil {
		slog.Warn("resource pressure: list conditions", "error", err)
		return
	}
	openBy := make(map[string]corrosion.HealthCondition, len(open))
	for _, c := range open {
		openBy[c.SubjectID] = c
	}
	live := make(map[string]bool, len(hosts))
	now := time.Now().UTC()
	for _, h := range hosts {
		live[h.Name] = true
		v := s.pressureView(h.Name, false)
		if !v.Answered || (!v.Asked.IsZero() && now.Sub(v.Asked) > pressureAnswerMaxAge) {
			continue
		}
		cur, isOpen := openBy[h.Name]
		lvl := v.Level()
		if lvl == PressureUnknown || lvl == pressure.OK.String() {
			if isOpen {
				why := "pressure back to ok"
				if lvl == PressureUnknown {
					why = "the host no longer reports pressure (pressure.enabled false, or an older build)"
				}
				s.resolvePressureCond(ctx, cur, now, why)
			}
			continue
		}
		s.raisePressureCond(ctx, h.Name, v, cur, isOpen, now)
	}
	for name, c := range openBy {
		if !live[name] {
			s.resolvePressureCond(ctx, c, now, "the host was removed")
		}
	}
}

func (s *Server) raisePressureCond(ctx context.Context, host string, v PeerPressureView, cur corrosion.HealthCondition, isOpen bool, now time.Time) {
	p := v.Pressure
	key := p.GetLevel() + "|" + joinSorted(p.GetResources())
	s.pressureCond.mu.Lock()
	last, seen := s.pressureCond.m[host]
	s.pressureCond.mu.Unlock()
	if isOpen && cur.Lifecycle == corrosion.ConditionConfirmed && seen && last.key == key && now.Sub(last.at) < pressureRefresh {
		return
	}
	stamp := now.Format(time.RFC3339)
	row := cur
	if !isOpen {
		row = corrosion.HealthCondition{Evaluator: PressureEvaluator, Code: CondHostPressure,
			SubjectKind: "host", SubjectID: host, Lifecycle: corrosion.ConditionObserved, FirstSeen: stamp}
	} else if row.Lifecycle == corrosion.ConditionObserved {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, stamp
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	if p.GetLevel() == pressure.Critical.String() {
		row.Severity = corrosion.SeverityCritical
	}
	row.Hosts = []string{host}
	ev := map[string]any{
		"host": host, "level": p.GetLevel(), "resources": p.GetResources(), "since": p.GetSince(),
		"time_to_full_sec": p.GetTimeToFullSec(),
		"sampled_at":       p.GetSampledAt(), "stale": p.GetStale(),
		"detail": "host " + host + " reports resource pressure " + p.GetLevel() + " on " + joinSorted(p.GetResources()) +
			"; `lv host inspect " + host + "` shows each resource. Nothing is refused because of it yet",
	}
	if !v.Asked.IsZero() {
		ev["reported_at"] = rfc3339(v.Asked)
	}
	b, _ := json.Marshal(ev)
	row.Evidence = string(b)
	row.LastSeen, row.ResolvedAt, row.Reporter = stamp, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("resource pressure: raise condition", "host", host, "error", err)
		return
	}
	s.pressureCond.mu.Lock()
	if s.pressureCond.m == nil {
		s.pressureCond.m = map[string]pressureWritten{}
	}
	s.pressureCond.m[host] = pressureWritten{key: key, at: now}
	s.pressureCond.mu.Unlock()
}

func (s *Server) resolvePressureCond(ctx context.Context, row corrosion.HealthCondition, now time.Time, why string) {
	stamp := now.Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, stamp, stamp, s.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	b, _ := json.Marshal(map[string]any{"host": row.SubjectID, "level": "ok", "detail": why})
	row.Evidence = string(b)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("resource pressure: resolve condition", "host", row.SubjectID, "error", err)
		return
	}
	s.pressureCond.mu.Lock()
	delete(s.pressureCond.m, row.SubjectID)
	s.pressureCond.mu.Unlock()
}

func joinSorted(in []string) string {
	out := slices.Clone(in)
	slices.Sort(out)
	s := ""
	for i, v := range out {
		if i > 0 {
			s += ","
		}
		s += v
	}
	return s
}
