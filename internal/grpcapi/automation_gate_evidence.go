package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	// generationBarrierFirstRetry doubles to generationBarrierMaxRetry while
	// a generation's evidence stays incomplete.
	generationBarrierFirstRetry = 5 * time.Second
	generationBarrierMaxRetry   = 10 * time.Minute
	// generationBarrierMaxAttempts caps barriers per (generation, members,
	// live missing voters): a voter that answers but never signs costs at
	// most this many records until something it depends on changes.
	generationBarrierMaxAttempts = 3
	// generationBarrierProbeTimeout bounds the liveness probe of one voter,
	// made outside the engine lock.
	generationBarrierProbeTimeout = 2 * time.Second
)

// generationBarrierDeadline bounds one whole pass, so the daemon's adoption
// loop (whose context has no deadline) can never stall on it.
var generationBarrierDeadline = 30 * time.Second

// SetGenerationBarrierDeadlineForTest replaces generationBarrierDeadline and
// returns a function restoring it.
func SetGenerationBarrierDeadlineForTest(d time.Duration) (restore func()) {
	old := generationBarrierDeadline
	generationBarrierDeadline = d
	return func() { generationBarrierDeadline = old }
}

// generationBarrierState is AutomationGenerationBarrier's retry state.
type generationBarrierState struct {
	mu       sync.Mutex
	boot     string // random per process: request ids never replay a pre-restart one
	key      string // generation, members and live missing voters the attempts count against
	attempts int
	next     time.Time
}

// AutomationGenerationBarrier gives the adopted voter generation certified
// evidence of its automation voters (F1 Task 5G follow-up B). When this voter
// holds automation authority, enforcement.automation is on, and its local
// evidence misses a member, it first probes the missing members (read-only
// GetAutomationImportSource, outside the engine lock). Only if one of them
// answers, holding authority at the generation under its member incarnation,
// does it certify an internal read barrier through its own engine, sending
// phase 2 only to members that answered: a dead or blackholed member costs no
// record and holds no engine lock for its timeout. Attempts are
// capped per (generation, members, live missing set) and spaced by backoff;
// a change in any of those re-arms them. The pass has its own deadline.
func (s *Server) AutomationGenerationBarrier(ctx context.Context) error {
	if !s.enfAutomation.Load() || s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, generationBarrierDeadline)
	defer cancel()
	st, err := s.db.AutomationMembershipStanding(ctx)
	if err != nil {
		return err
	}
	if !st.Imported || len(st.ImportedVoters) >= st.Voters {
		return nil
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil || cfg == nil || cfg.Generation != st.Generation {
		return err
	}
	live, unreachable := s.probeAutomationVoters(ctx, cfg, st.ImportedVoters)
	if len(live) == 0 {
		return nil // nobody missing can sign now; liveness changes re-arm
	}
	key := fmt.Sprintf("%d|%s|%s", cfg.Generation, corrosion.MembersHash(cfg.Members), strings.Join(live, ","))
	b := &s.generationBarrier
	b.mu.Lock()
	if b.boot == "" {
		var r [6]byte
		_, _ = rand.Read(r[:])
		b.boot = hex.EncodeToString(r[:])
	}
	if b.key != key {
		b.key, b.attempts, b.next = key, 0, time.Time{}
	}
	now := time.Now()
	if b.attempts >= generationBarrierMaxAttempts || now.Before(b.next) {
		b.mu.Unlock()
		return nil
	}
	attempt := b.attempts
	b.attempts++
	delay := generationBarrierFirstRetry << min(attempt, 7)
	if delay > generationBarrierMaxRetry {
		delay = generationBarrierMaxRetry
	}
	b.next = now.Add(delay)
	tag := fmt.Sprintf("%s-%d", b.boot, attempt)
	b.mu.Unlock()
	e, err := s.AutomationEngine()
	if err != nil {
		return err
	}
	if err := e.GenerationBarrier(ctx, cfg.Generation, tag, unreachable); err != nil {
		return err
	}
	// The barrier's own anchor is above the evidence cursor; an older anchor
	// upgraded in place meanwhile is picked up by rescanning.
	s.db.ResetAutomationEvidenceScan()
	return nil
}

// probeAutomationVoters probes, in parallel, every member of cfg other than
// this voter. live is "name/incarnation" of the members without evidence
// yet that answer holding automation authority at cfg's generation under
// their member incarnation, sorted; unreachable names every member that did
// not answer so (the barrier sends it no phase 2).
func (s *Server) probeAutomationVoters(ctx context.Context, cfg *corrosion.VoterConfig, evidenced []string) (live, unreachable []string) {
	have := map[string]bool{}
	for _, v := range evidenced {
		have[v] = true
	}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, m := range cfg.Members {
		if m.Name == s.hostName {
			continue
		}
		wg.Add(1)
		go func(m corrosion.VoterMember) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, generationBarrierProbeTimeout)
			defer cancel()
			ready := false
			if cl, closer, err := s.dialPeer(pctx, m.Name); err == nil {
				r, err := cl.GetAutomationImportSource(pctx, &pb.GetAutomationImportSourceRequest{Generation: cfg.Generation})
				closer()
				ready = err == nil && r.GetVoter() == m.Name && r.GetAuthority() && r.GetAdoptedGeneration() == cfg.Generation && r.GetIncarnation() == m.Incarnation
			}
			mu.Lock()
			switch {
			case !ready:
				unreachable = append(unreachable, m.Name)
			case !have[m.Name]:
				live = append(live, m.Name+"/"+m.Incarnation)
			}
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	sort.Strings(live)
	sort.Strings(unreachable)
	return live, unreachable
}

// ResetGenerationBarrierBackoffForTest clears the backoff (not the attempt
// cap), so a test can run passes back to back.
func (s *Server) ResetGenerationBarrierBackoffForTest() {
	s.generationBarrier.mu.Lock()
	s.generationBarrier.next = time.Time{}
	s.generationBarrier.mu.Unlock()
}
