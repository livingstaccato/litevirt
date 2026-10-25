package grpcapi

import (
	"context"
	"sync"
	"time"
)

// generationBarrierBackoff spaces out generation barriers while a
// generation's evidence stays incomplete: 5s doubling to 10 minutes.
const (
	generationBarrierFirstRetry = 5 * time.Second
	generationBarrierMaxRetry   = 10 * time.Minute
)

// generationBarrierState is the per-generation retry state of
// AutomationGenerationBarrier.
type generationBarrierState struct {
	mu      sync.Mutex
	gen     int64
	attempt int
	next    time.Time
}

// AutomationGenerationBarrier gives the adopted voter generation certified
// evidence of its automation voters (F1 Task 5G follow-up B): when this voter
// holds automation authority there, enforcement.automation is on, and its
// local evidence does not yet cover every member, it certifies an internal
// read barrier through its own engine. Nothing to do returns nil; a retry
// waits out a per-generation backoff. It never involves the public service.
func (s *Server) AutomationGenerationBarrier(ctx context.Context) error {
	if !s.enfAutomation.Load() || s.db == nil {
		return nil
	}
	st, err := s.db.AutomationMembershipStanding(ctx)
	if err != nil {
		return err
	}
	if !st.Imported || len(st.ImportedVoters) >= st.Voters {
		return nil
	}
	b := &s.generationBarrier
	b.mu.Lock()
	if b.gen != st.Generation {
		b.gen, b.attempt, b.next = st.Generation, 0, time.Time{}
	}
	now := time.Now()
	if now.Before(b.next) {
		b.mu.Unlock()
		return nil
	}
	attempt := b.attempt
	b.attempt++
	delay := generationBarrierFirstRetry << min(attempt, 7)
	if delay > generationBarrierMaxRetry {
		delay = generationBarrierMaxRetry
	}
	b.next = now.Add(delay)
	b.mu.Unlock()
	e, err := s.AutomationEngine()
	if err != nil {
		return err
	}
	return e.GenerationBarrier(ctx, st.Generation, attempt)
}
