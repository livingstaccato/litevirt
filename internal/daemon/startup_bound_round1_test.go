package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

type cleanupResumer struct {
	calls atomic.Int32
	errs  []error
	kick  chan struct{}
	// at records each attempt's time, for the waits between them.
	mu sync.Mutex
	at []time.Time
}

func (c *cleanupResumer) ResumeVMReplaceCleanups(context.Context) error {
	c.mu.Lock()
	c.at = append(c.at, time.Now())
	c.mu.Unlock()
	n := int(c.calls.Add(1)) - 1
	if n < len(c.errs) {
		return c.errs[n]
	}
	return nil
}

func (c *cleanupResumer) VMReplaceCleanupKick() <-chan struct{} { return c.kick }

// waitCalls waits until c has been called n times.
func (c *cleanupResumer) waitCalls(t *testing.T, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.calls.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d attempts after 5s, want %d", c.calls.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Round 1 M-3, and ccguard I3: a journaled cutover cleanup that fails is
// tried again without a daemon restart, whatever the failure: storage that
// does not answer, or a transient error such as a row read that failed.
//
// Mutation "retry only a deferral" (the loop before ccguard I3): the libvirt
// failure is tried once, red.
func TestResumeVMReplaceCleanups_RetriesAFailedCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deferred := &storage.FSNoAnswerError{Op: "stat", Path: "/mnt/nfs/pool"}
	r := &cleanupResumer{errs: []error{deferred, errors.New("a row read failed"), errors.New("a libvirt failure"), nil}}
	go resumeVMReplaceCleanups(ctx, r, 5*time.Millisecond, time.Hour)
	r.waitCalls(t, 4)
}

// The wait after a failure doubles from minRetry up to maxRetry, and starts
// again at minRetry once an attempt succeeds.
//
// Mutation "no cap" (wait doubles past maxRetry): the last gap reaches 4x
// min, red.
func TestResumeVMReplaceCleanups_BackoffIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fail := errors.New("transient")
	const min = 100 * time.Millisecond
	r := &cleanupResumer{errs: []error{fail, fail, fail, fail}}
	go resumeVMReplaceCleanups(ctx, r, min, 2*min)
	r.waitCalls(t, 5)
	cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	gaps := make([]time.Duration, 0, 4)
	for i := 1; i < 5; i++ {
		gaps = append(gaps, r.at[i].Sub(r.at[i-1]))
	}
	// min, 2min, 2min, 2min.
	if gaps[0] < min || gaps[1] < 2*min {
		t.Fatalf("waits %v; want them to start at %v and double", gaps, min)
	}
	if gaps[3] >= 4*min-min/2 {
		t.Fatalf("waits %v; want none past the %v cap", gaps, 2*min)
	}
}

// Once nothing fails, a kick (a cutover that left its phases journaled)
// starts an attempt at once, not after the period.
//
// Mutation "the kick not listened for": no attempt within the test's 5s
// (the period is an hour), red.
func TestResumeVMReplaceCleanups_AKickRetriesAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cleanupResumer{kick: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		resumeVMReplaceCleanups(ctx, r, time.Hour, time.Hour)
		close(done)
	}()
	r.waitCalls(t, 1)
	r.kick <- struct{}{}
	r.waitCalls(t, 2)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not end with its context")
	}
}
