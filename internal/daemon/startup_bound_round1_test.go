package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

type cleanupResumer struct {
	calls atomic.Int32
	errs  []error
}

func (c *cleanupResumer) ResumeVMReplaceCleanups(context.Context) error {
	n := int(c.calls.Add(1)) - 1
	if n < len(c.errs) {
		return c.errs[n]
	}
	return nil
}

// Round 1 M-3: a cutover cleanup deferred because its storage did not answer
// is tried again, until none is deferred; any other failure is left to the
// next start, as before.
//
// Mutation "no retry" — one call only: red.
func TestResumeVMReplaceCleanups_RetriesADeferredCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deferred := &storage.FSNoAnswerError{Op: "stat", Path: "/mnt/nfs/pool"}
	r := &cleanupResumer{errs: []error{deferred, errors.Join(deferred, errors.New("other")), nil}}
	done := make(chan struct{})
	go func() {
		resumeVMReplaceCleanups(ctx, r, 10*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the resume loop did not end once nothing was deferred")
	}
	if n := r.calls.Load(); n != 3 {
		t.Fatalf("%d attempts, want 3 (two deferred, then done)", n)
	}
	other := &cleanupResumer{errs: []error{errors.New("a libvirt failure")}}
	resumeVMReplaceCleanups(ctx, other, 10*time.Millisecond)
	if n := other.calls.Load(); n != 1 {
		t.Fatalf("%d attempts after a failure that is not a deferral, want 1", n)
	}
}
