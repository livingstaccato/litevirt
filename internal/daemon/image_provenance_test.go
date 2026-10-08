package daemon

import (
	"context"
	"testing"
	"time"
)

type blockedRecorder struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockedRecorder) RecordLegacyImageProvenance(context.Context) {
	close(b.started)
	<-b.release
}

// I-C: startup goes on to listen while the provenance pass is still hashing.
func TestStartLegacyImageProvenance_DoesNotHoldUpStartup(t *testing.T) {
	r := &blockedRecorder{started: make(chan struct{}), release: make(chan struct{})}
	defer close(r.release)
	returned := make(chan struct{})
	go func() {
		startLegacyImageProvenance(context.Background(), r)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("startup is waiting on the provenance pass")
	}
	select {
	case <-r.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the provenance pass never ran")
	}
}
