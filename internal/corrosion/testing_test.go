package corrosion

import (
	"context"
	"fmt"
	"testing"
)

// recordingT runs nothing on its own: it collects the cleanups
// NewTestClientT registers, so the test can run them and look at the client
// afterwards.
type recordingT struct {
	cleanups []func()
	fatal    string
}

func (r *recordingT) Helper()                        {}
func (r *recordingT) Cleanup(f func())               { r.cleanups = append(r.cleanups, f) }
func (r *recordingT) Fatalf(format string, a ...any) { r.fatal = fmt.Sprintf(format, a...) }

// TestNewTestClientTClosesOnCleanup: the client is open for the test and
// closed once the test's cleanups run. An in-memory test database that is
// never closed keeps its memory for the life of the test binary.
func TestNewTestClientTClosesOnCleanup(t *testing.T) {
	rt := &recordingT{}
	c := NewTestClientT(rt)
	if rt.fatal != "" {
		t.Fatalf("NewTestClientT failed the test: %s", rt.fatal)
	}
	if err := c.db.PingContext(context.Background()); err != nil {
		t.Fatalf("client should be open before cleanup: %v", err)
	}
	if len(rt.cleanups) != 1 {
		t.Fatalf("want exactly one cleanup registered, got %d", len(rt.cleanups))
	}
	rt.cleanups[0]()
	if err := c.db.PingContext(context.Background()); err == nil {
		t.Fatal("client is still open after cleanup: the test database leaks")
	}
}
