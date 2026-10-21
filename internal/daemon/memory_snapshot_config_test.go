package daemon

import (
	"testing"
	"time"
)

// memory_snapshot.* parse as positive Go durations; empty keeps the
// built-in default (zero here); anything else fails the config load.
func TestMemorySnapshotConfig_Durations(t *testing.T) {
	b, d, err := MemorySnapshotConfig{}.Durations()
	if err != nil || b != 0 || d != 0 {
		t.Fatalf("empty: %v %v %v, want zeros", b, d, err)
	}
	b, d, err = MemorySnapshotConfig{PauseBudget: "500ms", LiveDeadline: "3m"}.Durations()
	if err != nil || b != 500*time.Millisecond || d != 3*time.Minute {
		t.Fatalf("set: %v %v %v", b, d, err)
	}
	for _, bad := range []MemorySnapshotConfig{
		{PauseBudget: "fast"}, {LiveDeadline: "10"}, {PauseBudget: "0s"}, {LiveDeadline: "-1s"},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%+v validated", bad)
		}
	}
}
