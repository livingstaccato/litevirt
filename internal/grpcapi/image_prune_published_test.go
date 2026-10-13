package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// publishedAfterDelete: a file published after its image's delete is kept,
// one published before is the delete's; a delete recorded to the second
// covers the whole second; what cannot be read keeps the file.
func TestPublishedAfterDelete(t *testing.T) {
	f := filepath.Join(t.TempDir(), "imgr@0123456789abcdef.qcow2")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 13, 12, 54, 7, 400_000_000, time.UTC) // no provenance record: its mtime
	if err := os.Chtimes(f, at, at); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		deletedAt string
		keep      bool
	}{
		{"2026-10-13T12:54:08Z", false},   // deleted after it was published
		{"2026-10-13T12:54:07Z", false},   // the delete's second covers 12:54:07.4
		{"2026-10-13T12:54:07.5Z", false}, // to the nanosecond, after it
		{"2026-10-13T12:54:07.3Z", true},  // to the nanosecond, before it
		{"2026-10-13T12:54:06Z", true},    // deleted the second before it was published
		{"2026-10-13T06:09:55Z", true},    // and imgq, hours after
		{"not a time", true},              // fail closed
	} {
		why := publishedAfterDelete("imgr", f, tc.deletedAt)
		if got := why != ""; got != tc.keep {
			t.Errorf("deleted at %s: keep=%v (%q), want keep=%v", tc.deletedAt, got, why, tc.keep)
		}
	}
	if why := publishedAfterDelete("imgr", filepath.Join(t.TempDir(), "gone.qcow2"), "2026-10-13T12:54:08Z"); why == "" {
		t.Error("a file whose publish time cannot be read was not kept")
	}
}
