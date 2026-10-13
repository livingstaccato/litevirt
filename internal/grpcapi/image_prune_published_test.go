package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/image"
)

// publishedAfterDelete (review round 1, I-3): a deleted image's file is the
// delete's only when it was published more than margin before the delete —
// the two times are two hosts' clocks. At or after deletedAt-margin it is
// kept; a delete recorded to the second is not widened; what cannot be read
// keeps the file.
func TestPublishedAfterDelete(t *testing.T) {
	f := filepath.Join(t.TempDir(), "imgr@0123456789abcdef.qcow2")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 13, 12, 54, 7, 400_000_000, time.UTC) // no provenance record: its mtime
	if err := os.Chtimes(f, at, at); err != nil {
		t.Fatal(err)
	}
	const margin = 5 * time.Minute
	stamp := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	for _, tc := range []struct {
		name      string
		deletedAt string
		margin    time.Duration
		keep      bool
	}{
		{"deleted well after it was published", stamp(at.Add(margin + time.Second)), margin, false},
		{"one nanosecond past the margin", stamp(at.Add(margin + time.Nanosecond)), margin, false},
		{"exactly at the margin: kept", stamp(at.Add(margin)), margin, true},
		// The deleting host's clock runs ahead of this one: the operator
		// re-imported here after the delete, and the delete reads later.
		{"a deleter clock running 3 minutes ahead", stamp(at.Add(3 * time.Minute)), margin, true},
		{"deleted before it was published", stamp(at.Add(-time.Hour)), margin, true},
		// A delete recorded to the second is its second's first instant;
		// nothing widens it toward removal.
		{"a second-precision delete in the publish's second", "2026-10-13T12:54:07Z", 0, true},
		{"a second-precision delete the second after", "2026-10-13T12:54:08Z", 0, false},
		{"an unreadable delete time", "not a time", margin, true},
	} {
		why := publishedAfterDelete("imgr", f, tc.deletedAt, tc.margin)
		if got := why != ""; got != tc.keep {
			t.Errorf("%s (deleted at %s, margin %s): keep=%v (%q), want keep=%v", tc.name, tc.deletedAt, tc.margin, got, why, tc.keep)
		}
	}
	if why := publishedAfterDelete("imgr", filepath.Join(t.TempDir(), "gone.qcow2"), stamp(at.Add(time.Hour)), margin); why == "" {
		t.Error("a file whose publish time cannot be read was not kept")
	}
	if why := publishedAfterDelete("imgr", f, stamp(at.Add(3*time.Minute)), margin); !strings.Contains(why, "lv image rm imgr again after") {
		t.Errorf("the kept reason does not say how to remove it: %q", why)
	}
}

// A re-import of the same content reuses the file: its republish counts as
// its publish for the guard (review round 1, m-2).
func TestPublishedAfterDelete_ReadsTheRepublish(t *testing.T) {
	st := image.NewStore(t.TempDir())
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	publish := func() string {
		tmp := filepath.Join(st.ImageDir(), "import-x.tmp")
		if err := os.WriteFile(tmp, []byte("same content"), 0o600); err != nil {
			t.Fatal(err)
		}
		d, err := image.FileDigest(tmp)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := st.Publish("imgr", tmp, d)
		if err != nil {
			t.Fatal(err)
		}
		return pub.Path
	}
	f := publish()
	p, _ := image.RecordedProvenance(f)
	deletedAt := p.PublishedAt.Add(10 * time.Millisecond).Format(time.RFC3339Nano)
	if why := publishedAfterDelete("imgr", f, deletedAt, 0); why != "" {
		t.Fatalf("published before the delete, yet kept: %q", why)
	}
	time.Sleep(20 * time.Millisecond)
	if again := publish(); again != f {
		t.Fatalf("the same content published again went to %s, not the file it reuses %s", again, f)
	}
	if why := publishedAfterDelete("imgr", f, deletedAt, 0); why == "" {
		t.Fatal("re-imported after the delete, yet the file reads as the delete's")
	}
}

// imageDeleteMargin: the floor (hlc.MaxSkewMS) unless a fresher measured skew
// is larger; a stale measurement does not count.
func TestImageDeleteMargin(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if m := s.imageDeleteMargin(ctx); m != imageDeleteMarginFloor {
		t.Fatalf("no measured skew: margin %s, want the floor %s", m, imageDeleteMarginFloor)
	}
	stale := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	fresh := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx, `INSERT INTO clock_skew (observer, target, skew_seconds, updated_at) VALUES ('a','b',900,?)`, stale); err != nil {
		t.Fatal(err)
	}
	if m := s.imageDeleteMargin(ctx); m != imageDeleteMarginFloor {
		t.Fatalf("only a stale measurement: margin %s, want the floor", m)
	}
	if err := s.db.Execute(ctx, `INSERT INTO clock_skew (observer, target, skew_seconds, updated_at) VALUES ('a','c',-420,?)`, fresh); err != nil {
		t.Fatal(err)
	}
	if m := s.imageDeleteMargin(ctx); m != 7*time.Minute {
		t.Fatalf("a fresh 420 s skew: margin %s, want 7m", m)
	}
}
