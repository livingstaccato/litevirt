package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ageOutClockSkew removes the clock_skew rows the replicator's prune removes
// when the clock reads now: those older than corrosion.ClockSkewRetention.
func ageOutClockSkew(t *testing.T, s *Server, now time.Time) {
	t.Helper()
	ctx := context.Background()
	cutoff := now.Add(-corrosion.ClockSkewRetention).UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx, `DELETE FROM clock_skew WHERE updated_at < ?`, cutoff); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.db.Query(ctx, `SELECT 1 FROM clock_skew`); err != nil || len(rows) != 0 {
		t.Fatalf("clock_skew rows left after the retention: %v (err %v)", rows, err)
	}
}

// Re-review 2, m-2: a skew seen while its clock_skew rows were held still sets
// the margin of a delete made while it was measured, after the rows have aged
// out (ClockSkewRetention, 1 hour) and across a restart; it does not widen the
// margin of a delete made long after it.
func TestImageDeleteMargin_RememberedPastTheSkewRowsRetention(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := testServer(t)
	s.dataDir = dataDir
	measured := time.Now().UTC().Add(-70 * time.Minute) // the clock now reads 70 minutes past it
	if err := s.db.Execute(ctx, `INSERT INTO clock_skew (observer, target, skew_seconds, updated_at) VALUES ('a','b',900,?)`,
		measured.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	s.recordImageSkew(ctx) // RunImageSkewRecorder's look while the row was held
	ageOutClockSkew(t, s, time.Now())

	deleted := measured.Add(2 * time.Minute).Format(time.RFC3339Nano)
	long := measured.Add(3 * time.Hour).Format(time.RFC3339Nano)
	check := func(s *Server, what string) {
		t.Helper()
		if m, err := s.imageDeleteMargin(ctx, deleted); err != nil || m != 15*time.Minute {
			t.Fatalf("%s: a delete while a 900 s skew was measured: margin %s (err %v), want 15m", what, m, err)
		}
		if m, err := s.imageDeleteMargin(ctx, long); err != nil || m != imageDeleteMarginFloor {
			t.Fatalf("%s: a delete 3 hours after it: margin %s (err %v), want the floor", what, m, err)
		}
	}
	check(s, "after the rows aged out")

	restarted := testServer(t) // a new database: none of the rows
	restarted.dataDir = dataDir
	check(restarted, "after a restart")

	// A history that cannot be read decides nothing: an error, so the prune
	// keeps the file; once it is readable (here: removed) it decides again.
	if err := os.WriteFile(filepath.Join(dataDir, imageSkewHistoryFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := testServer(t)
	unreadable.dataDir = dataDir
	if _, err := unreadable.imageDeleteMargin(ctx, deleted); err == nil {
		t.Fatal("an unreadable history gave a margin")
	}
}

// The prune keeps a deleted image's file published within a remembered skew
// of the delete after the skew's rows have aged out, and keeps every such file
// while the history cannot be read.
func TestPruneImages_KeepsAFileWithinARememberedSkewOfTheDelete(t *testing.T) {
	ctx := context.Background()
	s := pruneServer(t)
	noSeams(s)
	measured := time.Now().UTC().Add(-61 * time.Minute)
	if err := s.db.Execute(ctx, `INSERT INTO clock_skew (observer, target, skew_seconds, updated_at) VALUES ('a','b',900,?)`,
		measured.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	s.recordImageSkew(ctx)
	ageOutClockSkew(t, s, time.Now())

	f := deletedImage(t, s, "ubuntu") // published, then deleted, just now
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "within 15m0s of its image's delete") {
		t.Fatalf("file there: %v, reason %q; want it kept within the remembered 15m margin", exists(f), keptFor(resp, f))
	}

	history := filepath.Join(s.dataDir, imageSkewHistoryFile)
	unreadable := pruneServer(t)
	noSeams(unreadable)
	if err := os.WriteFile(filepath.Join(unreadable.dataDir, imageSkewHistoryFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f = deletedImage(t, unreadable, "ubuntu")
	resp, err = unreadable.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "clock skews this host has seen cannot be read") {
		t.Fatalf("file there: %v, reason %q; want it kept while the history cannot be read", exists(f), keptFor(resp, f))
	}
	if err := os.Remove(filepath.Join(unreadable.dataDir, imageSkewHistoryFile)); err != nil {
		t.Fatal(err)
	}
	resp, err = unreadable.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if exists(f) {
		t.Fatalf("history removed, no skew: the file is still there (reason %q)", keptFor(resp, f))
	}
	if _, err := os.Stat(history); err != nil {
		t.Fatalf("the remembered skew was not saved to %s: %v", history, err)
	}
}
