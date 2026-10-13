package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lastEntry is the statements of the newest entry this node put on its own
// replication stream.
func lastEntry(t *testing.T, s *Server) string {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the newest mutation_log entry: %v (%d rows)", err, len(rows))
	}
	return rows[0].String("stmts")
}

// recordImageHost over the row lv image rm left: the reviving upsert is a
// shape a host before the release cannot apply, so it goes on the stream only
// once the release token has latched here; before that, the plain insert.
// A row that is not deleted always gets the plain insert.
func TestRecordImageHost_RevivesOnlyOnceTheReleaseLatched(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	ih := corrosion.ImageHostRecord{ImageName: "imgr", HostName: s.hostName, Path: "/x/imgr.qcow2", Status: "ready", PulledAt: "2026-10-13T00:00:00Z"}
	if err := corrosion.InsertImageHost(ctx, s.db, ih); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteImage(ctx, s.db, "imgr"); err != nil {
		t.Fatal(err)
	}

	// No release gate: the release token has not latched.
	if err := s.recordImageHost(ctx, ih); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, s); strings.Contains(e, "ON CONFLICT") {
		t.Fatalf("before the release token latched, the reviving upsert went on the stream: %s", e)
	}

	// Latched: the reviving upsert.
	if err := corrosion.DeleteImage(ctx, s.db, "imgr"); err != nil {
		t.Fatal(err)
	}
	s.SetReleaseFeatureGate(splitTokenGate{fakeFeatureGate: fakeFeatureGate{t: t, grant: true}, feature: "some_other_feature", released: true})
	if err := s.recordImageHost(ctx, ih); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, s); !strings.Contains(e, "deleted_at = NULL") {
		t.Fatalf("over a deleted row with the release token latched, want the reviving upsert, got: %s", e)
	}
	if deleted, err := corrosion.ImageHostDeleted(ctx, s.db, "imgr", s.hostName); err != nil || deleted {
		t.Fatalf("the row still reads deleted after the revive (err %v)", err)
	}

	// A live row: the plain insert, latched or not.
	if err := s.recordImageHost(ctx, ih); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, s); strings.Contains(e, "ON CONFLICT") {
		t.Fatalf("over a live row, want the plain insert, got: %s", e)
	}
}
