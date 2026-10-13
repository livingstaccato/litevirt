package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type pruneAuditRow struct{ action, target, detail, result, user string }

func pruneAuditRows(t *testing.T, s *Server) []pruneAuditRow {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT action, target, detail, result, username FROM audit_log WHERE action LIKE 'image.prune%' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var out []pruneAuditRow
	for _, r := range rows {
		out = append(out, pruneAuditRow{r.String("action"), r.String("target"), r.String("detail"), r.String("result"), r.String("username")})
	}
	return out
}

// Review round 2, R-1: --version removes a file on the operator's word that
// no other host's disk is built on it. Who removed which version, its bytes
// and the outcome are in the signed audit log; so is a plain prune that
// removed files. A dry run writes nothing.
//
// Mutations, each red: "no audit of --version"; "no audit of a prune that
// removed files"; "a dry run is audited".
func TestPruneImages_RemovalsAreAudited(t *testing.T) {
	s, old, used := prunableStore(t)
	s.imagePrune.storeFS = func(string) (string, error) { return "nfs", nil }
	ctx := adminCtx()

	if _, err := s.PruneImages(ctx, &pb.PruneImagesRequest{Name: "ubuntu", Version: filepath.Base(old), DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if rows := pruneAuditRows(t, s); len(rows) != 0 {
		t.Fatalf("a dry run was audited: %+v", rows)
	}

	if _, err := s.PruneImages(ctx, &pb.PruneImagesRequest{Name: "ubuntu", Version: filepath.Base(old)}); err != nil {
		t.Fatal(err)
	}
	rows := pruneAuditRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("audit rows %+v; want one for the version removed", rows)
	}
	r := rows[0]
	if r.action != "image.prune_version" || r.target != "images/ubuntu" || r.result != "success" || r.user != "admin" ||
		!strings.Contains(r.detail, old) || !strings.Contains(r.detail, "bytes=") {
		t.Fatalf("audit row %+v; want image.prune_version by admin naming %s and its bytes", r, old)
	}

	// A version the operator named that is kept: audited, with why.
	if _, err := s.PruneImages(ctx, &pb.PruneImagesRequest{Name: "ubuntu", Version: filepath.Base(used)}); err != nil {
		t.Fatal(err)
	}
	if rows = pruneAuditRows(t, s); len(rows) != 2 || rows[1].result != "kept" || !strings.Contains(rows[1].detail, "built on it") {
		t.Fatalf("audit rows %+v; want the kept version recorded with its reason", rows)
	}

	// A plain prune that removes a file, on a local store.
	s.imagePrune.storeFS = func(string) (string, error) { return "", nil }
	publishVersion(t, s, "ubuntu", "LATEST ", "")
	resp, err := s.PruneImages(ctx, &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil || len(resp.Removed) == 0 {
		t.Fatalf("plain prune: removed %v, %v", resp.GetRemoved(), err)
	}
	rows = pruneAuditRows(t, s)
	if len(rows) != 3 || rows[2].action != "image.prune" || !strings.Contains(rows[2].detail, resp.Removed[0]) {
		t.Fatalf("audit rows %+v; want an image.prune row naming what was removed", rows)
	}
}
