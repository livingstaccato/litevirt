package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// streamLen is the number of entries this node has put on its own
// replication stream.
func streamLen(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("count mutation_log: %v", err)
	}
	return rows[0].Int("n")
}

// lastEntry is the statements of the newest entry on this node's stream.
func lastEntry(t *testing.T, s *Server) string {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the newest mutation_log entry: %v (%d rows)", err, len(rows))
	}
	return rows[0].String("stmts")
}

func latchRelease(t *testing.T, s *Server) {
	s.SetReleaseFeatureGate(splitTokenGate{fakeFeatureGate: fakeFeatureGate{t: t, grant: true}, feature: "some_other_feature", released: true})
}

func testImageHost(s *Server) corrosion.ImageHostRecord {
	return corrosion.ImageHostRecord{ImageName: "imgr", HostName: s.hostName, Path: "/x/imgr.qcow2", Status: "ready", PulledAt: "2026-10-13T00:00:00Z"}
}

// Before the release token latches, recordImageHost writes exactly one entry,
// the plain insert (review round 1, m-4): positively that statement, so a
// recordImageHost that wrote nothing cannot pass.
func TestRecordImageHost_UnlatchedWritesThePlainInsert(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, reviving := range []bool{false, true} {
		before := streamLen(t, s)
		if err := s.recordImageHost(ctx, testImageHost(s), reviving); err != nil {
			t.Fatal(err)
		}
		if n := streamLen(t, s); n != before+1 {
			t.Fatalf("reviving=%v: the stream grew by %d entries, want 1", reviving, n-before)
		}
		e := lastEntry(t, s)
		if !strings.Contains(e, "INSERT OR REPLACE INTO image_hosts") || strings.Contains(e, "ON CONFLICT") {
			t.Fatalf("reviving=%v: before the release token latched, want the plain insert, got: %s", reviving, e)
		}
	}
}

// Once the release token has latched, recordImageHost always writes the
// reviving form (review round 1, I-2) — over a row that reads live here too:
// lv image rm on another host may not have reached this one yet.
func TestRecordImageHost_LatchedAlwaysRevives(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	latchRelease(t, s)
	for _, reviving := range []bool{false, true} {
		before := streamLen(t, s)
		if err := s.recordImageHost(ctx, testImageHost(s), reviving); err != nil {
			t.Fatal(err)
		}
		if n := streamLen(t, s); n != before+1 {
			t.Fatalf("reviving=%v: the stream grew by %d entries, want 1", reviving, n-before)
		}
		if e := lastEntry(t, s); !strings.Contains(e, "ON CONFLICT(image_name, host_name)") || !strings.Contains(e, "deleted_at = NULL") {
			t.Fatalf("reviving=%v: with the release token latched, want the reviving upsert, got: %s", reviving, e)
		}
	}
}

const reviveStmt = "UPDATE images SET deleted_at = ?"

// Only an operator's import writes the catalog revive (review round 1, I-1):
// a copy from a peer (push, auto-pull, heal), a pull, a build and a compose
// download write the plain insert, refuse a name that reads deleted, and
// record nothing when the row was deleted while they ran. An import revives a
// name that read deleted as it began, and records nothing when it was deleted
// again while it ran.
func TestRecordImage_OnlyAnOperatorImportRevives(t *testing.T) {
	ctx := context.Background()
	img := corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:ab"}
	for _, op := range []imageOp{imageOpImport, imageOpCopy, imageOpPull, imageOpBuild, imageOpCompose} {
		t.Run(string(op), func(t *testing.T) {
			s := testServer(t)
			ih := testImageHost(s)

			// A live (here: absent) row: the write, reviving only for an import.
			if err := s.recordImage(ctx, op, "", img, ih); err != nil {
				t.Fatal(err)
			}
			rows, _ := s.db.Query(ctx, `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 2`)
			catalog := rows[1].String("stmts")
			if !strings.Contains(catalog, "INSERT OR REPLACE INTO images") {
				t.Fatalf("the catalog write is not the images insert: %s", catalog)
			}
			if got := strings.Contains(catalog, reviveStmt); got != op.revives() {
				t.Fatalf("%s wrote the catalog revive=%v, want %v: %s", op, got, op.revives(), catalog)
			}

			// lv image rm while the operation ran: nothing recorded.
			if err := corrosion.DeleteImage(ctx, s.db, "imgr"); err != nil {
				t.Fatal(err)
			}
			before := streamLen(t, s)
			err := s.recordImage(ctx, op, "", img, ih)
			if status.Code(err) != codes.Aborted {
				t.Fatalf("%s over a row deleted while it ran: %v, want Aborted", op, err)
			}
			if n := streamLen(t, s); n != before {
				t.Fatalf("%s over a row deleted while it ran wrote %d entries", op, n-before)
			}

			// The row read deleted as the operation began.
			deletedAt, err := s.imageOpStart(ctx, "imgr", op)
			if !op.revives() {
				if status.Code(err) != codes.FailedPrecondition {
					t.Fatalf("%s of a deleted name began: %v, want FailedPrecondition", op, err)
				}
				if err := s.recordImage(ctx, op, deletedAt, img, ih); status.Code(err) != codes.FailedPrecondition {
					t.Fatalf("%s recorded over a deleted name: %v, want FailedPrecondition", op, err)
				}
				if n := streamLen(t, s); n != before {
					t.Fatalf("%s of a deleted name wrote %d entries", op, n-before)
				}
				return
			}
			if err != nil {
				t.Fatalf("an import of a deleted name refused to begin: %v", err)
			}
			if err := s.recordImage(ctx, op, deletedAt, img, ih); err != nil {
				t.Fatalf("an import of a deleted name: %v", err)
			}
			if d, _ := corrosion.ImageDeletedAt(ctx, s.db, "imgr"); d != "" {
				t.Fatalf("the import left the row deleted (%s)", d)
			}
		})
	}
}

// isImageCopy: PushImage's mark, or a peer under its own identity, is a copy;
// an operator — directly, on the node, or relayed by a peer as themselves —
// imports.
func TestIsImageCopy(t *testing.T) {
	bare := context.Background()
	peer := context.WithValue(context.WithValue(bare, ctxKeyPrincipalKind, principalKindPeer), ctxKeyAuthMethod, authMethodMTLS)
	relayed := context.WithValue(context.WithValue(bare, ctxKeyPrincipalKind, principalKindPeer), ctxKeyAuthMethod, authMethodSession)
	localRoot := context.WithValue(context.WithValue(bare, ctxKeyPrincipalKind, principalKindLocalRoot), ctxKeyAuthMethod, authMethodMTLS)
	marked := metadata.NewIncomingContext(relayed, metadata.Pairs(imageCopyMDKey, "push"))
	for _, tc := range []struct {
		name string
		ctx  context.Context
		copy bool
	}{
		{"a session", bare, false},
		{"a peer as itself (an earlier build's push)", peer, true},
		{"an operator relayed by a peer", relayed, false},
		{"root on the node", localRoot, false},
		{"PushImage's mark", marked, true},
	} {
		if got := isImageCopy(tc.ctx); got != tc.copy {
			t.Errorf("%s: copy=%v, want %v", tc.name, got, tc.copy)
		}
	}
}
