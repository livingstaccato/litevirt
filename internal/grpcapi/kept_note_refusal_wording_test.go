package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/health"
)

// A refusal whose reason is a kept-disk note names the note, as its path
// <data_dir>/kept-disks/<vm>.json, so an operator knows which file to read and,
// once the disk is dealt with, to remove. Both the create's sweep (a file a
// kept disk backs on, refused by SetAsideBeforeCreate) and the guard an import
// meets (keptFileCreateRefusal with no notes governing) are pinned.
//
// Mutation: drop the note's path from either message — the matching subtest
// goes red.
func TestKeptNoteRefusals_NameTheNotesPath(t *testing.T) {
	t.Run("create over a file a kept disk backs on", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		if err := health.NoteKeptBackingFiles(s.dataDir, "web", []string{base}); err != nil {
			t.Fatal(err)
		}
		note := filepath.Join(s.dataDir, "kept-disks", "web.json")
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "kept-disk note "+note) {
			t.Fatalf("create web = %v; want FailedPrecondition naming the kept-disk note %s", err, note)
		}
		createRefused(t, s, base, was, "backs on")
	})
	t.Run("a file a note names, with no notes governing", func(t *testing.T) {
		s, dst := orphanFixture(t, "imp-kn")
		plantOld(t, dst, "kept base")
		if err := health.NoteKeptBackingFiles(s.dataDir, "imp-kn", []string{dst}); err != nil {
			t.Fatal(err)
		}
		note := filepath.Join(s.dataDir, "kept-disks", "imp-kn.json")
		err := s.keptFileCreateRefusal(context.Background(), "other", []string{dst}, func(string) bool { return false }, false)
		if err == nil || !strings.Contains(err.Error(), "kept-disk note "+note) {
			t.Fatalf("keptFileCreateRefusal = %v; want a refusal naming the kept-disk note %s", err, note)
		}
	})
}
