package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// F3-b (rr3): a backing reference whose directory part does not resolve (a
// missing directory, a dangling link) reads as missing, as the kernel's
// open does, also when a file sits at the path the text cleans to. On
// 7b8f27bf1 keptBackingPath returned the cleaned text, so the decoy
// <disks>/web-data.qcow2 was reported as the base (stands_on) and its chain
// walked.
//
// Mutations: return the cleaned path again: red; return the error instead
// of the path: red.
func TestKeptRelease_AMissingDirectoryBeforeDotDotReadsAsMissing(t *testing.T) {
	for _, kind := range []string{"missing directory", "dangling link"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			top := s.images.DiskPath("web", "root")
			disks := filepath.Dir(top)
			if err := os.MkdirAll(disks, 0o755); err != nil {
				t.Fatal(err)
			}
			if kind == "dangling link" {
				if err := os.Symlink(filepath.Join(disks, "nowhere"), filepath.Join(disks, "sub")); err != nil {
					t.Fatal(err)
				}
			}
			decoy := filepath.Join(disks, "web-data.qcow2")
			if err := qcow2.Create(decoy, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			was, _ := os.ReadFile(decoy)
			if err := qcow2.CreateWithBackingFormat(top, "sub/../web-data.qcow2", "qcow2", 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			if err := health.NoteKeptDisks(s.dataDir, "web", []string{top}); err != nil {
				t.Fatal(err)
			}
			list, err := s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{})
			if err != nil || len(list.Chains) != 1 {
				t.Fatalf("list = %+v, %v", list, err)
			}
			ch := list.Chains[0]
			if slices.Contains(ch.StandsOn, decoy) || ch.MissingBase == "" || ch.MissingBase == decoy {
				t.Fatalf("chain = %+v; want a missing base, and not %s", ch, decoy)
			}
			if _, err := keptRelease(s, "web"); err != nil {
				t.Fatalf("release web: %v", err)
			}
			if got, err := os.ReadFile(decoy); err != nil || !bytes.Equal(got, was) {
				t.Fatalf("the decoy %s went with web's kept disk (err=%v)", decoy, err)
			}
			if exists(top) {
				t.Error("web's kept disk is still there")
			}
		})
	}
}
