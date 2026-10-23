package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// dotdotDeleteFixture is VM web as a real `lv rm --keep-disks` leaves it: its
// disk web-root.qcow2 backs on "sub/../web-data.qcow2", and <disks>/sub
// points into the legacy directory <disks>/web, so the base the kernel opens
// is <disks>/web/web-data.qcow2, one of web's own candidates. The note is
// written by the delete's own noteKeptDisks, then the VM's row goes. It
// returns the top, the real base, and the base's bytes.
func dotdotDeleteFixture(t *testing.T) (*Server, string, string, []byte) {
	t.Helper()
	s, _ := provableCreateServer(t)
	top := s.images.DiskPath("web", "root")
	disks := filepath.Dir(top)
	sub := filepath.Join(disks, "web", "inner")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(disks, "sub")); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(disks, "web", "web-data.qcow2")
	if err := qcow2.Create(real, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(real, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("THE ONLY COPY OF THE GUEST'S DATA"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	was, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(top, "sub/../web-data.qcow2", "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: s.hostName, Path: top, StorageType: "local", DeleteWithVM: true}}); err != nil {
		t.Fatal(err)
	}
	if err := s.noteKeptDisks(adminCtx(), "web", true); err != nil {
		t.Fatalf("noteKeptDisks: %v", err)
	}
	if err := corrosion.DeleteVM(adminCtx(), s.db, "web"); err != nil {
		t.Fatal(err)
	}
	return s, top, real, was
}

func baseUntouched(t *testing.T, real string, was []byte, when string) {
	t.Helper()
	got, err := os.ReadFile(real)
	if err != nil || !bytes.Equal(got, was) {
		t.Fatalf("%s: %s, reached through \"..\", was removed or changed (err=%v)", when, real, err)
	}
}

// releaseNeverTakes releases the base by its path and checks that nothing
// removed it.
func releaseNeverTakes(t *testing.T, s *Server, real string, was []byte) {
	t.Helper()
	if _, err := keptRelease(s, real); err == nil {
		t.Errorf("release %s by its path succeeded; it is reached through \"..\" and is never released", real)
	}
	baseUntouched(t, real, was, "release of the base by its path")
}

// F3-a (rr3): a file reached through ".." is listed only, also when the
// delete's own note reaches it. On 7b8f27bf1 noteKeptDisks noted the real
// base <disks>/web/web-data.qcow2 as a file web's kept disk backs on, so
// keptUnits made it a top of its own: `release web` was refused on web's own
// chain, and releasing the top and then the base by path removed the base.
//
//   - noteKeptDisks notes the top only: nothing at or below the layer it
//     reaches through "..";
//   - `release web` removes the top only, with the base under stands_on, and
//     a release of the base by its path afterwards removes nothing;
//   - the top, then the base, by path: the base stays;
//   - a note an earlier build wrote naming the base (as 7b8f27bf1 did) is
//     read the same way, and the release forgets that entry with the top;
//   - with the base no longer noted, a create of the name and the debris
//     sweep still leave it while the top is there;
//   - a second kept overlay naming the base by its real path still leaves
//     it listed only.
//
// Mutations: note every candidate layer again (noteKeptBackingFiles): the
// first subtest red; let keptUnits make a ".."-reached file a top: "an
// earlier build's note" red; let another chain's own walk take it: "another
// kept chain" red; drop the release's forgetting of such an entry: "an
// earlier build's note" red; drop the hold of a noted chain's ".."-reached
// layers from the create guard, or from keptHolds: "a create of the name"
// red.
func TestKeptRelease_NeverTakesWhatADeleteReachedThroughDotDot(t *testing.T) {
	t.Run("the delete notes nothing at or below the .. layer", func(t *testing.T) {
		s, top, real, _ := dotdotDeleteFixture(t)
		noted, err := health.KeptNotedFiles(s.dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if noted[top] != "web" {
			t.Errorf("the kept disk %s is not noted: %v", top, noted)
		}
		if noted[real] != "" {
			t.Errorf("%s, reached through \"..\", is noted as web's: %v", real, noted)
		}
	})
	t.Run("release web removes only its own, and leaves the base listed", func(t *testing.T) {
		s, top, real, was := dotdotDeleteFixture(t)
		list, err := s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{})
		if err != nil || len(list.Chains) != 1 {
			t.Fatalf("list = %+v, %v; want web's one chain", list, err)
		}
		if ch := list.Chains[0]; len(ch.Files) != 1 || ch.Files[0].Path != top || !slices.Contains(ch.StandsOn, real) || ch.Held != "" {
			t.Fatalf("chain = %+v; want only %s to go, standing on %s, releasable", ch, top, real)
		}
		resp, err := keptRelease(s, "web")
		if err != nil {
			t.Fatalf("release web: %v", err)
		}
		if exists(top) {
			t.Error("web's kept disk is still there")
		}
		baseUntouched(t, real, was, "release web")
		if len(resp.Chains) != 1 || !slices.Contains(resp.Chains[0].StandsOn, real) {
			t.Errorf("release answer = %+v; want %s under stands_on", resp.Chains, real)
		}
		releaseNeverTakes(t, s, real, was)
	})
	t.Run("the top, then the base, by path", func(t *testing.T) {
		s, top, real, was := dotdotDeleteFixture(t)
		if _, err := keptRelease(s, top); err != nil {
			t.Fatalf("release %s: %v", top, err)
		}
		baseUntouched(t, real, was, "release of the top")
		releaseNeverTakes(t, s, real, was)
	})
	t.Run("an earlier build's note naming the base", func(t *testing.T) {
		for _, first := range []string{"web", "top"} {
			t.Run(first, func(t *testing.T) {
				s, top, real, was := dotdotDeleteFixture(t)
				// As 7b8f27bf1's noteKeptBackingFiles wrote it.
				if err := health.NoteKeptBackingFiles(s.dataDir, "web", []string{real}); err != nil {
					t.Fatal(err)
				}
				list, err := s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{})
				if err != nil || len(list.Chains) != 1 {
					t.Fatalf("list = %+v, %v; want web's one chain, the base not a top of its own", list, err)
				}
				if ch := list.Chains[0]; len(ch.Files) != 1 || !slices.Contains(ch.StandsOn, real) || ch.Held != "" {
					t.Fatalf("chain = %+v; want only %s to go, standing on %s, releasable", ch, top, real)
				}
				what := "web"
				if first == "top" {
					what = top
				}
				if _, err := keptRelease(s, what); err != nil {
					t.Fatalf("release %s: %v", what, err)
				}
				if exists(top) {
					t.Error("web's kept disk is still there")
				}
				baseUntouched(t, real, was, "release "+first)
				releaseNeverTakes(t, s, real, was)
				if noted, _ := health.KeptNotedFiles(s.dataDir); noted[real] != "" {
					t.Errorf("%s is still noted for web with nothing kept over it: a create of the name would refuse on it for good", real)
				}
			})
		}
	})
	t.Run("another kept chain reaching it directly", func(t *testing.T) {
		s, top, real, was := dotdotDeleteFixture(t)
		// A second kept overlay of web that names the base by its real
		// path, with no "..": the base is still listed only.
		snap := filepath.Join(filepath.Dir(top), "web-snap.qcow2")
		if err := qcow2.CreateWithBackingFormat(snap, real, "qcow2", 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		if err := health.NoteKeptDisks(s.dataDir, "web", []string{snap}); err != nil {
			t.Fatal(err)
		}
		resp, err := keptRelease(s, "web")
		if err != nil {
			t.Fatalf("release web: %v", err)
		}
		if exists(top) || exists(snap) {
			t.Error("a kept overlay of web is still there")
		}
		baseUntouched(t, real, was, "release web")
		for _, ch := range resp.Chains {
			for _, f := range ch.Files {
				if f.Path == real {
					t.Errorf("release answer = %+v; %s is among the files it removes", resp.Chains, real)
				}
			}
		}
		releaseNeverTakes(t, s, real, was)
	})
	t.Run("a create of the name still leaves the base while the top is there", func(t *testing.T) {
		s, top, real, was := dotdotDeleteFixture(t)
		s.sweepVMDiskDebris(adminCtx(), "web")
		baseUntouched(t, real, was, "the debris sweep")
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), real) {
			t.Fatalf("create web = %v; want FailedPrecondition naming %s", err, real)
		}
		baseUntouched(t, real, was, "a refused create")
		if !exists(top) {
			t.Error("the kept disk went in a refused create")
		}
	})
}

// The stale-record delete's note (noteDeleteKeptDisks) names nothing at or
// below the layer a kept chain reaches through ".." either.
//
// Mutation: note every layer below the top again: red.
func TestKeptRelease_TheStaleRecordNoteStopsAboveDotDot(t *testing.T) {
	s, _ := provableCreateServer(t)
	top := s.images.DiskPath("web", "root")
	disks := filepath.Dir(top)
	sub := filepath.Join(disks, "web", "inner")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(disks, "sub")); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(disks, "web", "web-data.qcow2")
	if err := qcow2.Create(real, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(top, "sub/../web-data.qcow2", "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: s.hostName, Path: top, StorageType: "local", DeleteWithVM: true}}); err != nil {
		t.Fatal(err)
	}
	if err := s.noteDeleteKeptDisks(adminCtx(), "web", []KeptDisk{{Path: top, Disk: "root", Host: s.hostName, Reason: "no answer"}}); err != nil {
		t.Fatalf("noteDeleteKeptDisks: %v", err)
	}
	noted, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if noted[top] != "web" || noted[real] != "" {
		t.Fatalf("noted = %v; want %s and not %s", noted, top, real)
	}
}

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
