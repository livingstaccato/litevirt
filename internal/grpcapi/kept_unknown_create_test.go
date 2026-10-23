package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// keptUnknown makes what kept overlays on s's host back on unknown: how is
// "registry" (kept-disks.json does not parse) or "chain" (a kept disk's
// qcow2 header is cut short). It returns the file the refusal names.
func keptUnknown(t *testing.T, s *Server, how string) string {
	t.Helper()
	switch how {
	case "registry":
		f := filepath.Join(s.dataDir, diskKeptFile)
		if err := os.WriteFile(f, []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	case "chain":
		top := registryKeep(t, s, "old", filepath.Join(t.TempDir(), "gone-base.raw"))
		if err := os.Truncate(top, 16); err != nil {
			t.Fatal(err)
		}
		return top
	}
	t.Fatalf("unknown setup %q", how)
	return ""
}

// While what a kept overlay backs on cannot be read, only a create that
// writes a disk on this host's own storage can become its base: one with no
// disk, or with every disk on shared storage, goes ahead. A create of a local
// disk is still refused.
//
// Mutation: treat every create as writing a local disk
// (createWritesHostDisk returns true): the diskless and ceph subtests red.
func TestCreateVM_AnUnknownKeptChainHoldsOnlyCreatesThatWriteHere(t *testing.T) {
	for _, how := range []string{"registry", "chain"} {
		t.Run(how+"/no disks", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			keptUnknown(t, s, how)
			if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("web")); err != nil {
				t.Fatalf("a create with no disk was refused: %v", err)
			}
		})
		t.Run(how+"/shared storage only", func(t *testing.T) {
			f := newCephPoolFixture(t)
			keptUnknown(t, f.s, how)
			if _, err := f.s.CreateVM(adminCtx(), cephCreateRequest("web", &pb.DiskSpec{Name: "root", Size: "1G", Storage: "ceph"})); err != nil {
				t.Fatalf("a create with every disk on ceph was refused: %v", err)
			}
		})
		t.Run(how+"/a local disk", func(t *testing.T) {
			f := newCephPoolFixture(t)
			named := keptUnknown(t, f.s, how)
			req := cephCreateRequest("web", &pb.DiskSpec{Name: "data", Size: "1G", Storage: "ceph"}, &pb.DiskSpec{Name: "root", Size: "1M"})
			_, err := f.s.CreateVM(adminCtx(), req)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
				t.Fatalf("a create with a local disk = %v; want FailedPrecondition naming %s", err, named)
			}
		})
	}
}

// An unknown kept chain is visible on the host, not only in the error of
// each create it refuses: disk_leftover names the file and what it holds up.
//
// Mutation: drop the keptRegistryChains check from judgeKeptDisks: the
// chain subtest red (the registry one is named by record_unreadable too,
// but not as refusing creates: red as well).
func TestKeptDisks_AnUnknownKeptChainIsNamedInHealth(t *testing.T) {
	for _, how := range []string{"registry", "chain"} {
		t.Run(how, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			named := keptUnknown(t, s, how)
			s.judgeKeptDisks(context.Background())
			open, ev := keptDiskCondition(t, s)
			if !open {
				t.Fatalf("disk_leftover is not raised: %s", ev)
			}
			var e map[string]any
			if err := json.Unmarshal([]byte(ev), &e); err != nil {
				t.Fatal(err)
			}
			refused, _ := e["creates_refused"].(string)
			if !strings.Contains(refused, named) {
				t.Fatalf("creates_refused = %q; want it to name %s", refused, named)
			}
		})
	}
}

// A kept chain that is read again lets the condition resolve: the
// evidence follows the file, not a latch.
func TestKeptDisks_AKeptChainReadAgainClearsTheRefusal(t *testing.T) {
	s, _ := provableCreateServer(t)
	keptUnknown(t, s, "chain")
	s.judgeKeptDisks(context.Background())
	if err := os.WriteFile(filepath.Join(s.dataDir, diskKeptFile), []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.judgeKeptDisks(context.Background())
	if open, ev := keptDiskCondition(t, s); open {
		t.Fatalf("still raised once the record no longer names the chain: %s", ev)
	}
}

// Minor 8: a create whose debris candidates cannot be listed is refused.
// Skipping the sweep skipped both kept-create checks with it.
//
// Mutation: log and return nil, nil on a VMDiskCandidates error again: red
// (the create goes ahead).
func TestCreateVM_RefusesWhenItsDebrisCannotBeListed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists a 0000 directory")
	}
	s, _ := provableCreateServer(t)
	legacy := filepath.Join(s.images.DiskDir("web"), "web")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(legacy, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(legacy, 0o755) })
	req := disklessCreateRequest("web")
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
	_, err := s.CreateVM(adminCtx(), req)
	if err == nil || !strings.Contains(err.Error(), legacy) {
		t.Fatalf("create web = %v; want a refusal naming %s", err, legacy)
	}
	if vm, gerr := corrosion.GetVM(adminCtx(), s.db, "web"); gerr != nil || vm != nil {
		t.Fatalf("a refused create left a VM row: %+v (%v)", vm, gerr)
	}
	if exists(s.images.DiskPath("web", "root")) {
		t.Fatal("a refused create wrote its disk")
	}
}

// Minor 6: an import refused because kept-disks.json cannot be read does not
// suggest another --name, which meets the same refusal.
//
// Mutation: append "import under another --name" again: red.
func TestImportVM_AnUnreadableKeptRecordDoesNotSuggestAnotherName(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	named := keptUnknown(t, s, "registry")
	err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp", false)}})
	if err == nil || !strings.Contains(err.Error(), named) {
		t.Fatalf("import = %v; want a refusal naming %s", err, named)
	}
	if strings.Contains(err.Error(), "another --name") {
		t.Fatalf("the refusal suggests another --name, which is refused the same way: %v", err)
	}
	if !strings.Contains(err.Error(), "whatever its name") {
		t.Fatalf("the refusal does not say a name does not help: %v", err)
	}
}

// The two ways a create the exemption could wrongly let through writes a
// local disk after all: an nfs pool whose target is this host's disk
// directory (as written, or through a symlink to it), and a create with an
// image and no disks, whose default root disk is local. Each is still
// refused while what kept overlays back on is unknown.
//
// Mutations: the nfs target clause never matches: the direct and symlink
// subtests red. Compare targets by filepath.Clean alone: the symlink
// subtest red. An image create with no disks counts as diskless: the image
// subtest red.
func TestCreateVM_AnUnknownKeptChainStillHoldsCreatesThatOnlyLookShared(t *testing.T) {
	nfsAt := func(t *testing.T, s *Server, target string) {
		t.Helper()
		ref := StoragePoolRef{Driver: "nfs", Source: "10.0.0.9:/export", Target: target}
		if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
			HostName: "test-host", Name: "share", Driver: ref.Driver, Source: ref.Source, Target: ref.Target, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		s.addStoragePoolRef("share", ref)
	}
	refused := func(t *testing.T, s *Server, req *pb.CreateVMRequest, named string) {
		t.Helper()
		_, err := s.CreateVM(adminCtx(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
			t.Fatalf("create = %v; want FailedPrecondition naming %s", err, named)
		}
	}
	for _, how := range []string{"registry", "chain"} {
		t.Run(how+"/nfs mounted at the disk directory", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			named := keptUnknown(t, s, how)
			nfsAt(t, s, s.images.DiskDir("web"))
			refused(t, s, cephCreateRequest("web", &pb.DiskSpec{Name: "root", Size: "1M", Storage: "share"}), named)
		})
		t.Run(how+"/nfs mounted at a symlink to the disk directory", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			named := keptUnknown(t, s, how)
			link := filepath.Join(t.TempDir(), "share")
			if err := os.Symlink(s.images.DiskDir("web"), link); err != nil {
				t.Fatal(err)
			}
			nfsAt(t, s, link)
			refused(t, s, cephCreateRequest("web", &pb.DiskSpec{Name: "root", Size: "1M", Storage: "share"}), named)
		})
		t.Run(how+"/an image and no disks", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			named := keptUnknown(t, s, how)
			img := s.images.ImagePath("base")
			if err := os.MkdirAll(filepath.Dir(img), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(img, []byte("not read: the create is refused first"), 0o644); err != nil {
				t.Fatal(err)
			}
			req := disklessCreateRequest("web")
			req.Spec.Image = "base"
			refused(t, s, req, named)
			if exists(s.images.DiskPath("web", "root")) {
				t.Fatal("a refused create wrote its default root disk")
			}
		})
	}
}
