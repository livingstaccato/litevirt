package grpcapi

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Follow-up 1: in a shared directory, a plain ISO/image file that no VM disk
// row (on any host), replica or other pool's upload refers to is library
// content, visible to everyone who may read the pool — as before pools were
// confined. Deleting it is an admin's. A file a record does refer to stays
// with its owner.
func TestPoolFollowup_UnownedImagesAreLibraryContent(t *testing.T) {
	for _, project := range []string{"", "acme"} {
		t.Run("project="+project, func(t *testing.T) {
			s := newPoolTestServer(t)
			disks := filepath.Join(s.dataDir, "disks")
			if err := os.MkdirAll(disks, 0o755); err != nil {
				t.Fatal(err)
			}
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "default", Driver: "local", Target: disks, Project: project})
			in := func(n string) string { return filepath.Join(disks, n) }
			insertProjectVM(t, s, "bvm", "bravo", "root", in("bvm-root.qcow2"), "default")
			// A disk row on another host naming a file here still owns it.
			if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "cvm", Project: "bravo", HostName: "host-b", State: "stopped"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{
				VMName: "cvm", DiskName: "root", HostName: "host-b", Path: in("cvm-root.qcow2"), StorageType: "local",
			}); err != nil {
				t.Fatal(err)
			}
			insertReplicationSchedule(t, s, "bvm", "elsewhere")
			for _, n := range []string{"debian.iso", "bvm-root.qcow2", "cvm-root.qcow2", "bvm-root-20261006T000000Z.qcow2",
				"bvm-root.qcow2.superseded-20261006T000000Z", "notes.txt"} {
				writePoolFile(t, in(n), n)
			}
			pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))

			if got := listNames(t, s, pat, "default"); !slices.Equal(got, []string{"debian.iso"}) {
				t.Fatalf("acme's listing = %v, want [debian.iso]", got)
			}
			_, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "default", Filename: "debian.iso"})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("an operator deleting an unowned library ISO: got %v, want PermissionDenied", err)
			}
			if _, err := os.Stat(in("debian.iso")); err != nil {
				t.Fatalf("the library ISO was deleted: %v", err)
			}
			if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "default", Filename: "debian.iso"}); err != nil {
				t.Fatalf("the admin deleting it: %v", err)
			}
		})
	}
}

// Follow-up 2: unowned library content is installer media only. An unowned
// disk image (.qcow2, .raw, .img, …) may be any project's — it is an
// admin's, not library content. A disk kept after its VM was deleted (or
// detached) is still owned, through its tombstoned rows: its project sees it
// (a row on this host), nobody else does (a row on any host hides it).
func TestPoolFollowup2_LibraryIsMediaAndKeptDisksStayOwned(t *testing.T) {
	s := newPoolTestServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "default", Driver: "local", Target: disks})
	in := func(n string) string { return filepath.Join(disks, n) }

	// bravo's VM, deleted with its disk kept; a VM on another host likewise.
	insertProjectVM(t, s, "bvm", "bravo", "root", in("bvm-root.qcow2"), "default")
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "cvm", Project: "bravo", HostName: "host-b", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "cvm", DiskName: "root", HostName: "host-b", Path: in("cvm-root.raw"), StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	for _, vm := range []string{"bvm", "cvm"} {
		if err := corrosion.DeleteVM(adminCtx(), s.db, vm); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"debian.iso", "win.iso.xz", "other-project.qcow2", "old.img", "bvm-root.qcow2", "cvm-root.raw"} {
		writePoolFile(t, in(n), n)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))

	if got := listNames(t, s, pat, "default"); !slices.Equal(got, []string{"debian.iso", "win.iso.xz"}) {
		t.Errorf("acme's listing = %v, want only the ISOs", got)
	}
	// cvm's row is on host-b: it describes host-b's file at that path, not
	// this one, so it hides the file here (owned) without giving it to bravo.
	if got := listNames(t, s, bob, "default"); !slices.Equal(got, []string{"bvm-root.qcow2", "debian.iso", "win.iso.xz"}) {
		t.Errorf("bravo's listing = %v, want its kept disk on this host and the ISOs", got)
	}
	if got := listNames(t, s, adminCtx(), "default"); !slices.Contains(got, "other-project.qcow2") || !slices.Contains(got, "old.img") {
		t.Errorf("the admin's listing lacks the unowned disk images: %v", got)
	}
}
