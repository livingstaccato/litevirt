package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A root disk in a file-based pool was backed by the bare image NAME, which
// qemu resolves next to the disk: inside the pool directory, where anyone who
// can upload to the pool can put a file of that name — a crafted qcow2 that
// chains to a host file. It is backed by the image store's own file instead,
// judged standalone first.

func poolBackingServer(t *testing.T) *Server {
	t.Helper()
	dataDir := t.TempDir()
	st := image.NewStore(dataDir)
	_ = st.Init()
	return &Server{dataDir: dataDir, images: st}
}

func TestPoolRootDiskBacking_IsTheImageStoreFile(t *testing.T) {
	s := poolBackingServer(t)
	if err := qcow2.Create(s.images.ImagePath("ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.poolRootDiskBacking("ubuntu", "dir")
	if err != nil {
		t.Fatalf("poolRootDiskBacking: %v", err)
	}
	if want := s.images.ImagePath("ubuntu"); got != want || !filepath.IsAbs(got) {
		t.Fatalf("backing = %q, want the image store's absolute path %q", got, want)
	}
}

func TestPoolRootDiskBacking_RefusesABaseThatNamesAHostFile(t *testing.T) {
	s := poolBackingServer(t)
	hostFile := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(hostFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(s.images.ImagePath("crafted"), hostFile, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.poolRootDiskBacking("crafted", "nfs"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("base image naming a host file: got %v, want FailedPrecondition", err)
	}
}

func TestPoolRootDiskBacking_RefusesAPathAsTheImageName(t *testing.T) {
	s := poolBackingServer(t)
	if _, err := s.poolRootDiskBacking("../../etc/shadow", "dir"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("image name with a path: got %v, want InvalidArgument", err)
	}
}

// A ceph root disk is built from the same image store file as any other
// (imported into the pool once, then cloned): the name an image create
// carries, auto-pulled like every image, never a caller-named rbd snapshot.
func TestPoolRootDiskBacking_CephUsesTheImageStoreFile(t *testing.T) {
	s := poolBackingServer(t)
	if err := qcow2.Create(s.images.ImagePath("cirros"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.poolRootDiskBacking("cirros", "ceph")
	if err != nil || got != s.images.ImagePath("cirros") {
		t.Fatalf("ceph backing = %q, %v; want the image store file", got, err)
	}
	if _, err := s.poolRootDiskBacking("rbd/base@gold", "ceph"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an rbd snapshot spec as the image: got %v, want InvalidArgument", err)
	}
}
