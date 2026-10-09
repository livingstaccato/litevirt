package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/storage"
)

// Container inputs that name a host path go through the same rules a VM's do:
// naming one needs storage.hostpath (Admin), and the protected places are
// refused for everyone. A non-admin names an OCI library item instead.

func ctOperatorCtx() context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "op")
	return context.WithValue(ctx, ctxKeyRole, "operator")
}

// ctPathServer is a server with a real data directory and a fake runtime.
func ctPathServer(t *testing.T) (*Server, *fakeCTRuntime) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	s.pkiDir = filepath.Join(t.TempDir(), "pki")
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	return s, rt
}

// mkCTRootfs makes a directory that looks like a root filesystem.
func mkCTRootfs(t *testing.T, dir string) string {
	t.Helper()
	for _, d := range []string{"bin", "etc", "usr"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func createCT(s *Server, ctx context.Context, name, template string) error {
	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{Name: name, Template: template})
	return err
}

func TestCreateContainer_OperatorNamingAHostPathIsDenied(t *testing.T) {
	s, rt := ctPathServer(t)
	rootfs := mkCTRootfs(t, filepath.Join(t.TempDir(), "rootfs"))
	for _, tmpl := range []string{"/etc", rootfs, "rootfs:" + rootfs} {
		err := createCT(s, ctOperatorCtx(), "c1", tmpl)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("operator template %q: got %v, want PermissionDenied", tmpl, err)
		}
	}
	if len(rt.createCalls) != 0 {
		t.Fatalf("the runtime was asked to create from a host path: %+v", rt.createCalls)
	}
}

func TestCreateContainer_OperatorNamesAnOCILibraryItem(t *testing.T) {
	s, rt := ctPathServer(t)
	item := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "alpine", "rootfs"))
	for i, tmpl := range []string{filepath.Dir(item), item} {
		name := []string{"lib1", "lib2"}[i]
		if err := createCT(s, ctOperatorCtx(), name, tmpl); err != nil {
			t.Fatalf("operator library item %q: %v", tmpl, err)
		}
	}
	if len(rt.createCalls) != 2 {
		t.Fatalf("create calls = %d, want 2", len(rt.createCalls))
	}
}

func TestCreateContainer_OperatorLibraryLinkOutIsRefused(t *testing.T) {
	s, rt := ctPathServer(t)
	outside := mkCTRootfs(t, filepath.Join(t.TempDir(), "outside"))
	lib := filepath.Join(s.dataDir, "oci")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(lib, "evil")); err != nil {
		t.Fatal(err)
	}
	err := createCT(s, ctOperatorCtx(), "c1", filepath.Join(lib, "evil"))
	if code := status.Code(err); code != codes.PermissionDenied && code != codes.InvalidArgument {
		t.Fatalf("a library name linking out of the library: got %v, want a refusal", err)
	}
	// A deeper path inside a library item (an image's own rootfs content) is
	// not a library item either: the image chose its links.
	deep := mkCTRootfs(t, filepath.Join(lib, "img", "rootfs", "srv", "inner"))
	err = createCT(s, ctOperatorCtx(), "c2", deep)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a path inside a library item: got %v, want PermissionDenied", err)
	}
	if len(rt.createCalls) != 0 {
		t.Fatalf("runtime create calls: %+v", rt.createCalls)
	}
}

func TestCreateContainer_AdminHostPathOutsideDaemonStateWorks(t *testing.T) {
	s, rt := ctPathServer(t)
	rootfs := mkCTRootfs(t, filepath.Join(t.TempDir(), "rootfs"))
	if err := createCT(s, adminCtx(), "c1", rootfs); err != nil {
		t.Fatalf("admin rootfs outside daemon state: %v", err)
	}
	if len(rt.createCalls) != 1 || rt.createCalls[0].Template != rootfs {
		t.Fatalf("create calls = %+v", rt.createCalls)
	}
}

func TestCreateContainer_ProtectedPlacesRefusedForAdmin(t *testing.T) {
	s, rt := ctPathServer(t)
	state := mkCTRootfs(t, filepath.Join(s.dataDir, "vms"))
	for _, tmpl := range []string{"/etc", "/", state, s.dataDir, filepath.Dir(s.dataDir)} {
		err := createCT(s, adminCtx(), "c1", tmpl)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin template %q: got %v, want InvalidArgument", tmpl, err)
		}
	}
	if len(rt.createCalls) != 0 {
		t.Fatalf("runtime create calls: %+v", rt.createCalls)
	}
}

func TestCreateContainer_TemplateNamesStillWork(t *testing.T) {
	s, rt := ctPathServer(t)
	if _, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{
		Name: "d1", Template: "download", Distro: "alpine", Release: "3.21",
	}); err != nil {
		t.Fatalf("download template: %v", err)
	}
	if err := createCT(s, ctOperatorCtx(), "b1", "busybox"); err != nil {
		t.Fatalf("named template: %v", err)
	}
	if len(rt.createCalls) != 2 {
		t.Fatalf("create calls = %d, want 2", len(rt.createCalls))
	}
}

func TestPullOCIImage_AdminPathsAreJudged(t *testing.T) {
	s, rt := ctPathServer(t)
	for _, req := range []*pb.PullOCIImageRequest{
		{Image: "alpine:3.19", Dest: "/etc/cron.d/x"},
		{Image: "alpine:3.19", Dest: filepath.Join(s.dataDir, "vms", "x")},
		{Image: "oci:/etc/ssl:1", Dest: "img"},
	} {
		if _, err := s.PullOCIImage(adminCtx(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("pull %+v: got %v, want InvalidArgument", req, err)
		}
	}
	if len(rt.pullCalls) != 0 {
		t.Fatalf("runtime pulled: %+v", rt.pullCalls)
	}
	// The library itself, named absolutely, and an ordinary admin path still pull.
	for _, dest := range []string{filepath.Join(s.dataDir, "oci", "a"), filepath.Join(t.TempDir(), "b")} {
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "alpine:3.19", Dest: dest}); err != nil {
			t.Errorf("pull to %q: %v", dest, err)
		}
	}
}

// An Admin's template inside the LXC store works again (LXC's template cache,
// another container's rootfs), as on main; the container's own directory and
// the store itself are refused, and a non-admin still names no host path.
func TestCreateContainer_AdminTemplateInTheLXCStore(t *testing.T) {
	s, rt := ctPathServer(t)
	store := t.TempDir()
	s.SetContainerLxcpath(store)
	restore := storage.SetSecretRootsForTest([]string{"/etc", store})
	defer restore()
	base := mkCTRootfs(t, filepath.Join(store, "base", "rootfs"))
	if err := createCT(s, adminCtx(), "c1", base); err != nil {
		t.Fatalf("admin template in the LXC store: %v", err)
	}
	if err := createCT(s, ctOperatorCtx(), "c2", base); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator naming the LXC store: %v", err)
	}
	mkCTRootfs(t, filepath.Join(store, "c3", "rootfs"))
	for _, tmpl := range []string{store, filepath.Join(store, "c3", "rootfs")} {
		if err := createCT(s, adminCtx(), "c3", tmpl); status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin template %q: %v, want InvalidArgument", tmpl, err)
		}
	}
	if len(rt.createCalls) != 1 {
		t.Fatalf("create calls: %+v", rt.createCalls)
	}
}
