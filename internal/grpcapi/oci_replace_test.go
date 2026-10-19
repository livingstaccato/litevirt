package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/storage"
)

// mkBundle lays down an unpacked OCI bundle (config.json + rootfs) at
// <dataDir>/oci/<name> with generation gen, as a pull leaves it.
func mkBundle(t *testing.T, s *Server, name, gen string) string {
	t.Helper()
	dir := filepath.Join(s.dataDir, "oci", name)
	mkCTRootfs(t, filepath.Join(dir, "rootfs"))
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if gen != "" {
		if err := os.WriteFile(filepath.Join(dir, lxc.ImageGenFile), []byte(gen+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A pull over an existing item replaces what every container built from it
// is recreated from, in every project it serves: only an Admin's claim
// (--project) does it; any other pull over it is refused, as umoci refused it.
func TestPullOCI_OverAnExistingItemIsAnAdminClaimOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		project string
		want    codes.Code
	}{
		{"operator", ctOperatorCtx(), "", codes.FailedPrecondition},
		{"operator --project", ctOperatorCtx(), "acme", codes.PermissionDenied}, // claiming an ownerless item
		{"admin without --project", adminCtx(), "", codes.FailedPrecondition},
		{"admin claim", adminCtx(), "acme", codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rt := ctPathServer(t)
			mkBundle(t, s, "base", "g1")
			_, err := s.PullOCIImage(tc.ctx, &pb.PullOCIImageRequest{Image: "ghcr.io/x/y:2", Dest: "base", Project: tc.project})
			if status.Code(err) != tc.want {
				t.Fatalf("pull over an existing item: %v, want %v", err, tc.want)
			}
			if tc.want == codes.OK {
				if len(rt.pullReplace) != 1 || !rt.pullReplace[0] {
					t.Fatalf("the Admin's claim did not ask the runtime to replace: %v", rt.pullReplace)
				}
			} else if len(rt.pullCalls) != 0 {
				t.Fatalf("a refused pull reached the runtime: %+v", rt.pullCalls)
			}
		})
	}
	// A pull into a new name replaces nothing.
	s, rt := ctPathServer(t)
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/y:2", Dest: "fresh"}); err != nil {
		t.Fatal(err)
	}
	if len(rt.pullReplace) != 1 || rt.pullReplace[0] {
		t.Fatalf("a pull into a new name asked to replace: %v", rt.pullReplace)
	}
}

// An Admin's claim is refused while a container uses the item's rootfs in
// place (one an earlier release created from it): replacing it would remove
// that container's files.
func TestPullOCI_AnItemAContainerUsesInPlaceIsNotReplaced(t *testing.T) {
	s, rt := ctPathServer(t)
	dir := mkBundle(t, s, "base", "g1")
	rt.rootfsRefs = map[string][]string{dir: {"legacy-web"}}
	_, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/y:2", Dest: "base", Project: "acme"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "legacy-web") {
		t.Fatalf("claim of an item a container uses in place: %v, want FailedPrecondition naming legacy-web", err)
	}
	if len(rt.pullCalls) != 0 {
		t.Fatalf("the pull reached the runtime: %+v", rt.pullCalls)
	}
}

// A forwarded pull replaces only when the entry host marked it an Admin's
// claim; an entry that predates the marker gets the refusal.
func TestPullOCI_AForwardedReplaceNeedsTheEntrysClaim(t *testing.T) {
	s, rt := ctPathServer(t)
	mkBundle(t, s, "base", "g1")
	peer := context.WithValue(context.WithValue(peerCtxFor(t, s, "host-b"), ctxKeyUsername, "host-b"), ctxKeyRole, "admin")
	req := func() *pb.PullOCIImageRequest {
		return &pb.PullOCIImageRequest{Image: "ghcr.io/x/y:2", Dest: "base", Project: "acme"}
	}
	for _, unmarked := range []context.Context{peer, metadata.NewIncomingContext(peer, metadata.Pairs(ociReplaceMDKey, "0", "x-other", "1"))} {
		if _, err := s.PullOCIImage(unmarked, req()); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("an unmarked forward: %v, want FailedPrecondition", err)
		}
	}
	marked := metadata.NewIncomingContext(peer, metadata.Pairs(ociReplaceMDKey, "1"))
	if _, err := s.PullOCIImage(marked, req()); err != nil {
		t.Fatalf("a forward marked as an Admin's claim: %v", err)
	}
	if len(rt.pullReplace) != 1 || !rt.pullReplace[0] {
		t.Fatalf("pull replace = %v, want one replacing pull", rt.pullReplace)
	}
}

// A recreate of a privileged member from the same item path, after an
// Admin's pull replaced the item's content, runs a new image as root: a
// deployer without ContainerRoot is refused before the delete; an Admin is not.
func TestComposeRecreate_ReplacedItemContentIsAnImageChange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		curGen  string
		admin   bool
		wantErr codes.Code
	}{
		{"unchanged item", "g1", false, codes.OK},
		{"replaced item, deployer", "g2", false, codes.PermissionDenied},
		{"replaced item, admin", "g2", true, codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rt := secServer(t)
			carl := carlCtx(t, s)
			item := mkBundle(t, s, "build", tc.curGen)
			tmpl := filepath.Join(item, "rootfs")
			seedSecCT(t, s, rt, "web", "running", corrosion.ContainerCreateSpec{})
			if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
				HostName: "host-a", Name: "web", State: "running", Project: "acme", Image: tmpl,
				Labels:     map[string]string{corrosion.LabelStack: "st"},
				CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tmpl, TemplateGen: "g1", Arch: "amd64"}),
			}); err != nil {
				t.Fatal(err)
			}
			f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindOCI, Image: tmpl, CPU: 4}}}
			upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
			ctx := carl
			if tc.admin {
				ctx = adminCtx()
			}
			err := recreateMember(ctx, s, upd, f)
			if status.Code(err) != tc.wantErr {
				t.Fatalf("recreate: %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != codes.OK {
				if !strings.Contains(err.Error(), "ContainerRoot") || !strings.Contains(err.Error(), "replaced") {
					t.Errorf("the refusal does not say why: %v", err)
				}
				memberExists(t, s, rt)
			}
		})
	}
}

// On the owner, a forwarded exec the entry host judged the caller may not
// run as root is refused for a container the owner's own row shows
// privileged or legacy (an entry whose replica lags may not know); an entry
// that predates the judgment is trusted as before.
func TestExecContainer_TheOwnerRechecksAForwardedExec(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.containerRuntime = rt
	seedExecCT(t, s, "priv", privDefault)
	seedExecCT(t, s, "plain", unprivDefault)
	peer := context.WithValue(context.WithValue(peerCtxFor(t, s, "host-b"), ctxKeyUsername, "host-b"), ctxKeyRole, "admin")
	with := func(v string) context.Context {
		return metadata.NewIncomingContext(peer, metadata.Pairs(execRootMDKey, v))
	}
	if _, err := s.ExecContainer(with("0"), &pb.ExecContainerRequest{Name: "priv", HostName: s.hostName, Argv: []string{"id"}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a forward judged not-root into a privileged container: %v, want PermissionDenied", err)
	}
	for _, c := range []struct {
		ctx  context.Context
		name string
	}{{with("1"), "priv"}, {with("0"), "plain"}, {peer, "priv"}} {
		if _, err := s.ExecContainer(c.ctx, &pb.ExecContainerRequest{Name: c.name, HostName: s.hostName, Argv: []string{"id"}}); err != nil {
			t.Errorf("forwarded exec into %s: %v", c.name, err)
		}
	}
}

// The pre-delete recreate probe is a read: it rides InspectContainer, which
// on any build only reads, never DeleteContainer, which on v1.0.3–v1.0.25
// would hand "." to lxc-destroy.
func TestRecreateProbe_RidesInspectNeverDelete(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{fetchErr: errFetchForTest}
	s.containerRuntime = rt
	seedExecCT(t, s, "web", unprivDefault)
	peer := context.WithValue(context.WithValue(peerCtxFor(t, s, "host-b"), ctxKeyUsername, "host-b"), ctxKeyRole, "admin")
	probe := metadata.NewIncomingContext(peer, metadata.Pairs(
		recreateProbeMDKey, "web", recreateTemplateMDKey, "download", recreateProjectMDKey, "acme",
		recreateDistroMDKey, "alpine", recreateReleaseMDKey, "3.99", recreateArchMDKey, "amd64"))
	if _, err := s.InspectContainer(probe, &pb.InspectContainerRequest{Name: "web", HostName: s.hostName}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "left as it is") {
		t.Fatalf("the probe on InspectContainer: %v, want the fetch refusal", err)
	}
	if len(rt.fetchCalls) != 1 {
		t.Fatalf("fetch calls %d, want 1", len(rt.fetchCalls))
	}
	if _, err := s.DeleteContainer(probe, &pb.DeleteContainerRequest{Name: ".", HostName: s.hostName}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a probe on DeleteContainer: %v, want the name refused", err)
	}
	if len(rt.fetchCalls) != 1 || len(rt.deleteCalls) != 0 {
		t.Fatalf("DeleteContainer acted on a probe: fetch %d delete %v", len(rt.fetchCalls), rt.deleteCalls)
	}
	// Without the probe key Inspect is the plain read it always was.
	if _, err := s.InspectContainer(peer, &pb.InspectContainerRequest{Name: "web", HostName: s.hostName}); err != nil {
		t.Fatalf("a plain inspect from a peer: %v", err)
	}
}

var errFetchForTest = status.Error(codes.Unavailable, "no image alpine 3.99")

// An Admin's absolute --dest in the library must be an item name like any
// other: "+" (the staging directory's own name among them) is refused.
func TestPullOCI_AnAbsoluteLibraryDestIsAnItemName(t *testing.T) {
	s, rt := ctPathServer(t)
	for _, name := range []string{"foo+x", ".litevirt+unpack"} {
		dest := filepath.Join(s.dataDir, "oci", name)
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/y:2", Dest: dest}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("an absolute --dest %s: %v, want InvalidArgument", dest, err)
		}
	}
	if len(rt.pullCalls) != 0 {
		t.Fatalf("a refused pull reached the runtime: %+v", rt.pullCalls)
	}
}

// A local "oci:<dir>" source is the Admin's, from a directory the host
// may read: an Operator is refused, and an Admin's reaches the runtime as
// spelled.
func TestPullOCI_ALocalOCISourceIsTheAdmins(t *testing.T) {
	s, rt := ctPathServer(t)
	layout := filepath.Join(t.TempDir(), "layout")
	if err := os.MkdirAll(layout, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "oci:" + layout + ":v2"
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: src, Dest: "img"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an Operator's local oci: source: %v, want PermissionDenied", err)
	}
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: src, Dest: "img"}); err != nil {
		t.Fatalf("an Admin's local oci: source: %v", err)
	}
	if len(rt.pullCalls) != 1 || rt.pullCalls[0].Image != src {
		t.Fatalf("pull calls %+v, want one with the source as spelled", rt.pullCalls)
	}
}

// Every local transport reads a host path as root: it is the Admin's, and
// the path is judged (a directory for oci: and dir:, a regular file for the
// archives). A registry source stays open to the roles it was. Any other
// transport is refused for everyone.
func TestPullOCI_LocalTransportsAreTheAdminsAndJudged(t *testing.T) {
	s, rt := ctPathServer(t)
	dir := filepath.Join(t.TempDir(), "img")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "img.tar")
	if err := os.WriteFile(archive, []byte("tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := []string{
		"oci:" + dir + ":v1",
		"oci:" + dir + ":odd:tag", // the path ends at the first colon, as skopeo reads it
		"dir:" + dir,
		"dir://" + dir,
		"oci-archive:" + archive,
		"oci-archive://" + archive + ":v1",
		"docker-archive:" + archive,
		"docker-archive://" + archive,
	}
	for _, src := range local {
		if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: src, Dest: "img"}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("an Operator's %s: %v, want PermissionDenied", src, err)
		}
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: src, Dest: "img-" + strconv.Itoa(len(rt.pullCalls))}); err != nil {
			t.Errorf("an Admin's %s: %v", src, err)
		}
	}
	for _, src := range []string{
		"dir:///etc/ssl",              // a protected tree
		"oci-archive:///etc/shadow",   // a protected file
		"docker-archive:///dev/zero",  // not a regular file
		"oci:/nonexistent/layout:v1",  // missing
		"oci-archive://" + dir,        // a directory is not an archive
		"docker-daemon:alpine:latest", // not an allowed transport
		"containers-storage:alpine",
		"-alpine",
	} {
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: src, Dest: "bad"}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("an Admin's %s: %v, want InvalidArgument", src, err)
		}
	}
	// A registry source is still the Operator's.
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "docker://ghcr.io/acme/x:1", Dest: "reg"}); err != nil {
		t.Errorf("an Operator's registry pull: %v", err)
	}
	if n := len(rt.pullCalls); n != len(local)+1 {
		t.Fatalf("runtime pulls %d, want %d (each Admin local source and the registry pull)", n, len(local)+1)
	}
}

// The rules for a local pull source are one rule per kind, the same wherever
// the path is: a directory for oci: and dir:, a regular file for the
// archives, and never a protected place. An archive under a home directory
// is accepted as a directory there is (it is no ISO image rule). The host
// that reads the source judges the object it opens: the runtime is handed
// the same check.
func TestPullOCI_TheSourceRulesAreOnePerKind(t *testing.T) {
	s, rt := ctPathServer(t)
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		t.Skip("no home directory")
	}
	under, err := os.MkdirTemp(home, "lv-pull-test-")
	if err != nil {
		t.Skipf("home not writable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(under) })
	archive := filepath.Join(under, "img.tar")
	if err := os.WriteFile(archive, []byte("tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"oci-archive:" + archive, "docker-archive:" + archive, "dir:" + under} {
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: src, Dest: "h" + strconv.Itoa(len(rt.pullCalls))}); err != nil {
			t.Errorf("an Admin's %s under a home directory: %v", src, err)
		}
	}
	if rt.pullCheck == nil {
		t.Fatal("the runtime was not handed the source check")
	}
	if err := rt.pullCheck("docker-archive", "/etc/shadow"); err == nil {
		t.Error("the check handed to the runtime accepts /etc/shadow")
	}
	if err := rt.pullCheck("docker-archive", archive); err != nil {
		t.Errorf("the check handed to the runtime refuses the archive it accepted: %v", err)
	}
	if err := rt.pullCheck("dir", archive); err == nil {
		t.Error("the check accepts a file as a dir: source")
	}
}

// VM disk storage is not an archive source: a file directly in
// <data_dir>/disks, or inside a storage pool on this host.
func TestPullOCI_VMDiskStorageIsNoArchiveSource(t *testing.T) {
	s, rt := ctPathServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	inDisks := filepath.Join(disks, "web-root.qcow2")
	pool := filepath.Join(t.TempDir(), "pool1")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	inPool := filepath.Join(pool, "db-data.raw")
	for _, f := range []string{inDisks, inPool} {
		if err := os.WriteFile(f, []byte("disk"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "pool1", Driver: "dir", Target: pool}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{inDisks, inPool} {
		for _, tr := range []string{"oci-archive", "docker-archive"} {
			if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: tr + ":" + f, Dest: "d"}); status.Code(err) != codes.InvalidArgument {
				t.Errorf("%s:%s: %v, want InvalidArgument", tr, f, err)
			}
		}
	}
	if len(rt.pullCalls) != 0 {
		t.Fatalf("a refused source reached the runtime: %+v", rt.pullCalls)
	}
}

// Any VM's disk is no archive source, wherever it lives: on a target-less
// NFS pool (mounted at <data_dir>/mounts/<name>), or outside every pool.
func TestPullOCI_AnyVMDiskIsNoArchiveSource(t *testing.T) {
	s, rt := ctPathServer(t)
	ctx := context.Background()
	src := "srv:/export"
	mnt := filepath.Join(s.dataDir, "mounts", storage.NFSMountName(src))
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	onNFS := filepath.Join(mnt, "vm1-root.raw")
	loose := filepath.Join(t.TempDir(), "vm2-data.raw")
	for _, f := range []string{onNFS, loose} {
		if err := os.WriteFile(f, []byte("disk"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nfs1", Driver: "nfs", Source: src}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{VMName: "vm2", DiskName: "data", HostName: "other-host", Path: loose}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{onNFS, loose} {
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "docker-archive:" + f, Dest: "d"}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("a VM disk %s as an archive: %v, want InvalidArgument", f, err)
		}
	}
	if len(rt.pullCalls) != 0 {
		t.Fatalf("a VM disk reached the runtime: %+v", rt.pullCalls)
	}
}

// The runtime's refusals of a source answer as refusals, like the same
// refusal made by the handler: a refused source is InvalidArgument, too
// little space is ResourceExhausted; anything else stays Internal.
func TestPullOCI_RuntimeRefusalsKeepTheirCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{fmt.Errorf("%w: x is not a regular file", lxc.ErrSourceRefused), codes.InvalidArgument},
		{fmt.Errorf("%w: needs 9 bytes", lxc.ErrStagingSpace), codes.ResourceExhausted},
		{status.Error(codes.InvalidArgument, "docker-archive source: refused by the check"), codes.InvalidArgument},
		{errors.New("umoci unpack: exit status 1"), codes.Internal},
	} {
		s, rt := ctPathServer(t)
		rt.pullErr = tc.err
		_, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/y:1", Dest: "img"})
		if status.Code(err) != tc.want {
			t.Errorf("runtime error %v: %v, want %v", tc.err, err, tc.want)
		}
	}
}

// A container recreate whose delete fails says the member was not
// recreated, how to tell whether it is still there, and how to retry.
func TestComposeRecreate_AFailedDeleteSaysTheMemberWasKept(t *testing.T) {
	s, rt := secServer(t)
	seedMember(t, s, rt, "3.22")
	rt.deleteErr = errors.New("transport is closing")
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	err := recreateMember(adminCtx(), s, upd, f)
	if err == nil {
		t.Fatal("a failed delete reported success")
	}
	for _, want := range []string{"not recreated", "lv ct inspect web", "lv compose up"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
}
