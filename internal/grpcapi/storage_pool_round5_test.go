package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// contentViewMDKey is the metadata a daemon's own content call carries
// (poolContentViewMDKey); spelled out so this test also compiles on a tree
// that predates it.
const contentViewMDKey = "x-litevirt-pool-content-view"

// bareEntryPeer is how a call forwarded from another node reaches the pool's
// host: a trusted peer, admin by default, with no user identity of its own.
func bareEntryPeer(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := peerCtxFor(t, s, "host-entry")
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	return context.WithValue(ctx, ctxKeyRealm, "local")
}

// forwardedAs is a call forwarded on behalf of user: the entry node relays the
// user's bearer (pki.FwdBearerMDKey), whether or not forwarded identity is
// enforced cluster-wide.
func forwardedAs(t *testing.T, s *Server, peer context.Context, user string) context.Context {
	t.Helper()
	token, _, _, err := s.mintSession(context.Background(), user, "local", "10.0.0.9", "test")
	if err != nil {
		t.Fatalf("mintSession(%s): %v", user, err)
	}
	return withFwdBearer(peer, "Bearer "+token)
}

func withContentView(ctx context.Context, v string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	} else {
		md = md.Copy()
	}
	md.Set(contentViewMDKey, v)
	return metadata.NewIncomingContext(ctx, md)
}

// twoProjectsOnDisks is an older cluster's host: acme's pool pa and bravo's
// pool pb are both <data_dir>/disks, holding both projects' files.
func twoProjectsOnDisks(t *testing.T) (*Server, string) {
	t.Helper()
	s := newPoolTestServer(t)
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "pa", Driver: "local", Target: disks, Project: "acme"})
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "pb", Driver: "local", Target: disks, Project: "bravo"})
	in := func(n string) string { return filepath.Join(disks, n) }
	insertProjectVM(t, s, "avm", "acme", "root", in("avm-root.qcow2"), "pa")
	insertProjectVM(t, s, "bvm", "bravo", "root", in("bvm-root.qcow2"), "pb")
	for _, n := range []string{"avm-root.qcow2", "bvm-root.qcow2", "debian.iso", "stray.qcow2"} {
		writePoolFile(t, in(n), n)
	}
	return s, disks
}

// C1 + I4: a content call that entered on another node is confined as the
// user who made it, on the pool's host: acme's operator via another node
// lists, uploads and deletes only acme's files (and sees library ISOs).
func TestPoolRound5_ForwardedCallIsConfinedAsTheOriginalCaller(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	_ = pat
	peer := bareEntryPeer(t, s)
	viaX := forwardedAs(t, s, peer, "pat")

	if err := uploadAs(bob, s, "pb", "bravo.iso", "bravo"); err != nil {
		t.Fatal(err)
	}
	if err := uploadAs(viaX, s, "pa", "acme.iso", "acme"); err != nil {
		t.Fatalf("acme uploads through another node: %v", err)
	}
	if got := listNames(t, s, viaX, "pa"); !slices.Equal(got, []string{"acme.iso", "avm-root.qcow2", "debian.iso"}) {
		t.Fatalf("acme's listing through another node = %v, want [acme.iso avm-root.qcow2 debian.iso]", got)
	}
	for _, n := range []string{"bravo.iso", "bvm-root.qcow2", "stray.qcow2"} {
		if _, err := s.DeleteStoragePoolContent(viaX, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: n}); status.Code(err) != codes.NotFound {
			t.Errorf("acme deleting %s through another node: got %v, want NotFound", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(disks, "bvm-root.qcow2")); err != nil {
		t.Errorf("bravo's disk was deleted: %v", err)
	}
	if got := listNames(t, s, bob, "pb"); !slices.Contains(got, "bravo.iso") {
		t.Errorf("bravo's own upload is gone from its listing: %v", got)
	}
	// The uploader owns what it uploaded through another node.
	if _, err := s.DeleteStoragePoolContent(viaX, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: "acme.iso"}); err != nil {
		t.Errorf("acme deleting its own upload through another node: %v", err)
	}
}

// C1, restored by I-A: a peer call with no user identity is the daemon
// itself or a node that predates the content marker — never a user, whose
// bearer is always relayed — so it sees and changes every file, as on main.
// The marker means nothing from a user.
func TestPoolRound5_PeerWithoutIdentityIsTheDaemon(t *testing.T) {
	s, _ := twoProjectsOnDisks(t)
	peer := bareEntryPeer(t, s)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if err := uploadAs(pat, s, "pa", "acme-own.img", "acme"); err != nil {
		t.Fatal(err)
	}
	// (A live disk of another pool is never listed as this pool's content.)
	all := []string{"acme-own.img", "avm-root.qcow2", "debian.iso", "stray.qcow2"}
	for _, ctx := range []context.Context{peer, withContentView(peer, "all")} {
		if got := listNames(t, s, ctx, "pa"); !slices.Equal(got, all) {
			t.Errorf("the daemon's own listing = %v, want every file of the pool %v", got, all)
		}
	}
	// Its upload is nobody's: an ISO it puts there is library content no
	// project may delete.
	if err := uploadAs(peer, s, "pa", "peer.iso", "x"); err != nil {
		t.Fatalf("a bare peer's upload: %v", err)
	}
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: "peer.iso"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("acme deleting an unrecorded ISO: got %v, want PermissionDenied", err)
	}
	op := withContentView(pat, "all")
	if got := listNames(t, s, op, "pa"); slices.Contains(got, "stray.qcow2") {
		t.Errorf("a user carrying the daemon's marker sees an unowned disk image: %v", got)
	}
	if got := listNames(t, s, withContentView(pat, "replicas"), "pa"); slices.Contains(got, "stray.qcow2") {
		t.Errorf("a user carrying the replica marker sees an unowned disk image: %v", got)
	}
}

// I1: replica ownership is by exact record only, never by file-name prefix.
// With no replica records on this branch, a file named like a replica is
// unowned — a disk image, so an admin's. Even one named after the caller's own
// VM, and even with the caller's replication schedule pointing here.
func TestPoolRound5_ReplicaNamesAreNotOwnership(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	insertReplicationSchedule(t, s, "avm", "pa")
	// bravo's VM web-prod's replica, and acme's VM web with disk prod-root.
	insertProjectVM(t, s, "web", "acme", "prod-root", filepath.Join(disks, "web-prod-root.qcow2"), "pa")
	insertReplicationSchedule(t, s, "web", "pa")
	for _, n := range []string{"avm-root-20261006T000000Z.qcow2", "web-prod-root-20261006T000000Z.qcow2"} {
		writePoolFile(t, filepath.Join(disks, n), n)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	got := listNames(t, s, pat, "pa")
	for _, n := range []string{"avm-root-20261006T000000Z.qcow2", "web-prod-root-20261006T000000Z.qcow2"} {
		if slices.Contains(got, n) {
			t.Errorf("acme's listing includes %s by its name: %v", n, got)
		}
		if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Filename: n}); err == nil {
			t.Errorf("acme deleted %s by its name", n)
		}
	}
}

// I3: an upload never shares the VM-disk namespace. In a pool on
// <data_dir>/disks it lands in disks/uploads/, so creating, deleting or
// rebuilding a VM named like its prefix never sweeps it, and a VM's disk can
// always be placed (or migrated in) at its own name.
func TestPoolRound5_UploadsIntoDisksStayOutOfTheDiskNamespace(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	bob := hostPathEngineCtx(t, s, "bob", "Operator", projectRBACBase("bravo"))
	for _, n := range []string{"ubuntu-noble.qcow2", "avm-data.qcow2"} {
		if err := uploadAs(bob, s, "pb", n, "bravo's"); err != nil {
			t.Fatalf("upload %s: %v", n, err)
		}
		if _, err := os.Stat(filepath.Join(disks, n)); err == nil {
			t.Errorf("%s landed among the VM disks", n)
		}
		if _, err := os.Stat(filepath.Join(disks, "uploads", n)); err != nil {
			t.Errorf("%s not in disks/uploads: %v", n, err)
		}
	}
	// An older upload already at the root of disks/ is recorded and kept.
	old := filepath.Join(disks, "ubuntu-old.qcow2")
	writePoolFile(t, old, "bravo's older upload")
	if err := s.recordPoolUpload(context.Background(), "pb", "bravo", "bob@local", old); err != nil {
		t.Fatal(err)
	}
	s.sweepVMDiskDebris(adminCtx(), "ubuntu")
	for _, p := range []string{filepath.Join(disks, "uploads", "ubuntu-noble.qcow2"), old} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("creating VM ubuntu swept bravo's upload %s: %v", filepath.Base(p), err)
		}
	}
	if got := listNames(t, s, bob, "pb"); !slices.Contains(got, "ubuntu-noble.qcow2") || !slices.Contains(got, "ubuntu-old.qcow2") {
		t.Errorf("bravo's listing = %v, want its uploads", got)
	}
	if _, err := s.DeleteStoragePoolContent(bob, &pb.DeleteStoragePoolContentRequest{PoolName: "pb", Filename: "ubuntu-noble.qcow2"}); err != nil {
		t.Errorf("bravo deleting its upload: %v", err)
	}
}

// M1: an upload record describes one file: rewritten (or replaced by a file
// that reuses its inode), it is no longer the upload.
func TestPoolRound5_RewrittenUploadIsNotTheUpload(t *testing.T) {
	s, disks := twoProjectsOnDisks(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if err := uploadAs(pat, s, "pa", "mine.img", "acme"); err != nil {
		t.Fatal(err)
	}
	got := listNames(t, s, pat, "pa")
	if !slices.Contains(got, "mine.img") {
		t.Fatalf("acme's own upload is not listed: %v", got)
	}
	var path string
	for _, p := range []string{filepath.Join(disks, "uploads", "mine.img"), filepath.Join(disks, "mine.img")} {
		if _, err := os.Stat(p); err == nil {
			path = p
		}
	}
	if err := os.WriteFile(path, []byte("someone else's, same inode"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := listNames(t, s, pat, "pa"); slices.Contains(got, "mine.img") {
		t.Errorf("a rewritten file is still listed as acme's upload: %v", got)
	}
}

// I2: the same-pool exemption is for one nfs pool defined on several hosts —
// the same name, project AND export. Never across drivers, never for a nested
// export, and never against a host's <data_dir>/disks.
func TestPoolRound5_SamePoolExemptionIsNarrow(t *testing.T) {
	for name, tc := range map[string]struct {
		other corrosion.StoragePoolRecord
		src   string
	}{
		"an nfs pool over another host's dir pool of the same name": {
			corrosion.StoragePoolRecord{HostName: "host-b", Name: "p", Driver: "local", Target: "/var/lib/litevirt/disks", Project: "acme",
				Options: map[string]string{storage.NFSExportOption: "nas:/hosts/b/disks"}}, "nas:/hosts/b/disks"},
		"the same nfs pool name on a nested export": {
			corrosion.StoragePoolRecord{HostName: "host-b", Name: "p", Driver: "nfs", Source: "nas:/x", Project: "acme"}, "nas:/x/sub"},
		"another host's data_dir disks on NFS": {
			corrosion.StoragePoolRecord{HostName: "host-b", Name: "default", Driver: "local", Target: "/var/lib/litevirt/pools/default",
				Options: map[string]string{"data_disks_nfs_export": "nas:/hosts/b/disks"}}, "nas:/hosts/b"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newPoolTestServer(t)
			upsertPool(t, s, tc.other)
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
				Name: "p", Driver: "nfs", Source: tc.src, Target: t.TempDir(), Options: noPrepare, Project: "acme"})
			wantSharedRefusal(t, "create", err)
		})
	}
}

// I2: this host's own <data_dir>/disks on NFS is an export no nfs pool may
// mount, whether or not any pool row names it.
func TestPoolRound5_OwnDisksExportIsNotAPool(t *testing.T) {
	s := newPoolTestServer(t)
	overrideMounts(t, nfsMountLine(s.dataDir, "nas:/hosts/a"))
	// The pool that is <data_dir>/disks itself — an older cluster's default —
	// is that storage, and keeps working.
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "default", Driver: "local", Target: disks})
	if _, err := s.resolveVolume(adminCtx(), "", "default"); err != nil {
		t.Fatalf("the default pool on an NFS <data_dir>/disks: %v", err)
	}
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "q", Driver: "nfs", Source: "nas:/hosts/a/disks", Target: t.TempDir(), Options: noPrepare, Project: "acme"})
	wantSharedRefusal(t, "an nfs pool on this host's own disks/ export", err)
}
