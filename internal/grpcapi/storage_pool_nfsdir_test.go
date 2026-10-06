package grpcapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

func weakNFSMountLine(dir, source string) string {
	return fmt.Sprintf("40 1 0:60 / %s rw,nosuid,relatime - nfs4 %s rw,vers=4.2", dir, source)
}

// Item 2: a dir, local or btrfs pool on a hardened NFS mount (fstab, an NFS
// data_dir) works again — created, used, and its export recorded so other
// hosts compare against it.
func TestPoolNFSDir_HardenedMountWorks(t *testing.T) {
	s := newPoolTestServer(t)
	mnt := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mnt, "vms"), 0o755); err != nil {
		t.Fatal(err)
	}
	overrideMounts(t, nfsMountLine(mnt, "nas:/bravo"))
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "d", Driver: "dir", Target: filepath.Join(mnt, "vms"), Project: "acme"}); err != nil {
		t.Fatalf("a dir pool on a hardened NFS mount: %v", err)
	}
	rec, _, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "d")
	if got := rec.Options[storage.NFSExportOption]; got != "nas:/bravo/vms" {
		t.Errorf("recorded export = %q, want nas:/bravo/vms", got)
	}
	if _, err := s.resolveVolume(adminCtx(), "", "d"); err != nil {
		t.Fatalf("a disk on it: %v", err)
	}
}

// Item 2: the NFS data_dir case — the built-in local pools live on the mount.
func TestPoolNFSDir_LocalPoolOnAnNFSDataDir(t *testing.T) {
	s := newPoolTestServer(t)
	overrideMounts(t, nfsMountLine(s.dataDir, "nas:/hosts/a"))
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "scratch", Driver: "local"}); err != nil {
		t.Fatalf("a local pool with data_dir on a hardened NFS mount: %v", err)
	}
	if _, err := s.resolveVolume(adminCtx(), "", "scratch"); err != nil {
		t.Fatalf("use: %v", err)
	}
}

// Item 2, the attack still closed: an unhardened mount under the directory is
// refused at create and at use, saying which options are missing.
func TestPoolNFSDir_UnhardenedMountIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	mnt := t.TempDir()
	overrideMounts(t, weakNFSMountLine(mnt, "nas:/bravo"))
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "d", Driver: "dir", Target: mnt, Project: "acme"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "without nodev,noexec,nosymfollow") {
		t.Fatalf("create on an unhardened NFS mount: got %v, want FailedPrecondition naming the missing options", err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "d", Driver: "dir", Target: mnt, Project: "acme"})
	if _, err := s.resolveVolume(adminCtx(), "", "d"); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "nosymfollow") {
		t.Fatalf("use on an unhardened NFS mount: got %v, want FailedPrecondition naming the missing options", err)
	}
}

// Item 2: a directory pool on an NFS mount IS that export (plus the path
// below the mount), and collides with an nfs pool or another directory pool
// on the same export, on any host, exactly as two nfs pools would — the same
// pool (name and project) on several hosts excepted.
func TestPoolNFSDir_ExportIdentityCollides(t *testing.T) {
	for _, tc := range []struct {
		name   string
		other  corrosion.StoragePoolRecord
		shared bool
	}{
		{"an nfs pool on the export", corrosion.StoragePoolRecord{HostName: "host-b", Name: "n", Driver: "nfs", Source: "nas:/bravo", Project: "bravo"}, true},
		{"an nfs pool on the server's pseudo-root", corrosion.StoragePoolRecord{HostName: s0, Name: "n", Driver: "nfs", Source: "NAS:/", Target: "/srv/n", Project: "bravo"}, true},
		{"an nfs pool on the directory below", corrosion.StoragePoolRecord{HostName: "host-b", Name: "n", Driver: "nfs", Source: "nas:/bravo/vms/x", Project: "bravo"}, true},
		{"another host's dir pool on the export", corrosion.StoragePoolRecord{HostName: "host-b", Name: "o", Driver: "dir", Target: "/mnt/x", Project: "bravo",
			Options: map[string]string{storage.NFSExportOption: "nas:/bravo/vms"}}, true},
		{"the same pool on another host", corrosion.StoragePoolRecord{HostName: "host-b", Name: "d", Driver: "dir", Target: "/mnt/x", Project: "acme",
			Options: map[string]string{storage.NFSExportOption: "nas:/bravo/vms"}}, false},
		{"a sibling export", corrosion.StoragePoolRecord{HostName: "host-b", Name: "n", Driver: "nfs", Source: "nas:/bravo2", Project: "bravo"}, false},
		{"an nfs pool on a sibling directory of the same export", corrosion.StoragePoolRecord{HostName: "host-b", Name: "n", Driver: "nfs", Source: "nas:/bravo/other", Project: "bravo"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newPoolTestServer(t)
			mnt := t.TempDir()
			vms := filepath.Join(mnt, "vms")
			if err := os.MkdirAll(vms, 0o755); err != nil {
				t.Fatal(err)
			}
			overrideMounts(t, nfsMountLine(mnt, "nas:/bravo"))
			other := tc.other
			if other.HostName == s0 {
				other.HostName = s.hostName
			}
			upsertPool(t, s, other)
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "d", Driver: "dir", Target: vms, Project: "acme"})
			if tc.shared {
				wantSharedRefusal(t, "create", err)
			} else if err != nil {
				t.Fatalf("create: %v", err)
			}
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "d", Driver: "dir", Target: vms, Project: "acme"})
			_, err = s.resolveVolume(adminCtx(), "", "d")
			if tc.shared != (status.Code(err) == codes.FailedPrecondition) {
				t.Fatalf("use: got %v, shared=%v", err, tc.shared)
			}
		})
	}
}

// s0 stands for "this test server's host" in a table built before the server.
const s0 = "\x00this-host"

// Item 2, the other direction: an nfs pool on an export another host's
// directory pool is recorded on is refused, as two nfs pools would be.
func TestPoolNFSDir_NFSPoolCollidesWithARecordedDirPool(t *testing.T) {
	s := newPoolTestServer(t)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: "host-b", Name: "o", Driver: "dir", Target: "/mnt/x", Project: "bravo",
		Options: map[string]string{storage.NFSExportOption: "nas:/bravo/vms"}})
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "n", Driver: "nfs", Source: "nas:/bravo", Target: t.TempDir(), Options: noPrepare, Project: "acme"})
	wantSharedRefusal(t, "an nfs pool containing another host's NFS-backed dir pool", err)
}

// The recorded export is the daemon's: a request may not set it, or a pool
// could claim to be on some other export to dodge or provoke the comparison.
func TestPoolNFSDir_RequestCannotSetTheRecordedExport(t *testing.T) {
	s := newPoolTestServer(t)
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "d", Driver: "dir", Target: t.TempDir(), Options: map[string]string{storage.NFSExportOption: "elsewhere:/x"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
}

// Directory pools may share a local directory; an nfs pool's mount point may
// not be laid over, under or onto another pool's directory: the mount would
// hide one pool's files or put the export where the other writes.
func TestPoolNFSDir_NFSMountPointOverADirPoolIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "d", Driver: "dir", Target: dir, Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "n", Driver: "nfs", Source: "nas:/x", Target: dir, Options: noPrepare, Project: "acme"})
	wantSharedRefusal(t, "an nfs pool mounted on a dir pool's directory", err)
}
