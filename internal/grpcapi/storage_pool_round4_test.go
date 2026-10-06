package grpcapi

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// sharedRefusal is the create-time refusal for storage another pool has. A
// Prepare failure is also FailedPrecondition, so a test asserts the text.
const sharedRefusal = "is already another pool's"

func wantSharedRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), sharedRefusal) {
		t.Fatalf("%s: got %v, want FailedPrecondition %q", what, err, sharedRefusal)
	}
}

// notSharedRefusal: the create got past the shared-storage check. In tests it
// then fails at Prepare (no real mount), which is fine.
func notSharedRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), sharedRefusal) || !strings.Contains(err.Error(), "prepare")) {
		t.Fatalf("%s: got %v, want the create to reach Prepare", what, err)
	}
}

// noPrepare makes an NFS pool's Prepare fail at once, before any mountpoint or
// mount command (and so before any name lookup a real mount.nfs would do).
var noPrepare = map[string]string{"command_timeout": "never"}

func upsertPool(t *testing.T, s *Server, r corrosion.StoragePoolRecord) {
	t.Helper()
	r.State = "active"
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, r); err != nil {
		t.Fatal(err)
	}
}

func overrideMounts(t *testing.T, lines ...string) {
	t.Helper()
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	}))
}

func nfsMountLine(dir, source string) string {
	return fmt.Sprintf("40 1 0:60 / %s rw,nosuid,nodev,noexec,nosymfollow,relatime - nfs4 %s rw,vers=4.2", dir, source)
}

// IMP-2: a hardened mount at an NFS pool's mount point is that pool's only if
// it is the pool's export. Another export left there (a deleted pool's, or one
// mounted by hand) is refused for everything.
func TestPoolRound4_MountOfAnotherExportIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "acme-nfs", Driver: "nfs", Source: "nas:/acme", Target: dir, Project: "acme"})

	overrideMounts(t, nfsMountLine(dir, "nas:/bravo"))
	if _, err := s.resolveVolume(adminCtx(), "", "acme-nfs"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a disk on another export mounted at the pool's target: got %v, want FailedPrecondition", err)
	}
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "acme-nfs"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("listing another export mounted at the pool's target: got %v, want FailedPrecondition", err)
	}

	overrideMounts(t, nfsMountLine(dir, "NAS:/acme/"))
	if _, err := s.resolveVolume(adminCtx(), "", "acme-nfs"); err != nil {
		t.Fatalf("the pool's own export, mounted hardened: %v", err)
	}
}

// IMP-2: a dir or local pool on an NFS mount point is on an export no NFS
// pool of it owns, mounted with nothing litevirt checks: refused at create and
// at use.
func TestPoolRound4_DirPoolOnAnNFSMountIsRefused(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	overrideMounts(t, nfsMountLine(dir, "nas:/bravo"))
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "d", Driver: "dir", Target: dir, Project: "acme"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "NFS") {
		t.Fatalf("a dir pool on an NFS mount point: got %v, want FailedPrecondition naming NFS", err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "d", Driver: "dir", Target: dir, Project: "acme"})
	if _, err := s.resolveVolume(adminCtx(), "", "d"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a disk on a dir pool over an NFS mount: got %v, want FailedPrecondition", err)
	}
}

// IMP-3: an NFS export is cluster-wide storage. The same export on another
// host is the same storage, allowed only for the same pool (name and
// project) defined on several hosts.
func TestPoolRound4_OneExportAcrossHosts(t *testing.T) {
	for _, tc := range []struct {
		name, otherName, otherProject string
		shared                        bool
	}{
		{"another project's pool", "acme-nfs", "acme", true},
		{"another pool of the same project", "acme-nfs", "bravo", true},
		{"the same name in another project", "bravo-nfs", "acme", true},
		{"the same name, global", "bravo-nfs", "", true},
		{"the same pool on another host", "bravo-nfs", "bravo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newPoolTestServer(t)
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: "host-b", Name: tc.otherName, Driver: "nfs", Source: "nas:/vol", Project: tc.otherProject})
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
				Name: "bravo-nfs", Driver: "nfs", Source: "nas:/vol", Target: t.TempDir(), Options: noPrepare, Project: "bravo"})
			if tc.shared {
				wantSharedRefusal(t, "bravo-nfs on host-b's export", err)
			} else {
				notSharedRefusal(t, "the same pool on a second host", err)
			}
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "bravo-nfs", Driver: "nfs", Source: "nas:/vol", Target: t.TempDir(), Project: "bravo"})
			_, err = s.resolveVolume(adminCtx(), "", "bravo-nfs")
			if tc.shared && status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("use of an export another host's pool has: got %v, want FailedPrecondition", err)
			}
			if !tc.shared && err != nil {
				t.Fatalf("use of the same pool on a second host: %v", err)
			}
		})
	}
}

// IMP-1: one export written two ways, and two exports one inside the other,
// are the same storage — at create and at use. No DNS is needed for these.
func TestPoolRound4_ExportSpellingsAndNesting(t *testing.T) {
	for name, pair := range map[string][2]string{
		"nested export":            {"nas:/tenants", "nas:/tenants/acme"},
		"containing export":        {"nas:/tenants/acme", "nas:/tenants"},
		"NFSv4 pseudo-root":        {"nas:/", "nas:/srv/nfs"},
		"server case":              {"NAS:/x", "nas:/x"},
		"IPv6 case":                {"[FE80::A]:/x", "[fe80::a]:/x"},
		"IPv6 zero compression":    {"[fe80::1]:/x", "[fe80:0::1]:/x"},
		"IPv6 nested export":       {"[2001:db8::5]:/a", "[2001:DB8:0:0::5]:/a/b"},
		"IPv4-mapped IPv6 address": {"10.0.0.5:/x", "[::ffff:10.0.0.5]:/x"},
		"trailing slash":           {"nas:/x", "nas:/x/"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newPoolTestServer(t)
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "first", Driver: "nfs", Source: pair[0], Target: t.TempDir(), Project: "acme"})
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
				Name: "second", Driver: "nfs", Source: pair[1], Target: t.TempDir(), Options: noPrepare, Project: "bravo"})
			wantSharedRefusal(t, pair[1]+" beside "+pair[0], err)
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "second", Driver: "nfs", Source: pair[1], Target: t.TempDir(), Project: "bravo"})
			for _, p := range []string{"first", "second"} {
				if _, err := s.resolveVolume(adminCtx(), "", p); status.Code(err) != codes.FailedPrecondition {
					t.Errorf("use of %s: got %v, want FailedPrecondition", p, err)
				}
			}
		})
	}
	// Sibling exports on one server, and one path on two servers, are not.
	for name, pair := range map[string][2]string{
		"sibling exports":       {"nas:/tenants/acme", "nas:/tenants/acme2"},
		"one path, two servers": {"10.0.0.5:/x", "10.0.0.6:/x"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newPoolTestServer(t)
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "first", Driver: "nfs", Source: pair[0], Target: t.TempDir()})
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
				Name: "second", Driver: "nfs", Source: pair[1], Target: t.TempDir(), Options: noPrepare})
			notSharedRefusal(t, pair[1]+" beside "+pair[0], err)
		})
	}
}
