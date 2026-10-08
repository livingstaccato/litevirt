package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi.Mode().Perm()
}

// A container snapshot is the container's whole rootfs (its /etc/shadow
// included). It was written 0644 in a 0755 directory, readable by every local
// user. Snapshots are 0600 in 0700 directories.
func TestSnapshotContainer_TarIsPrivate(t *testing.T) {
	s, _ := snapTestServer(t, "stopped")
	// An earlier build left the directories world-readable.
	if err := os.MkdirAll(filepath.Join(s.dataDir, containerSnapshotDir, "ct1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("SnapshotContainer: %v", err)
	}
	p := ctSnapshotPath(s.dataDir, "ct1", "s1")
	if m := modeOf(t, p); m != 0o600 {
		t.Errorf("snapshot tar mode = %o, want 600", m)
	}
	for _, d := range []string{filepath.Dir(p), filepath.Dir(filepath.Dir(p))} {
		if m := modeOf(t, d); m != 0o700 {
			t.Errorf("snapshot dir %s mode = %o, want 700", d, m)
		}
	}
}

// A snapshot an earlier build wrote world-readable is made private the next
// time it is used: no backfill, only the files touched.
func TestSnapshotContainer_ExistingTarIsMadePrivateOnUse(t *testing.T) {
	for _, use := range []string{"list", "revert"} {
		t.Run(use, func(t *testing.T) {
			s, _ := snapTestServer(t, "stopped")
			p := ctSnapshotPath(s.dataDir, "ct1", "old")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(filepath.Dir(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("old-tar"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertContainerSnapshot(context.Background(), s.db, corrosion.ContainerSnapshotRecord{
				CtName: "ct1", HostName: "host-a", Name: "old", State: "ok", Type: "tar", Path: p,
			}); err != nil {
				t.Fatal(err)
			}
			var err error
			if use == "list" {
				_, err = s.ListContainerSnapshots(adminCtx(), &pb.ListContainerSnapshotsRequest{Name: "ct1", HostName: "host-a"})
			} else {
				_, err = s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "old"})
			}
			if err != nil {
				t.Fatalf("%s: %v", use, err)
			}
			if m := modeOf(t, p); m != 0o600 {
				t.Errorf("after %s the old tar mode = %o, want 600", use, m)
			}
			for _, d := range []string{filepath.Dir(p), filepath.Dir(filepath.Dir(p))} {
				if m := modeOf(t, d); m != 0o700 {
					t.Errorf("after %s dir %s mode = %o, want 700", use, d, m)
				}
			}
		})
	}
}
