package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Deleting a container's last snapshot leaves no empty ct-snapshots/<name>/
// behind; one with snapshots left keeps its directory.
func TestDeleteContainerSnapshot_RemovesTheEmptyDirectory(t *testing.T) {
	s, _ := snapTestServer(t, "stopped")
	for _, sn := range []string{"s1", "s2"} {
		if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: sn}); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Dir(ctSnapshotPath(s.dataDir, "ct1", "s1"))
	if _, err := s.DeleteContainerSnapshot(adminCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the directory went with a snapshot still in it: %v", err)
	}
	if _, err := s.DeleteContainerSnapshot(adminCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("empty snapshot directory left behind: %v", err)
	}
}
