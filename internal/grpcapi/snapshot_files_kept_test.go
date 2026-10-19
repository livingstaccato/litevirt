package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A snapshot libvirt cannot merge safely is deleted as metadata only, and
// every file stays: nothing is lost, and no space comes back. The delete
// says so, naming the files it kept and their size, in the response header
// lv snapshot rm prints and in the VM's event snapshot.files-kept. On
// 458db618 only the daemon's log said it.
//
// Mutation "report dropped" (DeleteSnapshot sets no header and records no
// event for a SnapshotFilesKeptError): red twice.
func TestDeleteSnapshot_AMetadataOnlyDeleteReportsTheFilesItKept(t *testing.T) {
	s := lockTestServer(t)
	fake := seedRestorableVM(t, s, "disk")
	// A second snapshot, so the delete is libvirt's, not the last one's flatten.
	if _, err := fake.CreateSnapshot("rs", "s2"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(adminCtx(), s.db, corrosion.SnapshotRecord{
		ID: "rs-s2", VMName: "rs", HostName: s.hostName, Name: "s2", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(t.TempDir(), "rs-root.s1")
	if err := os.WriteFile(overlay, make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.DeleteSnapshotKeeps = []string{overlay}

	h := &headerCapture{}
	ctx := grpc.NewContextWithServerTransportStream(adminCtx(), h)
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v (the metadata-only delete succeeded)", err)
	}
	if snap, _ := corrosion.GetSnapshot(adminCtx(), s.db, "rs", "s1"); snap != nil {
		t.Fatal("the snapshot's record is still live")
	}
	w := h.md.Get(SnapshotFilesKeptHeader)
	if len(w) != 1 || !strings.Contains(w[0], overlay) || !strings.Contains(w[0], "3.0 MiB") {
		t.Errorf("response header %s = %q, want the kept overlay and its size", SnapshotFilesKeptHeader, w)
	}
	evs, err := corrosion.ListVMEvents(adminCtx(), s.db, "rs", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "snapshot.files-kept" && strings.Contains(e.Detail, overlay) {
			found = true
		}
	}
	if !found {
		t.Errorf("no snapshot.files-kept event naming %s among %+v", overlay, evs)
	}
}

// A delete libvirt merges reports nothing kept.
func TestDeleteSnapshot_AMergedDeleteReportsNothingKept(t *testing.T) {
	s := lockTestServer(t)
	seedRestorableVM(t, s, "disk")
	h := &headerCapture{}
	ctx := grpc.NewContextWithServerTransportStream(adminCtx(), h)
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if w := h.md.Get(SnapshotFilesKeptHeader); len(w) != 0 {
		t.Errorf("a merged delete set %s = %q", SnapshotFilesKeptHeader, w)
	}
}
