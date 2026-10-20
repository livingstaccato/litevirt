package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// lv snapshot rm entered on a node that does not own the VM: the owner
// deletes the snapshot as metadata only (libvirt cannot merge it safely), and
// the files it kept, with their size, reach the caller through the entry
// node's forward, as lv prints them.
//
// Mutation "entry does not relay" (DeleteSnapshot's forward drops the
// owner's SnapshotFilesKeptHeader): red.
func TestFleet_SnapshotRmForwardedReportsTheFilesKept(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	seedRunningVM(t, c, owner, "kvm", "", 1, 256)
	for _, name := range []string{"s1", "s2"} { // two: s1's delete is libvirt's, not a flatten
		if _, err := owner.Virt.CreateSnapshot("kvm", name); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertSnapshot(ctx, entry.DB, corrosion.SnapshotRecord{
			ID: "kvm-" + name, VMName: "kvm", HostName: owner.Name, Name: name, State: "ok", Type: "disk",
		}); err != nil {
			t.Fatal(err)
		}
	}
	overlay := filepath.Join(t.TempDir(), "kvm-root.s1")
	if err := os.WriteFile(overlay, make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	owner.Virt.DeleteSnapshotKeeps = []string{overlay}

	var hdr metadata.MD
	if _, err := c.SelfClient(entry).DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "kvm", SnapshotName: "s1"}, grpc.Header(&hdr)); err != nil {
		t.Fatalf("DeleteSnapshot through %s: %v", entry.Name, err)
	}
	w := hdr.Get(grpcapi.SnapshotFilesKeptHeader)
	if len(w) != 1 || !strings.Contains(w[0], overlay) || !strings.Contains(w[0], "2.0 MiB") {
		t.Fatalf("the caller got %s = %q, want the owner's kept overlay and its size", grpcapi.SnapshotFilesKeptHeader, w)
	}
}
