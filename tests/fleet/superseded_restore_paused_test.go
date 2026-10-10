package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// M8: a restore is refused under a domain that is paused — libvirt's coarse
// state reads "stopped" for it, but its disk is open — even when the row says
// stopped. Nothing is moved.
//
// Mutation: read the coarse DomainState instead of DomainIsActive in the
// restore's running check — the paused domain reads stopped, the disk is
// swapped under it and the test is red.
func TestFleet_RestoreRefusedUnderAPausedDomain(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	asked, holder := c.Nodes[0], c.Nodes[1]
	disks := filepath.Join(c.tmpRoot, holder.Name, "data", "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(disks, "pz-root.qcow2")
	copyPath := path + ".superseded-" + time.Now().Add(-time.Hour).UTC().Format("20060102T150405.000000000Z")
	for p, b := range map[string]string{path: "current", copyPath: "real"} {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, asked.DB, corrosion.VMRecord{Name: "pz", HostName: holder.Name, State: "stopped", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "pz", DiskName: "root", HostName: holder.Name, Path: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := holder.Virt.DefineDomain(`<domain type='kvm'><name>pz</name></domain>`); err != nil {
		t.Fatal(err)
	}
	holder.Virt.SetPaused("pz")

	_, err := c.SelfClient(asked).SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name, Purge: true,
		OlderThanSec: grpcapi.SupersededNamedOnlySec, RestorePath: copyPath})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("restore under a paused domain: %v, want FailedPrecondition", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "current" {
		t.Fatalf("the disk under the paused domain was swapped: %q", b)
	}
}
