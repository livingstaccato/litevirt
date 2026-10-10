package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Nit of re-review 4: the define path clears a disk's hold only when this
// host can see the disk. A shared disk whose pool is not mounted here reads
// as "no overlay", and must not resolve a hold another host raised while
// that overlay stands.
//
// Mutation "clear whatever the disk" — red.
func TestSettlePITOverlays_ClearsOnlyADiskThisHostSees(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	r := NewReconciler("h1", t.TempDir(), db, libvirtfake.New())
	var cleared []string
	r.SetPITOverlayReporter(func(context.Context, string, string, string) {},
		func(_ context.Context, vm, disk string) { cleared = append(cleared, vm+"/"+disk) })
	seen := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := os.WriteFile(seen, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	failure := r.settlePITOverlays(context.Background(), corrosion.VMRecord{Name: "web"}, &pb.VMSpec{}, []lv.DiskConfig{
		{Name: "root", Path: seen},
		{Name: "data", Path: "/nonexistent-pool-not-mounted-here/web-data.qcow2"},
	})
	if failure != "" {
		t.Fatalf("settle: %s", failure)
	}
	if len(cleared) != 1 || cleared[0] != "web/root" {
		t.Fatalf("cleared %v; want only the disk this host sees", cleared)
	}
}
