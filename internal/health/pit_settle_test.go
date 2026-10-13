package health

import (
	"context"
	"os"
	"path/filepath"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/storage"
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
	failure, _ := r.settlePITOverlays(context.Background(), corrosion.VMRecord{Name: "web"}, &pb.VMSpec{}, []lv.DiskConfig{
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

// Lab 2 N-4, the reconciler's define-and-start path: a disk whose storage
// does not answer is never taken as having no overlay. The pass is not held
// by it, the VM is not defined (the failure is retried next pass), and its
// hold is not cleared.
//
// Mutation "the overlay is looked for unbounded" — the pass hangs: red.
func TestSettlePITOverlays_AStorageThatDoesNotAnswerIsAFailureNotNoOverlay(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	r := NewReconciler("h1", t.TempDir(), db, libvirtfake.New())
	var cleared []string
	r.SetPITOverlayReporter(func(context.Context, string, string, string) {},
		func(_ context.Context, vm, disk string) { cleared = append(cleared, vm+"/"+disk) })
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	release := make(chan struct{})
	t.Cleanup(pitoverlay.SetLstatForTest(func(p string) (os.FileInfo, error) {
		if p == pitoverlay.Path(disk) {
			<-release
		}
		return os.Lstat(p)
	}))
	t.Cleanup(func() { close(release) })
	type res struct {
		failure  string
		deferred error
	}
	done := make(chan res, 1)
	go func() {
		f, d := r.settlePITOverlays(context.Background(), corrosion.VMRecord{Name: "web"}, &pb.VMSpec{}, []lv.DiskConfig{{Name: "root", Path: disk}})
		done <- res{f, d}
	}()
	select {
	case got := <-done:
		if !strings.Contains(got.failure, "does not answer") || !errors.Is(got.deferred, ErrStartDeferred) {
			t.Fatalf("settle on storage that does not answer: %q, %v; want a deferral saying so", got.failure, got.deferred)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reconciler's overlay settle waited on storage that does not answer")
	}
	if len(cleared) != 0 {
		t.Fatalf("cleared %v while the overlay's presence was unknown", cleared)
	}
}
