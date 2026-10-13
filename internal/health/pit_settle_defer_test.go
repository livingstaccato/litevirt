package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/storage"
)

// Review round 1, I-1: a start whose overlay check does not answer is
// DEFERRED, not failed. failPendingStart parks a proof-less start (onboot
// autostart, a self-heal of a running row whose domain is gone) in "error",
// which no pass re-drives: the VM stayed down after its storage answered
// again, where main had started it once the hung pass went on. Deferred, it
// waits in "starting" and starts on the next pass after the storage answers.
//
// Mutation "the no-answer goes to failPendingStart" — the VM is left in
// error and never started: red.
func TestReconciler_AnOverlayCheckThatDoesNotAnswerDefersTheStart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
		spec  string
		first func(r *Reconciler, ctx context.Context)
	}{
		{"self-heal", "running", `{"name":"vm1"}`, func(r *Reconciler, ctx context.Context) { r.reconcile(ctx) }},
		{"onboot", "stopped", `{"name":"vm1","onboot":true}`, func(r *Reconciler, ctx context.Context) { r.StartOnbootVMs(ctx) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			disk := filepath.Join(t.TempDir(), "vm1-root.qcow2")
			if err := os.WriteFile(disk, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node-a", State: tc.state, Spec: tc.spec}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: disk, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
			release := make(chan struct{})
			var once sync.Once
			answer := func() { once.Do(func() { close(release) }) }
			t.Cleanup(answer)
			t.Cleanup(pitoverlay.SetLstatForTest(func(p string) (os.FileInfo, error) {
				if p == pitoverlay.Path(disk) {
					<-release
				}
				return os.Lstat(p)
			}))

			tc.first(r, ctx)
			if hwStarted(fake, "vm1") {
				t.Fatal("the VM started while its overlay check did not answer")
			}
			vm := requireState(t, db, "vm1", "starting")
			if !strings.Contains(vm.StateDetail, "does not answer") {
				t.Errorf("state detail %q does not say why the start waits", vm.StateDetail)
			}

			// The storage answers again: the stuck call returns.
			answer()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := pitoverlay.PresentBounded(disk); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the overlay check still does not answer after the release")
				}
				time.Sleep(20 * time.Millisecond)
			}
			r.reconcile(ctx)
			if !hwStarted(fake, "vm1") {
				t.Fatal("the deferred start was not re-driven once the storage answered")
			}
			requireState(t, db, "vm1", "running")
		})
	}
}
