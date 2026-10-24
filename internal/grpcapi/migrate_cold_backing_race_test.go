package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// End to end through streamColdDisk with no hook in the reader: the linked
// clone's template base (tpl-base.qcow2, accepted by diskChainRule) is flipped
// between itself and a link to another tenant's qcow2 by a loop, as an export
// writer could. A copy that lands on the target with the other image's bytes is
// the escape. Bounded by time.
//
// Red on 45d5844fb (the flatten opened backings by name, 3 of 3 runs within a
// second). Mutation: os.Open for backings in qcow2.openChainFollow - red.
func TestStreamColdDiskBackingSwapRaceShipsNothing(t *testing.T) {
	f := newColdDiskFixture(t)
	const size = 1 << 20
	f.recordTemplateBase(t)
	sp := f.src.hostDiskFile(f.path)
	dir := filepath.Dir(sp)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "tpl-base.qcow2")
	if err := qcow2.Create(base, size, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(sp, base, size, nil); err != nil {
		t.Fatal(err)
	}
	od := t.TempDir()
	raw := filepath.Join(od, "secret.raw")
	if err := os.WriteFile(raw, bytes.Repeat([]byte("OTHER-TENANT-SEC"), size/16), 0o600); err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(od, "ov.qcow2")
	if err := qcow2.CreateWithBackingFormat(ov, raw, "raw", size, nil); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(od, "other-tenant.qcow2")
	if err := qcow2.Convert(context.Background(), ov, secret, &qcow2.Options{Uncompressed: true}); err != nil {
		t.Fatal(err)
	}
	saved, lnk := base+".saved", filepath.Join(dir, ".lnk")
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			_ = os.Link(base, saved)
			_ = os.Symlink(secret, lnk)
			_ = os.Rename(lnk, base)
			_ = os.Rename(saved, base)
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	attempts, leaked := 0, 0
	for time.Now().Before(deadline) && leaked == 0 {
		attempts++
		_ = os.Remove(f.path)
		f.client = &loopDiskClient{up: &loopDiskUp{dst: f.dst, ctx: f.peer}}
		if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "qcow2"); err != nil {
			continue
		}
		if b, _ := os.ReadFile(f.path); bytes.Contains(b, []byte("OTHER-TENANT-SEC")) {
			leaked++
		}
	}
	stop.Store(true)
	<-done
	if leaked > 0 {
		t.Errorf("the target received another tenant's image as this disk's backing content (attempt %d)", attempts)
	}
}
