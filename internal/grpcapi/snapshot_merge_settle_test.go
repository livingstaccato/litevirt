package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Re-review 2, I-B, end to end through the RPC. The running merge pivots,
// but the persistent definition cannot be repointed (libvirt.FlattenSnapshot
// then keeps and marks the layers). Nothing is removed, the record moves to
// the base where the data is, and the next start, which would boot that
// stale top, is refused loudly.
func TestDeleteSnapshot_AnUnrepointedDefinitionKeepsTheRecordAndRefusesTheNextStart(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "ib-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "ib", "running", root, corrosion.DiskRecord{})
	top := f.snap(t, "s1", true)
	f.fake.FlattenLeavesConfig = true
	f.rm(t, "s1")

	// The record names where the data is (re-review 3, I-1); the start,
	// which judges the definition, still refuses below.
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "ib")
	if len(disks) != 1 || disks[0].Path != root {
		t.Fatalf("record %+v, want it on %s, where the data is", disks, root)
	}
	if _, err := os.Stat(top); err != nil {
		t.Fatalf("the top the definition names was removed: %v", err)
	}
	if into, ok := lv.MergedInto(top); !ok || into != root {
		t.Fatalf("the kept top is not marked merged into %s", root)
	}
	// Stopped, then started: the persistent definition still boots the top.
	f.fake.SetInactiveXML("ib", `<domain type='kvm'><name>ib</name><devices><disk type='file' device='disk'>`+
		`<driver name='qemu' type='qcow2'/><source file='`+top+`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`)
	err := f.s.verifyImageBasesForStart(adminCtx(), &corrosion.VMRecord{Name: "ib", HostName: "host-a"})
	if err == nil || !strings.Contains(err.Error(), "stale") || !strings.Contains(err.Error(), root) {
		t.Fatalf("a start booting the merged top was not refused loudly: %v", err)
	}
}

// A definition on its base with an unrelated marked file elsewhere starts.
func TestStart_ADefinitionOnItsBaseIsNotRefused(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "ok-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "ok", "stopped", root, corrosion.DiskRecord{})
	if err := os.WriteFile(lv.MergedLayerMarker(filepath.Join(dir, "ok-root.old")), []byte(root), 0o644); err != nil {
		t.Fatal(err)
	}
	f.fake.SetInactiveXML("ok", `<domain type='kvm'><name>ok</name><devices><disk type='file' device='disk'>`+
		`<driver name='qemu' type='qcow2'/><source file='`+root+`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`)
	if err := f.s.verifyImageBasesForStart(adminCtx(), &corrosion.VMRecord{Name: "ok", HostName: "host-a"}); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

// Re-review 2, m-3 through the RPC: a merge that fails after the metadata
// went falls back; every file stays and the record names the file the
// domain is on.
func TestDeleteSnapshot_AFailedMergeLeavesTheRecordOnTheDomainsFile(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "fm-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "fm", "stopped", root, corrosion.DiskRecord{})
	top := f.snap(t, "s1", true)
	f.fake.FailFlattenSnapshot = errors.New("qemu-img commit: Failed to get write lock")
	f.rm(t, "s1")
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "fm")
	if len(disks) != 1 || disks[0].Path != f.on(t) || disks[0].Path != top {
		t.Fatalf("record %+v, domain on %s; want both on %s", disks, f.on(t), top)
	}
	for _, p := range []string{root, top} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
}
