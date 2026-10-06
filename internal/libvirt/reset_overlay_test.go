package libvirt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// resetOverlay hands its base to qemu-img (format named -F qcow2), which opens
// an external data file together with the image. A base that keeps its data
// in another file is refused before qemu-img runs, and the overlay is left
// alone.
func TestResetOverlay_RefusesABaseWithExternalData(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(base)
	data[79] |= 1 << 2 // incompatible feature: external data file
	if err := os.WriteFile(base, data, 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "overlay.qcow2")
	if err := os.WriteFile(overlay, []byte("current overlay"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resetOverlay(overlay, base); err == nil {
		t.Fatal("resetOverlay accepted a base with an external data file")
	}
	if got, _ := os.ReadFile(overlay); string(got) != "current overlay" {
		t.Error("the overlay was touched although the base was refused")
	}
}
