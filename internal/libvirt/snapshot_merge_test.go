package libvirt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

func needQemuTools(t *testing.T) {
	t.Helper()
	for _, b := range []string{"qemu-img", "qemu-io"} {
		if _, err := exec.LookPath(b); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("%s is required in CI", b)
			}
			t.Skipf("%s not installed", b)
		}
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

func depthOf(t *testing.T, file string) int {
	t.Helper()
	n := 0
	for p := file; p != ""; n++ {
		info, err := qcow2.Info(p)
		if err != nil {
			t.Fatalf("qcow2.Info %s: %v", p, err)
		}
		p = info.BackingFile
	}
	return n
}

// A stopped VM's last snapshot is merged offline: each create/rm cycle
// commits the overlay's data into the base and leaves the chain as deep as
// it was. The base has a backing of its own (an image, as a VM's disk
// does), so the depth is measured, not a constant: the commit must stop at
// the base, never reach the image, and never leave a layer. Twenty cycles,
// every write kept.
func TestCommitLayersOffline_TwentyCyclesKeepDepthAndData(t *testing.T) {
	needQemuTools(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "image.qcow2")
	base := filepath.Join(dir, "vm-root.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", img, "1M")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", img, base)
	imgBefore := fileSum(t, img)
	for i := 0; i < 20; i++ {
		top := filepath.Join(dir, fmt.Sprintf("vm-root.c%d", i))
		run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, top)
		if d := depthOf(t, top); d != 3 {
			t.Fatalf("cycle %d: the top's chain is %d deep before the merge, want 3", i, d)
		}
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("write -P %d %d 4k", i+1, i*4096), top)
		above, err := commitLayersOffline(top, base)
		if err != nil {
			t.Fatalf("cycle %d: commitLayersOffline: %v", i, err)
		}
		if len(above) != 1 || above[0] != top {
			t.Fatalf("cycle %d: layers above the base = %q, want [%s]", i, above, top)
		}
		if err := os.Remove(top); err != nil {
			t.Fatal(err)
		}
		if d := depthOf(t, base); d != 2 {
			t.Fatalf("cycle %d: the base's chain is %d deep, want 2 (base over its image)", i, d)
		}
		if fileSum(t, img) != imgBefore {
			t.Fatalf("cycle %d: the commit wrote into the image under the base", i)
		}
	}
	run(t, "qemu-img", "check", "-q", base)
	for i := 0; i < 20; i++ {
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("read -P %d %d 4k", i+1, i*4096), base)
	}
}

// Layers between the top and the base are merged too and reported, so the
// caller removes every file the chain no longer uses.
func TestCommitLayersOffline_MergesEveryLayerAboveTheBase(t *testing.T) {
	needQemuTools(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "vm-root.qcow2")
	mid := filepath.Join(dir, "vm-root.m1")
	top := filepath.Join(dir, "vm-root.m2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", base, "1M")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, mid)
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 7 0 4k", mid)
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", mid, top)
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 9 4k 4k", top)
	above, err := commitLayersOffline(top, base)
	if err != nil {
		t.Fatalf("commitLayersOffline: %v", err)
	}
	if len(above) != 2 || above[0] != top || above[1] != mid {
		t.Fatalf("layers above = %q, want [%s %s]", above, top, mid)
	}
	run(t, "qemu-io", "-f", "qcow2", "-c", "read -P 7 0 4k", base)
	run(t, "qemu-io", "-f", "qcow2", "-c", "read -P 9 4k 4k", base)
}

// A base that is not in the top's chain is refused before anything is
// written.
func TestCommitLayersOffline_RefusesABaseOutsideTheChain(t *testing.T) {
	needQemuTools(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "vm-root.qcow2")
	other := filepath.Join(dir, "other.qcow2")
	top := filepath.Join(dir, "vm-root.s1")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", base, "1M")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", other, "1M")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, top)
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -P 5 0 4k", top)
	if _, err := commitLayersOffline(top, other); err == nil {
		t.Fatal("a base outside the chain was accepted")
	}
	run(t, "qemu-io", "-f", "qcow2", "-c", "read -P 5 0 4k", top)
}
