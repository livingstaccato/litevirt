package libvirtfake

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// I-1 of the pit-restore review: the fake's "the definition names the
// overlay" (pitOn) follows the definition. A redefine that does not name the
// overlay, or an undefine, takes the domain off it, as in libvirt; a start
// on a definition still naming a missing (or dangling-symlinked) overlay is
// refused.
//
// Mutations "define keeps pitOn", "undefine keeps pitOn" and "Lstat, not
// Stat" — red.
func TestPITOverlay_TheDefinitionDecidesWhatAStartOpens(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "d.qcow2")
	overlay := filepath.Join(dir, ".d.qcow2.lv-pit")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	onBase := "<domain><name>vm</name><uuid>0b7c6a8e-0000-4000-8000-0000000000aa</uuid><devices><disk type='file'><source file='" + disk + "'/></disk></devices></domain>"
	onOverlay := "<domain><name>vm</name><uuid>0b7c6a8e-0000-4000-8000-0000000000aa</uuid><devices><disk type='file'><source file='" + overlay + "'/></disk></devices></domain>"
	f := New()
	strand := func() {
		t.Helper()
		f.SetState("vm", StateRunning)
		if _, err := f.SnapshotDiskExternal("vm", disk, overlay); err != nil {
			t.Fatal(err)
		}
		f.SetState("vm", StateShutdown)
		if err := os.Remove(overlay); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.DefineDomain(onBase); err != nil {
		t.Fatal(err)
	}

	strand()
	if err := f.StartDomain("vm"); err == nil {
		t.Fatal("a definition naming a missing overlay started")
	}
	// A dangling symlink at the overlay's path is as missing to qemu.
	if err := os.Symlink(filepath.Join(dir, "gone"), overlay); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("vm"); err == nil {
		t.Fatal("a definition naming a dangling-symlink overlay started")
	}
	_ = os.Remove(overlay)
	// A redefine that names the overlay keeps the domain on it.
	if err := f.DefineDomain(onOverlay); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.DomainUsesFile("vm", overlay); !on {
		t.Fatal("a redefine naming the overlay took the domain off it")
	}
	// A redefine from the spec, which names the base, takes it off.
	if err := f.DefineDomain(onBase); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.DomainUsesFile("vm", overlay); on {
		t.Fatal("a redefine on the base left the domain on the overlay")
	}
	if err := f.StartDomain("vm"); err != nil {
		t.Fatalf("start after a redefine on the base: %v", err)
	}

	f.SetState("vm", StateRunning)
	strand()
	if err := f.UndefineDomain("vm", false); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.DomainUsesFile("vm", overlay); on {
		t.Fatal("an undefined domain is still on the overlay")
	}
	if err := f.DefineDomain(onBase); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("vm"); err != nil {
		t.Fatalf("start of a domain undefined and defined again on its base: %v", err)
	}

	// The same through UndefineDomainPreservingState.
	strand()
	if err := f.UndefineDomainPreservingState("vm"); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.DomainUsesFile("vm", overlay); on {
		t.Fatal("a domain undefined preserving its state is still on the overlay")
	}
	if err := f.DefineDomain(onBase); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("vm"); err != nil {
		t.Fatalf("start of a domain undefined and defined again on its base: %v", err)
	}
}
