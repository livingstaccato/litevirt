package pitoverlay

import (
	"os"
	"path/filepath"
	"testing"
)

// OrphanPath takes only a name SetAside makes for the disk: never a path,
// another disk's orphan, the live overlay, or a binding.
//
// Mutation "no prefix check" (OrphanPath joins any name without a slash):
// the live overlay and another disk's orphan are taken; red.
func TestOrphanPath_TakesOnlyThisDisksSetAsideNames(t *testing.T) {
	disk := filepath.Join("/srv/pool", "web-root.qcow2")
	good := ".web-root.qcow2.lv-pit.orphan-20261018-120000"
	if p, err := OrphanPath(disk, good); err != nil || p != filepath.Join("/srv/pool", good) {
		t.Fatalf("OrphanPath(%q) = %q, %v", good, p, err)
	}
	for _, bad := range []string{
		"../x", "/etc/passwd", ".web-root.qcow2.lv-pit", ".web-root.qcow2.lv-pit.orphan-",
		good + ".id", ".db-root.qcow2.lv-pit.orphan-20261018-120000",
		".web-root.qcow2.lv-pit.orphan-x/../../y",
	} {
		if p, err := OrphanPath(disk, bad); err == nil {
			t.Errorf("OrphanPath(%q) = %q, want refused", bad, p)
		}
	}
}

// R2 I-1. Only SetAside's exact shape is an orphan: ".<disk>.lv-pit.orphan-"
// and a stamp YYYYMMDD-HHMMSS (optionally -N) at the very end. A dotted VM or
// disk name that merely contains ".lv-pit.orphan-" names a LIVE overlay
// (ending ".lv-pit"), a binding, or a disk, never an orphan.
//
// Mutation "prefix-only shape" (IsOrphanName accepts any name containing
// the marker): the live overlay of VM w.lv-pit.orphan-1 is an orphan; red.
func TestIsOrphanName_OnlySetAsidesExactShape(t *testing.T) {
	for name, want := range map[string]string{
		".web-root.qcow2.lv-pit.orphan-20261018-120000":               "web-root.qcow2",
		".web-root.qcow2.lv-pit.orphan-20261018-120000-3":             "web-root.qcow2",
		".w.lv-pit.orphan-1-root.qcow2.lv-pit.orphan-20261018-120000": "w.lv-pit.orphan-1-root.qcow2",
	} {
		if base, ok := IsOrphanName(name); !ok || base != want {
			t.Errorf("IsOrphanName(%q) = %q, %v; want %q", name, base, ok, want)
		}
	}
	for _, name := range []string{
		".w.lv-pit.orphan-1-root.qcow2.lv-pit",    // VM w.lv-pit.orphan-1's live overlay
		".w.lv-pit.orphan-1-root.qcow2.lv-pit.id", // its binding
		".web-root.qcow2.lv-pit.orphan-20261018-120000.id",
		".web-root.qcow2.lv-pit.orphan-2026",
		".web-root.qcow2.lv-pit.orphan-20261018-120000x",
		".web-root.qcow2.lv-pit.orphan-20261018-120000-",
		"web-root.qcow2.lv-pit.orphan-20261018-120000",
	} {
		if base, ok := IsOrphanName(name); ok {
			t.Errorf("IsOrphanName(%q) = %q, true; want refused", name, base)
		}
	}
}

// R2 I-1, the VM-scoped side: beside a disk "w", a sibling disk named
// "w.lv-pit.orphan-1-root.qcow2" has a live overlay ".w.lv-pit.orphan-1-
// root.qcow2.lv-pit". It is neither listed as w's orphan nor accepted as one.
//
// Mutation "glob unfiltered" (orphansWith keeps every glob match): it is
// listed; red.
func TestOrphans_ASiblingsLiveOverlayIsNotAnOrphan(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "w")
	sibling := filepath.Join(dir, "w.lv-pit.orphan-1-root.qcow2")
	real := Path(disk) + ".orphan-20261018-120000"
	for _, p := range []string{Path(sibling), real} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Orphans(disk)
	if err != nil || len(got) != 1 || got[0] != real {
		t.Fatalf("Orphans(w) = %v, %v; want only %s", got, err, real)
	}
	if _, err := OrphanPath(disk, filepath.Base(Path(sibling))); err == nil {
		t.Fatal("OrphanPath took the sibling's live overlay as w's orphan")
	}
}
