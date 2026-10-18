package pitoverlay

import (
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
