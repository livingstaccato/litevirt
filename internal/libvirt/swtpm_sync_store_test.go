package libvirt

import (
	"path/filepath"
	"testing"
)

// Merge of the vTPM durability work into the per-host store: a store's
// SyncSwtpmState works on that store's swtpm tree, so two hosts in one
// process (the fleet harness) each sync their own, and the marker names it.
//
// Mutation: sync DefaultSwtpmBase from the method — the pass reports another
// tree, red.
func TestFirmwareStore_SyncSwtpmStateUsesItsOwnTree(t *testing.T) {
	a, b := storeAt(t.TempDir(), t.TempDir()), storeAt(t.TempDir(), t.TempDir())
	for _, st := range []*FirmwareStore{a, b} {
		rep := st.SyncSwtpmState(false, filepath.Join(st.DataDir, "vtpm-state-sync"))
		want, err := filepath.EvalSymlinks(st.SwtpmBase)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Base != st.SwtpmBase && rep.Base != want {
			t.Errorf("the pass worked on %q, want the store's %q", rep.Base, st.SwtpmBase)
		}
	}
}
