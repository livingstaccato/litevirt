//go:build linux

package libvirt

import (
	"os"
	"path/filepath"
	"testing"
)

// The real ioctls, on the filesystem that holds t.TempDir(): a state file
// swtpm writes after the pass (a new file renamed into place) carries the
// flag, and off clears it again.
func TestSwtpmSync_RealFilesystem(t *testing.T) {
	base, _, tpm2, state := swtpmTree(t)
	rep := syncSwtpmTree(base, true, osSwtpmFlagOps)
	switch rep.State {
	case SwtpmSyncOn:
	case SwtpmSyncUnsupported, SwtpmSyncNotInherited:
		t.Skipf("the filesystem under %s does not keep an inherited sync flag (%s: %v); "+
			"the fake-backed tests cover the logic", base, rep.State, rep.Err)
	default:
		t.Fatalf("report %+v", rep)
	}

	tmp := filepath.Join(tpm2, "TMP2-00.permall")
	if err := os.WriteFile(tmp, []byte("new state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, state); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{base, tpm2, state} {
		fl, err := osSwtpmFlagOps.get(p)
		if err != nil {
			t.Fatal(err)
		}
		if fl&fsSyncFlag == 0 {
			t.Errorf("%s: flags %#x, no sync flag", p, fl)
		}
	}

	if rep := syncSwtpmTree(base, false, osSwtpmFlagOps); rep.State != SwtpmSyncOff {
		t.Fatalf("off: %+v", rep)
	}
	for _, p := range []string{base, tpm2, state} {
		if fl, _ := osSwtpmFlagOps.get(p); fl&fsSyncFlag != 0 {
			t.Errorf("%s: off left the sync flag (%#x)", p, fl)
		}
	}
}
