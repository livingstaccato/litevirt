package fencessh_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A host init'd with --local before the fix has /etc/litevirt 0700. The daemon
// repairs it at startup (its first sync): the search bit only, no read bit, and
// the files beside the ssh dir are left alone.
func TestSync_RepairsAParentThatNobodyCannotSearch(t *testing.T) {
	w := newWorld(t)
	x := w.node("node-x", "127.0.0.3")
	x.start(false)
	x.hostRow(x.ip, x.port)

	parent := filepath.Dir(x.dir)
	secret := filepath.Join(parent, "admin-password")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	for i := 0; i < 2; i++ { // idempotent
		if err := x.publisher(true, true).Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		if fi, _ := os.Stat(parent); fi.Mode().Perm() != 0o701 {
			t.Fatalf("pass %d: parent mode %o, want 701", i, fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(secret); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret mode %o, want 600", fi.Mode().Perm())
	}
}
