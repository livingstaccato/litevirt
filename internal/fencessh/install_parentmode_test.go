package fencessh

import (
	"os"
	"path/filepath"
	"testing"
)

// sshd runs the AuthorizedKeysCommand as nobody, so it must traverse the parent
// of the ssh dir (/etc/litevirt). A 0700 parent, as `lv host init --local` left
// it, made every read fail. The install adds the search bit for others and
// nothing else, and the secrets beside the dir keep their modes.
func TestInstallScript_ParentDirIsSearchableNotReadable(t *testing.T) {
	w := newInstallWorld(t, "")
	parent := filepath.Dir(w.dir)
	secret := filepath.Join(parent, "admin-password")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	for i := 0; i < 2; i++ { // idempotent
		w.run(t)
		if fi, _ := os.Stat(parent); fi.Mode().Perm() != 0o701 {
			t.Fatalf("pass %d: parent mode %o, want 701", i, fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(secret); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret mode %o, want 600", fi.Mode().Perm())
	}
}
