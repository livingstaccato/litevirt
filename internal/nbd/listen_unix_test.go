package nbd

import (
	"os"
	"path/filepath"
	"testing"
)

// The unix socket a restore VM's qemu connects to is owner-only.
func TestListenUnix_OwnerOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nbd.sock")
	s := &Server{ExportName: "x"}
	if err := s.ListenUnix(p); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want a 0600 socket", st.Mode())
	}
}
