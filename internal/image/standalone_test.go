package image

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// craftedOverlay returns the bytes of a qcow2 whose header names hostFile as
// its backing file.
func craftedOverlay(t *testing.T) []byte {
	t.Helper()
	work := t.TempDir()
	hostFile := filepath.Join(work, "host-only")
	if err := os.WriteFile(hostFile, []byte("not for the guest"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(work, "crafted.qcow2")
	if err := qcow2.CreateWithBacking(p, hostFile, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPull_RefusesImageThatNamesAHostFile(t *testing.T) {
	body := craftedOverlay(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	if err := Pull(s, "crafted", srv.URL, "", PullOptions{}, ch); err == nil {
		t.Fatal("pull of an image naming a host file: got nil, want refusal")
	}
	if s.ImageExists("crafted") {
		t.Fatal("refused image finalized in the store")
	}
}

// An image stored before arrival checks existed must not become an overlay's
// base either.
func TestCreateOverlayDisk_RefusesBaseThatNamesAHostFile(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	if err := os.WriteFile(s.ImagePath("legacy"), craftedOverlay(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOverlayDisk("vm1", "root", "legacy", ""); err == nil {
		t.Fatal("overlay on a base naming a host file: got nil, want refusal")
	}
}
