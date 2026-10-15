package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// misalignedImage returns the bytes of a qcow2 whose L1 table names an L2
// table off a cluster boundary — what `lv image build` wrote from a disk
// over 512 MiB, and what qemu refuses as corrupt.
func misalignedImage(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "built.qcow2")
	if err := qcow2.Create(p, 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	l1 := binary.BigEndian.Uint64(b[40:48])
	// L1[0] -> 0x10200: sector-aligned, not cluster-aligned (64 KiB).
	binary.BigEndian.PutUint64(b[l1:l1+8], 0x10200|1<<63)
	return b
}

// Such an image is reported when a disk is made on it, and left untouched.
func TestCreateOverlayDisk_RefusesMisalignedBase(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	p := s.ImagePath("built")
	b := misalignedImage(t)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateOverlayDisk("vm1", "root", "built", "")
	if !errors.Is(err, qcow2.ErrMisaligned) {
		t.Fatalf("overlay on a misaligned base = %v, want qcow2.ErrMisaligned", err)
	}
	if _, serr := os.Stat(s.DiskPath("vm1", "root")); !os.IsNotExist(serr) {
		t.Fatalf("overlay disk created on a refused base (stat: %v)", serr)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, b) {
		t.Fatal("the refused image was modified")
	}
}

// A pull is refused on arrival, naming the image and the remedy, and
// nothing is kept in the store.
func TestPull_RefusesMisalignedImage(t *testing.T) {
	body := misalignedImage(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	err := Pull(s, "built", srv.URL, "", PullOptions{}, ch)
	if !errors.Is(err, qcow2.ErrMisaligned) {
		t.Fatalf("pull of a misaligned image = %v, want qcow2.ErrMisaligned", err)
	}
	for _, want := range []string{"built", "lv image build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %s", err, want)
		}
	}
	if s.ImageExists("built") {
		t.Fatal("refused image finalized in the store")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(s.ImagePath("built")), "*")); len(left) != 0 {
		t.Fatalf("refused pull left files behind: %v", left)
	}
}
