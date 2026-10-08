package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// stage writes b to a fresh temp in the store's image directory.
func stage(t *testing.T, s *Store, b []byte) string {
	t.Helper()
	f, err := os.CreateTemp(s.imageDir, "import-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

// Content is published as <name>@<sha256[:16]>.qcow2 and the name pointed at
// it; a refresh is a new version, and the first file is never written over.
func TestPublish_ARefreshIsANewVersionNeverAWriteOver(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	v1, v2 := []byte("version one"), []byte("version two")
	p1, err := s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil {
		t.Fatal(err)
	}
	// m-new-1: the first content is named by its content too, so every host
	// that holds it names it the same.
	if p1.Path != filepath.Join(s.imageDir, "ubuntu@"+digestOf(v1)[:16]+".qcow2") || p1.Superseded != "" || s.ImagePath("ubuntu") != p1.Path {
		t.Fatalf("first publish = %+v", p1)
	}
	p2, err := s.Publish("ubuntu", stage(t, s, v2), digestOf(v2))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Path == p1.Path || p2.Superseded != p1.Path {
		t.Fatalf("refresh = %+v", p2)
	}
	if got, _ := os.ReadFile(p1.Path); !bytes.Equal(got, v1) {
		t.Fatal("the first version was written over")
	}
	if s.ImagePath("ubuntu") != p2.Path {
		t.Errorf("ImagePath = %s, want the refresh %s", s.ImagePath("ubuntu"), p2.Path)
	}
	if !IsImageFile(s.imageDir, "ubuntu", p2.Path) || !IsImageFile(s.imageDir, "ubuntu", p1.Path) || IsImageFile(s.imageDir, "ubunt", p2.Path) {
		t.Error("IsImageFile does not know the image's files")
	}
	if n, ok := ImageNameOfFile(p2.Path); !ok || n != "ubuntu" {
		t.Errorf("ImageNameOfFile(%s) = %q, %v", p2.Path, n, ok)
	}
	// Publishing the current content again changes nothing.
	p3, err := s.Publish("ubuntu", stage(t, s, v2), digestOf(v2))
	if err != nil || p3.Path != p2.Path || p3.Superseded != "" {
		t.Errorf("republish of the current content = %+v, %v", p3, err)
	}
}

// Concern 1: a file whose bytes stopped matching its recorded identity is
// healed by content equal to that identity, and by nothing else.
func TestPublish_HealsOnlyWithTheRecordedIdentity(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	good := []byte("the base overlays were built on")
	p, err := s.Publish("img", stage(t, s, good), digestOf(good))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Path, []byte("damaged"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := []byte("other content")
	if _, err := s.Publish("img", stage(t, s, other), digestOf(other)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p.Path); string(got) != "damaged" {
		t.Fatal("other content was written over the damaged base")
	}
	h, err := s.Publish("img", stage(t, s, good), digestOf(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Healed) != 1 || h.Healed[0] != p.Path {
		t.Errorf("healed %v, want %s", h.Healed, p.Path)
	}
	if got, _ := os.ReadFile(p.Path); !bytes.Equal(got, good) {
		t.Error("the damaged base was not healed")
	}
	if ents, _ := filepath.Glob(filepath.Join(s.imageDir, "*.tmp")); len(ents) != 0 {
		t.Errorf("temps left behind: %v", ents)
	}
}

// N-I1: a pinned version is never removed, and a pin is no image file.
func TestPin_APinnedVersionIsNeverRemoved(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	v1, v2 := []byte("version one"), []byte("version two")
	p1, err := s.Publish("ubuntu", stage(t, s, v1), digestOf(v1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish("ubuntu", stage(t, s, v2), digestOf(v2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Pin(p1.Path); err != nil {
		t.Fatal(err)
	}
	if err := s.Pin(p1.Path); err != nil {
		t.Fatalf("a second pin: %v", err)
	}
	if !Pinned(p1.Path) {
		t.Fatal("not pinned")
	}
	if err := s.RemoveImageFile("ubuntu", p1.Path); err == nil {
		t.Error("a pinned version was removed")
	}
	if _, err := os.Stat(p1.Path); err != nil {
		t.Fatal("the pinned version is gone")
	}
	for f := range s.StoreFiles() {
		if filepath.Ext(f) == ".pinned" {
			t.Errorf("the pin %s is listed as an image file", f)
		}
	}
	if err := s.Pin(filepath.Join(t.TempDir(), "x.qcow2")); err == nil {
		t.Error("a file outside the store was pinned")
	}
}
