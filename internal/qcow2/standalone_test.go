package qcow2

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestAssertStandalone_PlainQcow2Passes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain.qcow2")
	if err := Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := AssertStandalone(p); err != nil {
		t.Fatalf("standalone qcow2: %v", err)
	}
}

func TestAssertStandalone_RawPasses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AssertStandalone(p); err != nil {
		t.Fatalf("raw image: %v", err)
	}
}

func TestAssertStandalone_BackingFileRefused(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "host-only")
	if err := os.WriteFile(other, []byte("not for the guest"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "overlay.qcow2")
	if err := CreateWithBacking(p, other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := AssertStandalone(p); err == nil {
		t.Fatal("qcow2 with a backing file: got nil, want refusal")
	}
}

func TestAssertStandalone_ExternalDataFileRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "datafile.qcow2")
	if err := Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	// Set incompatible feature bit 2 (external data file) in the v3 header.
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := f.ReadAt(buf, 72); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(buf, binary.BigEndian.Uint64(buf)|4)
	if _, err := f.WriteAt(buf, 72); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := AssertStandalone(p); err == nil {
		t.Fatal("qcow2 with an external data file: got nil, want refusal")
	}
}

func TestAssertStandalone_VMDKDescriptorRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "desc.vmdk")
	body := "# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"other-file\" 0\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AssertStandalone(p); err == nil {
		t.Fatal("VMDK descriptor naming an extent: got nil, want refusal")
	}
}

func TestAssertStandalone_SparseVMDKRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sparse.vmdk")
	b := make([]byte, 512)
	copy(b, "KDMV")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AssertStandalone(p); err == nil {
		t.Fatal("sparse VMDK (may embed an extent descriptor): got nil, want refusal")
	}
}
