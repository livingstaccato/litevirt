package vmimport

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// An OVA extracts into the import directory, which usually shares a
// filesystem with the daemon's database; it may write no more than the
// caller's budget.
func TestUnpackOVA_StopsAtItsBudget(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range map[string][]byte{"vm.ovf": []byte("<Envelope/>"), "disk.vmdk": make([]byte, 1<<20)} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	if _, err := UnpackOVA(bytes.NewReader(buf.Bytes()), t.TempDir(), Budget(64<<10)); err == nil {
		t.Fatal("an OVA larger than its budget was extracted")
	}
	if _, err := UnpackOVA(bytes.NewReader(buf.Bytes()), t.TempDir(), Budget(4<<20)); err != nil {
		t.Fatalf("an OVA within its budget: %v", err)
	}
}

// Each member is reserved, at the running total, before its file is created:
// a refused member leaves nothing of itself behind.
func TestUnpackOVA_ReservesEachMemberBeforeWritingIt(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range []struct {
		name string
		size int
	}{{"vm.ovf", 11}, {"disk1.vmdk", 1 << 20}, {"disk2.vmdk", 1 << 20}} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(m.size), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(make([]byte, m.size)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	dest := t.TempDir()
	var asked []uint64
	_, err := UnpackOVA(bytes.NewReader(buf.Bytes()), dest, func(total uint64) error {
		asked = append(asked, total)
		if total > 1<<20+11 {
			return fmt.Errorf("no room")
		}
		return nil
	})
	if err == nil {
		t.Fatal("an OVA past its reservation was extracted")
	}
	if want := []uint64{11, 1<<20 + 11, 2<<20 + 11}; !slices.Equal(asked, want) {
		t.Fatalf("reserved %v, want the running totals %v", asked, want)
	}
	if _, err := os.Stat(filepath.Join(dest, "disk2.vmdk")); !os.IsNotExist(err) {
		t.Fatalf("the refused member was created: %v", err)
	}
}
