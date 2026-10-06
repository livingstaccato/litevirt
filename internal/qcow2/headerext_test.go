package qcow2

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Two backing-format extensions are counted as two: this package reads the
// first, qemu the last, so a caller that judges then hands the file to qemu
// refuses more than one.
func TestBackingFormatExtensionCount(t *testing.T) {
	head := make([]byte, 4096)
	binary.BigEndian.PutUint32(head[0:4], Magic)
	binary.BigEndian.PutUint32(head[4:8], 3)
	binary.BigEndian.PutUint32(head[100:104], 104)
	off := 104
	put := func(typ uint32, data string) {
		binary.BigEndian.PutUint32(head[off:], typ)
		binary.BigEndian.PutUint32(head[off+4:], uint32(len(data)))
		copy(head[off+8:], data)
		off += 8 + (len(data)+7)/8*8
	}
	put(extBackingFormat, "qcow2")
	put(extBackingFormat, "raw")
	path := filepath.Join(t.TempDir(), "two.qcow2")
	if err := os.WriteFile(path, head, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := BackingFormatExtensionCount(path); err != nil || n != 2 {
		t.Errorf("count = %d, %v; want 2", n, err)
	}
	one := filepath.Join(t.TempDir(), "one.qcow2")
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(one, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := BackingFormatExtensionCount(one); err != nil || n != 1 {
		t.Errorf("a backed image this package wrote: count = %d, %v; want 1", n, err)
	}
}
