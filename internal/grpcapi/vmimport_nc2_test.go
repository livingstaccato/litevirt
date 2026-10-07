package grpcapi

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// The disk-file branch's N-C2: an imported disk whose OVF declares no format
// (or an unknown one) used to be probed by qemu-img, and a qcow2 with an
// external data file naming a host file — another project's disk, the host
// key — was copied into the importer's new disk. Integrated, the format is
// read from the header by litevirt, the header's data file is refused before
// qemu-img opens anything, and that holds for an undeclared format too.
func TestConvertForeignDisk_AnUndeclaredQcow2WithADataFileIsRefusedUnopened(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "disk.img")
	if err := qcow2.Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := f.ReadAt(buf, 72); err != nil {
		t.Fatal(err)
	}
	// The external data file incompatible feature bit.
	binary.BigEndian.PutUint64(buf, binary.BigEndian.Uint64(buf)|4)
	if _, err := f.WriteAt(buf, 72); err != nil {
		t.Fatal(err)
	}
	f.Close()
	refusedUnopened(t, p, "")
}
