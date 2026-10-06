package vmimport

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A VMA names each device stream; the name came from the archive, so it must
// never become part of a host path. A name with "../" made the parser create
// and fill a .raw file outside the import directory, as root, during parsing
// (so --inspect did it too).
func TestParseVMA_DeviceNameNeverLeavesTheImportDir(t *testing.T) {
	b := newVMABuilder()
	b.addConfig("qemu-server.conf", vmaEmbeddedConf)
	b.addDevice(1, "../../escaped", 64*1024)
	vma, _ := b.build()

	root := t.TempDir()
	dest := filepath.Join(root, "a", "b", "import")
	if _, err := ParseVMA(bytes.NewReader(vma), dest); err != nil {
		t.Logf("ParseVMA: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "a", "escaped.raw")); err == nil {
		t.Fatal("a VMA device name wrote a file outside the import directory")
	}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if rel, rerr := filepath.Rel(dest, p); rerr != nil || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
				t.Errorf("file written outside the import directory: %s", p)
			}
		}
		return nil
	})
}
