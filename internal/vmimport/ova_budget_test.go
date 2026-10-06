package vmimport

import (
	"archive/tar"
	"bytes"
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
	if _, err := UnpackOVA(bytes.NewReader(buf.Bytes()), t.TempDir(), 64<<10); err == nil {
		t.Fatal("an OVA larger than its budget was extracted")
	}
	if _, err := UnpackOVA(bytes.NewReader(buf.Bytes()), t.TempDir(), 4<<20); err != nil {
		t.Fatalf("an OVA within its budget: %v", err)
	}
}
