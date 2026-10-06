package grpcapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// assertNoExternalDiskRefs guards the foreign-disk conversion: qemu-img must
// not open a host file the source disk names. A backing file written as a
// json: or protocol name is not a plain path, so joining it to the disk's
// directory made it look contained; an external data file is a second file
// qemu-img reads guest data from.

func TestAssertNoExternalDiskRefs_RejectsJSONBackingName(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(outside, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := t.TempDir()
	overlay := filepath.Join(allowed, "overlay.qcow2")
	backing := `json:{"driver":"raw","file":{"driver":"file","filename":"` + outside + `"}}`
	qemuImg(t, "create", "-f", "qcow2", "-u", "-b", backing, "-F", "raw", overlay, "1M")

	if err := assertNoExternalDiskRefs(context.Background(), overlay, allowed); err == nil {
		t.Fatal("json: backing name pointing outside: got nil, want rejection")
	}
}

func TestAssertNoExternalDiskRefs_RejectsExternalDataFile(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := filepath.Join(t.TempDir(), "host-only")
	allowed := t.TempDir()
	img := filepath.Join(allowed, "datafile.qcow2")
	qemuImg(t, "create", "-f", "qcow2", "-o", "data_file="+outside, img, "1M")

	if err := assertNoExternalDiskRefs(context.Background(), img, allowed); err == nil {
		t.Fatal("external data file outside: got nil, want rejection")
	}
}

func TestAssertNoExternalDiskRefs_RejectsEscapeDeeperInTheChain(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := filepath.Join(t.TempDir(), "base.qcow2")
	allowed := t.TempDir()
	mid := filepath.Join(allowed, "mid.qcow2")
	top := filepath.Join(allowed, "top.qcow2")
	qemuImg(t, "create", "-f", "qcow2", outside, "1M")
	qemuImg(t, "create", "-f", "qcow2", "-b", outside, "-F", "qcow2", mid)
	qemuImg(t, "create", "-f", "qcow2", "-b", "mid.qcow2", "-F", "qcow2", top)

	if err := assertNoExternalDiskRefs(context.Background(), top, allowed); err == nil {
		t.Fatal("second-level backing outside the import dir: got nil, want rejection")
	}
}

func TestAssertNoExternalDiskRefs_AcceptsAChainInsideTheImportDir(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	allowed := t.TempDir()
	base := filepath.Join(allowed, "base.qcow2")
	top := filepath.Join(allowed, "top.qcow2")
	qemuImg(t, "create", "-f", "qcow2", base, "1M")
	qemuImg(t, "create", "-f", "qcow2", "-b", "base.qcow2", "-F", "qcow2", top)

	if err := assertNoExternalDiskRefs(context.Background(), top, allowed); err != nil {
		t.Fatalf("chain inside the import dir: %v", err)
	}
}

func TestPlainBackingPath(t *testing.T) {
	for name, want := range map[string]bool{
		"base.qcow2":                   true,
		"/var/lib/litevirt/x.qcow2":    true,
		"sub/dir:with-colon.qcow2":     true,
		`json:{"driver":"raw"}`:        false,
		"nbd:10.0.0.1:10809":           false,
		"http://example.invalid/x.img": false,
		"file:/etc/passwd":             false,
		"nbd+unix:///export?socket=/s": false,
	} {
		if got := plainBackingPath(name); got != want {
			t.Errorf("plainBackingPath(%q) = %v, want %v", name, got, want)
		}
	}
}
