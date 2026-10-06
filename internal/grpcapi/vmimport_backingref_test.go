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

// qemu opens a VMDK descriptor's extents whether or not the file starts with
// the "# Disk DescriptorFile" line, and whatever whitespace separates the
// fields. The check judges the files qemu itself reports, not the text.
func TestAssertNoExternalDiskRefs_RejectsAHeaderlessTabSeparatedVMDK(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(outside, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := t.TempDir()
	desc := filepath.Join(allowed, "disk.vmdk")
	body := "version=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW\t2048\tFLAT\t\"" + outside + "\"\t0\n"
	if err := os.WriteFile(desc, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := assertNoExternalDiskRefs(context.Background(), desc, allowed); err == nil {
		t.Fatal("header-less, tab-separated VMDK extent outside: got nil, want rejection")
	}
}

func TestAssertNoExternalDiskRefs_AcceptsAVMDKWithItsExtentInside(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	allowed := t.TempDir()
	if err := os.WriteFile(filepath.Join(allowed, "flat.bin"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	desc := filepath.Join(allowed, "disk.vmdk")
	body := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"flat.bin\" 0\n"
	if err := os.WriteFile(desc, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := assertNoExternalDiskRefs(context.Background(), desc, allowed); err != nil {
		t.Fatalf("VMDK whose extent is inside the import dir: %v", err)
	}
}

// A disk staged outside the import directory (--disk-map into the staging
// root, or an admin's path) is converted in place; its own location is not an
// escape, only files it names beyond its own directory are.
func TestAssertNoExternalDiskRefs_AcceptsAStagedDiskOutsideTheImportDir(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	staging := t.TempDir()
	importDir := t.TempDir()
	disk := filepath.Join(staging, "vm-100-disk-0.qcow2")
	qemuImg(t, "create", "-f", "qcow2", disk, "1M")
	if err := assertNoExternalDiskRefs(context.Background(), disk, importDir); err != nil {
		t.Fatalf("standalone staged disk outside the import dir: %v", err)
	}
}

// qemu opens a disk in the format it is TOLD, not the one it would probe: a
// VMDK descriptor whose first line is not "version=" probes as raw, yet
// `convert -f vmdk` follows its extents. The check must judge the disk in the
// format conversion will use.
func vmdkDescriptorNamedLikeRaw(t *testing.T, dir, outside string) string {
	t.Helper()
	desc := filepath.Join(dir, "disk.vmdk")
	body := "CID=fffffffe\nversion=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"" + outside + "\" 0\n"
	if err := os.WriteFile(desc, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return desc
}

func TestConvertForeignDisk_DeclaredVMDKIsJudgedAsVMDK(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(outside, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	importDir := t.TempDir()
	desc := vmdkDescriptorNamedLikeRaw(t, importDir, outside)
	dst := filepath.Join(t.TempDir(), "out.qcow2")

	if err := convertForeignDisk(context.Background(), desc, "vmdk", dst, importDir, nil); err == nil {
		t.Fatal("declared-vmdk descriptor whose extent is outside: converted, want refusal")
	}
}

func TestAssertNoExternalDiskRefs_BackingIsJudgedInItsRecordedFormat(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(outside, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	importDir := t.TempDir()
	vmdkDescriptorNamedLikeRaw(t, importDir, outside)
	top := filepath.Join(importDir, "top.qcow2")
	qemuImg(t, "create", "-f", "qcow2", "-u", "-b", "disk.vmdk", "-F", "vmdk", top, "1M")

	if err := assertNoExternalDiskRefs(context.Background(), top, importDir); err == nil {
		t.Fatal("qcow2 backed (-F vmdk) by a descriptor naming an outside extent: got nil, want refusal")
	}
}
