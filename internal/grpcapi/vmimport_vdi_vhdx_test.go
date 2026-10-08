package grpcapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// realQemuImg skips a test that needs the real qemu-img.
func realQemuImg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
}

func qemuImgOK(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("qemu-img", args...).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img %v: %v: %s", args, err, out)
	}
}

// foreignDiskWithData writes a 4 MiB raw disk holding a pattern at 1 MiB,
// converts it to format with opts, and returns the image and the raw bytes.
func foreignDiskWithData(t *testing.T, dir, format, opts string) (string, []byte) {
	t.Helper()
	raw := make([]byte, 4<<20)
	copy(raw[1<<20:], bytes.Repeat([]byte("litevirt-import "), 4096))
	rawPath := filepath.Join(t.TempDir(), "src.raw")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "disk."+format)
	args := []string{"convert", "-f", "raw", "-O", format}
	if opts != "" {
		args = append(args, "-o", opts)
	}
	qemuImgOK(t, append(args, rawPath, img)...)
	return img, raw
}

// I-1. VDI and VHDX disks — an OVA exported from VirtualBox, a Hyper-V disk
// through --disk-map — import again, fixed and dynamic, declared or read from
// the header, and the converted disk holds the source's data.
func TestConvertForeignDisk_ImportsVDIAndVHDX(t *testing.T) {
	realQemuImg(t)
	for _, c := range []struct {
		name, format, opts string
	}{
		{"dynamic VDI", "vdi", ""},
		{"fixed VDI", "vdi", "static=on"},
		{"dynamic VHDX", "vhdx", "subformat=dynamic"},
		{"fixed VHDX", "vhdx", "subformat=fixed"},
	} {
		for _, declared := range []bool{true, false} {
			name := c.name + map[bool]string{true: " declared", false: " undeclared"}[declared]
			t.Run(name, func(t *testing.T) {
				importDir := t.TempDir()
				img, want := foreignDiskWithData(t, importDir, c.format, c.opts)
				format := ""
				if declared {
					format = c.format
				}
				dst := filepath.Join(t.TempDir(), "out.qcow2")
				if err := convertForeignDisk(context.Background(), img, format, dst, importDir, 1<<30, nil, nil); err != nil {
					t.Fatalf("convert %s: %v", c.name, err)
				}
				back := filepath.Join(t.TempDir(), "back.raw")
				qemuImgOK(t, "convert", "-f", "qcow2", "-O", "raw", dst, back)
				got, err := os.ReadFile(back)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("the converted %s does not hold the source's data", c.name)
				}
			})
		}
	}
}

// A differencing VDI depends on a parent image. It is refused with a reason,
// and qemu-img never opens it.
func TestConvertForeignDisk_RefusesADifferencingVDI(t *testing.T) {
	realQemuImg(t)
	for name, mutate := range map[string]func(h []byte){
		"differencing type": func(h []byte) { binary.LittleEndian.PutUint32(h[vdiOffImageType:], 4) },
		"undo type":         func(h []byte) { binary.LittleEndian.PutUint32(h[vdiOffImageType:], 3) },
		"a parent uuid":     func(h []byte) { h[vdiOffUUIDParent+3] = 0x5a },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			img, _ := foreignDiskWithData(t, dir, "vdi", "")
			patchFile(t, img, 0, vdiHeaderLen, mutate)
			if err := assertStandaloneVDI(img); err == nil {
				t.Fatal("a VDI with a parent passed the header check")
			}
			refusedUnopened(t, img, "vdi")
			refusedUnopened(t, img, "")
		})
	}
}

// A differencing VHDX depends on a parent. Whether it says so by HasParent in
// its file parameters or by a parent locator item, it is refused with a
// reason, and qemu-img never opens it.
func TestConvertForeignDisk_RefusesADifferencingVHDX(t *testing.T) {
	realQemuImg(t)
	for name, mutate := range map[string]func(t *testing.T, img string, meta int64){
		"HasParent": func(t *testing.T, img string, meta int64) {
			off := vhdxItemOffset(t, img, meta, vhdxItemFileParams)
			patchFile(t, img, meta+int64(off), 8, func(p []byte) {
				binary.LittleEndian.PutUint32(p[4:], binary.LittleEndian.Uint32(p[4:])|vhdxHasParent)
			})
		},
		"a parent locator": func(t *testing.T, img string, meta int64) {
			patchFile(t, img, meta, vhdxMetaTableBytes, func(tab []byte) {
				n := binary.LittleEndian.Uint16(tab[10:12])
				e := tab[32+int(n)*32:]
				copy(e[:16], vhdxItemParentLoc)
				binary.LittleEndian.PutUint16(tab[10:12], n+1)
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			img, _ := foreignDiskWithData(t, dir, "vhdx", "subformat=dynamic")
			f, err := os.Open(img)
			if err != nil {
				t.Fatal(err)
			}
			meta, ok, err := vhdxMetadataRegion(f, vhdxRegionTable1)
			f.Close()
			if err != nil || !ok {
				t.Fatalf("a VHDX qemu-img wrote has no metadata region: %v", err)
			}
			if err := assertStandaloneVHDX(img); err != nil {
				t.Fatalf("the unmodified VHDX: %v", err)
			}
			mutate(t, img, meta)
			if err := assertStandaloneVHDX(img); err == nil {
				t.Fatal("a VHDX with a parent passed the header check")
			}
			refusedUnopened(t, img, "vhdx")
			refusedUnopened(t, img, "")
		})
	}
}

// patchFile reads n bytes of p at off, lets mutate change them, and writes
// them back.
func patchFile(t *testing.T, p string, off int64, n int, mutate func([]byte)) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	mutate(b)
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

// vhdxItemOffset is the offset, within the metadata region at meta, of the
// item id names.
func vhdxItemOffset(t *testing.T, img string, meta int64, id []byte) uint32 {
	t.Helper()
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	tab := b[meta:]
	n := int(binary.LittleEndian.Uint16(tab[10:12]))
	for i := 0; i < n; i++ {
		e := tab[32+i*32:]
		if bytes.Equal(e[:16], id) {
			return binary.LittleEndian.Uint32(e[16:20])
		}
	}
	t.Fatal("item not found")
	return 0
}
