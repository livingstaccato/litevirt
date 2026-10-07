package grpcapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/vmimport"
	"log/slog"
)

// A foreign disk reaches qemu-img as root. qemu-img opens whatever the disk's
// format makes it open — a VMDK descriptor's extents, a qcow2 data file — the
// moment it opens the disk, before any answer it gives can be judged. So
// litevirt reads the header itself first, and qemu-img only ever sees a disk
// whose header names no other file but a backing file (which qemu-img info
// leaves closed, and the chain walk judges).

// importDiskFormats are the formats an import converts. Each is one whose
// every file reference the header check understands.
var importDiskFormats = map[string]bool{"raw": true, "qcow2": true, "vmdk": true, "vpc": true, "vdi": true, "vhdx": true}

// vmdk4GDAtEnd is the grain-directory offset of a stream-optimized VMDK whose
// real header is the footer at the end of the file.
const vmdk4GDAtEnd = 0xffffffffffffffff

// precheckDiskHeader refuses a disk that qemu-img, opening it as format, would
// make open another file before anything could judge that file.
func precheckDiskHeader(file, format string) error {
	if !importDiskFormats[format] {
		return fmt.Errorf("disk format %q is not imported; convert it to qcow2 or raw first", format)
	}
	switch format {
	case "qcow2":
		return qcow2.AssertNoExternalData(file)
	case "vmdk":
		return assertSparseVMDK(file)
	case "vdi":
		return assertStandaloneVDI(file)
	case "vhdx":
		return assertStandaloneVHDX(file)
	}
	// raw and vpc name no other file.
	return nil
}

// VDI header (qemu block/vdi.c, VirtualBox VDICore.h): all little-endian.
const (
	vdiSignature     = 0xbeda107f
	vdiVersion1_1    = 0x00010001
	vdiTypeDynamic   = 1
	vdiTypeStatic    = 2
	vdiOffSignature  = 0x40
	vdiOffVersion    = 0x44
	vdiOffImageType  = 0x4c
	vdiOffUUIDParent = 0x1b8
	vdiHeaderLen     = 0x1c8
)

// assertStandaloneVDI accepts a VDI that is a whole disk: a fixed or dynamic
// image with no parent. qemu's vdi driver opens no other file, and refuses a
// differencing or undo image itself; litevirt says why first.
func assertStandaloneVDI(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	h := make([]byte, vdiHeaderLen)
	if _, err := io.ReadFull(f, h); err != nil {
		return fmt.Errorf("not a VDI image: short header")
	}
	le := binary.LittleEndian
	if le.Uint32(h[vdiOffSignature:]) != vdiSignature {
		return fmt.Errorf("not a VDI image: bad signature")
	}
	if v := le.Uint32(h[vdiOffVersion:]); v != vdiVersion1_1 {
		return fmt.Errorf("VDI version %#x is not imported; convert the disk to qcow2 first", v)
	}
	switch t := le.Uint32(h[vdiOffImageType:]); t {
	case vdiTypeDynamic, vdiTypeStatic:
	default:
		return fmt.Errorf("VDI image type %d is a differencing (or undo) image that depends on a parent; "+
			"merge it into its base in VirtualBox (or clone it to a standalone disk) and import that", t)
	}
	if !allZero(h[vdiOffUUIDParent : vdiOffUUIDParent+16]) {
		return fmt.Errorf("VDI image names a parent image; merge it into its base in VirtualBox (or clone it to a standalone disk) and import that")
	}
	return nil
}

// VHDX layout (MS-VHDX): the region tables at 192 KiB and 256 KiB, and in the
// metadata region a table of items. GUIDs are in their on-disk (mixed-endian)
// byte order.
var (
	vhdxRegionMetadata = []byte{0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e}
	vhdxItemFileParams = []byte{0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b}
	vhdxItemParentLoc  = []byte{0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c}
)

const (
	vhdxRegionTable1   = 192 << 10
	vhdxRegionTable2   = 256 << 10
	vhdxMaxEntries     = 2047
	vhdxHasParent      = 1 << 1
	vhdxMetaTableBytes = 64 << 10
)

// assertStandaloneVHDX accepts a VHDX that is a whole disk: no metadata
// region in either region table names a parent locator or sets HasParent in
// its file parameters. qemu's vhdx driver follows no parent (it refuses a
// differencing image); litevirt says why first, and refuses a file whose
// region tables it cannot read.
func assertStandaloneVHDX(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 8)
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head, []byte("vhdxfile")) {
		return fmt.Errorf("not a VHDX image: bad file identifier")
	}
	differencing := fmt.Errorf("VHDX image is a differencing disk that depends on a parent; " +
		"merge it into its parent in Hyper-V (or convert it to a standalone disk) and import that")
	read := 0
	for _, off := range []int64{vhdxRegionTable1, vhdxRegionTable2} {
		meta, ok, err := vhdxMetadataRegion(f, off)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		read++
		parent, err := vhdxNamesParent(f, meta)
		if err != nil {
			return err
		}
		if parent {
			return differencing
		}
	}
	if read == 0 {
		return fmt.Errorf("VHDX image has no readable region table with a metadata region")
	}
	return nil
}

// vhdxMetadataRegion is the file offset of the metadata region the region
// table at off names; ok is false when no table is there.
func vhdxMetadataRegion(f *os.File, off int64) (meta int64, ok bool, err error) {
	h := make([]byte, 16)
	if _, err := f.ReadAt(h, off); err != nil {
		return 0, false, nil
	}
	if !bytes.Equal(h[:4], []byte("regi")) {
		return 0, false, nil
	}
	n := binary.LittleEndian.Uint32(h[8:12])
	if n > vhdxMaxEntries {
		return 0, false, fmt.Errorf("VHDX region table has %d entries", n)
	}
	entries := make([]byte, 32*int(n))
	if _, err := f.ReadAt(entries, off+16); err != nil {
		return 0, false, fmt.Errorf("VHDX region table: %w", err)
	}
	for i := 0; i < int(n); i++ {
		e := entries[i*32 : (i+1)*32]
		if bytes.Equal(e[:16], vhdxRegionMetadata) {
			return int64(binary.LittleEndian.Uint64(e[16:24])), true, nil
		}
	}
	return 0, false, nil
}

// vhdxNamesParent reports whether the metadata region at meta holds a parent
// locator, or file parameters with HasParent set.
func vhdxNamesParent(f *os.File, meta int64) (bool, error) {
	t := make([]byte, vhdxMetaTableBytes)
	if _, err := f.ReadAt(t, meta); err != nil {
		return false, fmt.Errorf("VHDX metadata table: %w", err)
	}
	if !bytes.Equal(t[:8], []byte("metadata")) {
		return false, fmt.Errorf("VHDX metadata table: bad signature")
	}
	n := int(binary.LittleEndian.Uint16(t[10:12]))
	if n > vhdxMaxEntries {
		return false, fmt.Errorf("VHDX metadata table has %d entries", n)
	}
	for i := 0; i < n; i++ {
		e := t[32+i*32 : 32+(i+1)*32]
		switch {
		case bytes.Equal(e[:16], vhdxItemParentLoc):
			return true, nil
		case bytes.Equal(e[:16], vhdxItemFileParams):
			itemOff := binary.LittleEndian.Uint32(e[16:20])
			p := make([]byte, 8)
			if _, err := f.ReadAt(p, meta+int64(itemOff)); err != nil {
				return false, fmt.Errorf("VHDX file parameters: %w", err)
			}
			if binary.LittleEndian.Uint32(p[4:8])&vhdxHasParent != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// assertSparseVMDK accepts only a single-file sparse VMDK: a VMDK4 header with
// a capacity (and, for a stream-optimized disk, a footer with one). A text
// descriptor names its extents, and a sparse header with no capacity is opened
// through its embedded descriptor, whose extents qemu opens the same way.
// Whether a line of a descriptor names an extent is qemu's parser's call, so
// neither is imported; convert it to a stream-optimized VMDK or qcow2 first.
func assertSparseVMDK(file string) error {
	refuse := fmt.Errorf("only a single-file sparse or stream-optimized VMDK is imported; a VMDK descriptor names other files (convert it to qcow2 first)")
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 64)
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head[:4], []byte("KDMV")) {
		return refuse
	}
	if binary.LittleEndian.Uint64(head[12:20]) == 0 {
		return refuse
	}
	if binary.LittleEndian.Uint64(head[56:64]) != vmdk4GDAtEnd {
		return nil
	}
	// qemu replaces the header with the footer: magic at size-1024, the
	// header fields after it.
	fi, err := f.Stat()
	if err != nil || fi.Size() < 1536 {
		return refuse
	}
	foot := make([]byte, 64)
	if _, err := f.ReadAt(foot, fi.Size()-1024); err != nil {
		return refuse
	}
	if !bytes.Equal(foot[:4], []byte("KDMV")) || binary.LittleEndian.Uint64(foot[12:20]) == 0 {
		return refuse
	}
	return nil
}

// staticDiskFormat names an undeclared disk's format from its header, so
// qemu-img is never asked to probe one: a probe opens the disk in the format
// qemu guesses, and with it every file that format names. What is not
// recognised is raw, which qemu-img copies byte for byte.
func staticDiskFormat(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read disk header: %w", err)
	}
	head = head[:n]
	switch {
	case len(head) >= 4 && binary.BigEndian.Uint32(head[:4]) == qcow2.Magic:
		return "qcow2", nil
	case bytes.HasPrefix(head, []byte("KDMV")):
		return "vmdk", nil
	case bytes.HasPrefix(head, []byte("conectix")):
		return "vpc", nil
	case bytes.Contains(head, []byte("# Disk DescriptorFile")):
		return "", fmt.Errorf("a VMDK descriptor names other files; convert the disk to qcow2 first")
	case bytes.HasPrefix(head, []byte("vhdxfile")):
		return "vhdx", nil
	case len(head) >= 0x44 && binary.LittleEndian.Uint32(head[0x40:0x44]) == vdiSignature:
		return "vdi", nil
	case bytes.HasPrefix(head, []byte("QED\x00")):
		// Converted as raw it would copy its container bytes into a disk
		// that does not boot, and its backing file is not parsed here.
		return "", fmt.Errorf("disk is QED, which the import does not convert; convert it to qcow2 or raw first")
	}
	if fi, err := f.Stat(); err == nil && fi.Size() >= 512 {
		foot := make([]byte, 8)
		if _, err := f.ReadAt(foot, fi.Size()-512); err == nil && bytes.Equal(foot, []byte("conectix")) {
			return "vpc", nil
		}
	}
	return "raw", nil
}

// privateImportDisk returns a path to src that only the daemon can write. A
// disk the import itself wrote into importDir already is one. Any other —
// a staged file, a --disk-map path, an admin's path — is a file its owner can
// still change, so a disk checked as standalone could gain a backing file
// before qemu-img opens it. It is copied into importDir, opened without
// following a link, and must be a plain file; the copy is what is checked and
// converted.
//
// reserve, when set, is asked for the room the copy takes in importDir — the
// source's allocated blocks, since the copy is sparse — before it is written.
func privateImportDisk(ctx context.Context, src, importDir string, limit int64, reserve func(uint64) error) (string, error) {
	// importDir and everything under it is written by the daemon alone, so a
	// plain file named inside it (as written, or as resolved) is already
	// private.
	inside := safename.Contains(importDir, src)
	if root, err := filepath.EvalSymlinks(importDir); err == nil && safename.Contains(root, src) {
		inside = true
	}
	if fi, err := os.Lstat(src); inside && err == nil && fi.Mode().IsRegular() {
		return src, nil
	}
	in, err := openImportSourceNoLinks(src)
	if err != nil {
		return "", fmt.Errorf("open disk %s: %w", filepath.Base(src), err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("disk %s is not a plain file", filepath.Base(src))
	}
	if reserve != nil {
		if err := reserve(privateCopyNeed(fi)); err != nil {
			return "", err
		}
	}
	out, err := os.CreateTemp(importDir, "disk-*")
	if err != nil {
		return "", err
	}
	if err := copySparse(ctx, out, in, limit); err != nil {
		out.Close()
		os.Remove(out.Name())
		return "", fmt.Errorf("copy disk %s: %w", filepath.Base(src), err)
	}
	if err := out.Close(); err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

// privateCopyNeed is what copySparse writes for the source fi describes: its
// allocated blocks (it leaves every hole a hole), never more than its length.
// A filesystem that reports no blocks for a non-empty file is charged its
// length.
func privateCopyNeed(fi os.FileInfo) uint64 {
	size := uint64(max(fi.Size(), 0))
	alloc := size
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
		alloc = min(uint64(st.Blocks)*512, size)
	}
	// copySparse writes a partly-zero grain whole: the last one may round up.
	return min(size, alloc+copySparseGrain)
}

// copySparseGrain is the run of zeros copySparse leaves a hole.
const copySparseGrain = 64 << 10

// copySparse copies in to out leaving every all-zero chunk a hole, so a thin
// disk costs its data rather than its virtual size in the import directory,
// which usually shares a filesystem with state.db. It stops when ctx ends, and
// refuses a source longer than limit — the size the import was charged for —
// whatever its holes, so a file grown after admission cannot fill the disk.
func copySparse(ctx context.Context, out, in *os.File, limit int64) error {
	buf := make([]byte, 1<<20)
	var off int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := io.ReadFull(in, buf)
		if n > 0 {
			for g := 0; g < n; g += copySparseGrain {
				chunk := buf[g:min(g+copySparseGrain, n)]
				if allZero(chunk) {
					if _, err := out.Seek(int64(len(chunk)), io.SeekCurrent); err != nil {
						return err
					}
				} else if _, err := out.Write(chunk); err != nil {
					return err
				}
			}
			off += int64(n)
			if off > limit {
				return fmt.Errorf("disk is larger than the %d bytes the import was admitted for", limit)
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return out.Truncate(off)
}

// importSourceLimit is the largest staged file accepted for a disk of the
// given capacity: the capacity plus room for a format's own metadata (qcow2
// tables, VMDK grain tables, a VHD footer and BAT). A qcow2 carrying internal
// snapshots past that is refused; flatten it first.
func importSourceLimit(capacity uint64) int64 {
	const maxCap = 1 << 50
	if capacity > maxCap {
		capacity = maxCap
	}
	return int64(capacity + capacity/8 + 64<<20)
}

// bindImportDiskSizes makes the quota charge what the import will copy. The
// declared capacity comes from the foreign descriptor, which the operator who
// names --disk-map also writes; a disk that declares none is charged its file
// size, and a file larger than its declared capacity allows is refused before
// anything is admitted or copied.
func bindImportDiskSizes(fv *vmimport.ForeignVM) error {
	for i := range fv.Disks {
		d := &fv.Disks[i]
		if d.IsCDROM || d.LocalPath == "" {
			continue
		}
		fi, err := os.Stat(d.LocalPath)
		if err != nil {
			continue // a missing disk is refused at conversion
		}
		if d.CapacityBytes == 0 {
			d.CapacityBytes = uint64(fi.Size())
		}
		if fi.Size() > importSourceLimit(d.CapacityBytes) {
			return status.Errorf(codes.InvalidArgument,
				"disk %q is a %d-byte file but declares a %d-byte capacity; an import copies no more than its capacity allows",
				d.Name, fi.Size(), d.CapacityBytes)
		}
	}
	return nil
}

// importConvertSlack is room kept above what qemu-img measure says a
// conversion writes.
const importConvertSlack = 16 << 20

// importConvertNeed is what converting file (opened as format, of virtual
// size virtual) to qcow2 writes into the pool: what qemu-img measure says
// the qcow2 needs — the data it holds and the tables for it, not its
// capacity. Without an answer from measure, it is the whole virtual size
// with its tables.
func importConvertNeed(ctx context.Context, file, format string, virtual uint64) uint64 {
	req, err := qemuMeasure(ctx, file, format)
	if err == nil {
		return req + importConvertSlack
	}
	slog.Warn("import: qemu-img measure failed; reserving the disk's whole virtual size for its conversion", "disk", filepath.Base(file), "error", err)
	return coldFlattenEstimate(virtual, virtual)
}

// qemuMeasure is the bytes qemu-img says a qcow2 converted from file, opened
// as format (never probed), needs. file has passed the header check.
func qemuMeasure(ctx context.Context, file, format string) (uint64, error) {
	out, err := exec.CommandContext(ctx, "qemu-img", "measure", "--output=json", "-O", "qcow2", "-f", format, "--", file).Output()
	if err != nil {
		return 0, fmt.Errorf("measure %s: %w", filepath.Base(file), err)
	}
	var m struct {
		Required *uint64 `json:"required"`
	}
	if err := json.Unmarshal(out, &m); err != nil || m.Required == nil {
		return 0, fmt.Errorf("measure %s: unreadable qemu-img measure output", filepath.Base(file))
	}
	return *m.Required, nil
}

// qemuVirtualSize is the virtual size qemu-img reports for a disk that has
// already passed the header check, opened in the format it will be converted
// from.
func qemuVirtualSize(ctx context.Context, file, format string) (uint64, error) {
	out, err := exec.CommandContext(ctx, "qemu-img", "info", "-U", "--output=json", "-f", format, "--", file).Output()
	if err != nil {
		return 0, fmt.Errorf("inspect %s: %w", filepath.Base(file), err)
	}
	var info qemuImgInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return 0, fmt.Errorf("inspect %s: unreadable qemu-img info: %w", filepath.Base(file), err)
	}
	return info.VirtualSize, nil
}
