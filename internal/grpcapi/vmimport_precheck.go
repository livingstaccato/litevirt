package grpcapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// A foreign disk reaches qemu-img as root. qemu-img opens whatever the disk's
// format makes it open — a VMDK descriptor's extents, a qcow2 data file — the
// moment it opens the disk, before any answer it gives can be judged. So
// litevirt reads the header itself first, and qemu-img only ever sees a disk
// whose header names no other file but a backing file (which qemu-img info
// leaves closed, and the chain walk judges).

// importDiskFormats are the formats an import converts. Each is one whose
// every file reference the header check understands.
var importDiskFormats = map[string]bool{"raw": true, "qcow2": true, "vmdk": true, "vpc": true}

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
	}
	// raw and vpc name no other file.
	return nil
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
	case bytes.HasPrefix(head, []byte("vhdxfile")),
		bytes.HasPrefix(head, []byte("QED\x00")),
		len(head) >= 0x44 && binary.LittleEndian.Uint32(head[0x40:0x44]) == 0xbeda107f:
		// Converted as raw these would copy their container bytes into a
		// disk that does not boot.
		return "", fmt.Errorf("disk is VHDX, QED or VDI, which the import does not convert; convert it to qcow2 or raw first")
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
func privateImportDisk(ctx context.Context, src, importDir string) (string, error) {
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
	out, err := os.CreateTemp(importDir, "disk-*")
	if err != nil {
		return "", err
	}
	if err := copySparse(ctx, out, in); err != nil {
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

// copySparse copies in to out leaving every all-zero chunk a hole, so a thin
// disk costs its data rather than its virtual size in the import directory,
// which usually shares a filesystem with state.db. It stops when ctx ends.
func copySparse(ctx context.Context, out, in *os.File) error {
	buf := make([]byte, 1<<20)
	var off int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := io.ReadFull(in, buf)
		if n > 0 {
			if allZero(buf[:n]) {
				if _, err := out.Seek(int64(n), io.SeekCurrent); err != nil {
					return err
				}
			} else if _, err := out.Write(buf[:n]); err != nil {
				return err
			}
			off += int64(n)
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
