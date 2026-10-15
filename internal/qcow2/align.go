package qcow2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// ErrMisaligned marks a qcow2 image naming a table or cluster at an offset
// the qcow2 spec requires to be cluster-aligned. qemu refuses such an image
// as corrupt ("L2 table offset ... unaligned"), so a guest booted from it
// sees I/O errors. `lv image build` wrote images like this from any disk
// whose data spans more than one L2 table (over 512 MiB at the default 64 KiB
// clusters) until the convert placed its L2 tables on cluster boundaries;
// such an image has to be built again. Nothing here repairs one.
var ErrMisaligned = errors.New("qcow2 metadata not cluster-aligned")

// IsMisaligned reports whether err is an ErrMisaligned refusal, here or —
// by its text, the only part a gRPC status carries — on a peer.
func IsMisaligned(err error) bool {
	return err != nil && (errors.Is(err, ErrMisaligned) || strings.Contains(err.Error(), ErrMisaligned.Error()))
}

// misalignedHint is appended to every ErrMisaligned report.
const misalignedHint = "qemu refuses this image as corrupt; lv image build wrote images like this from disks over 512 MiB until it was fixed: rebuild the image with a fixed lv image build"

func misaligned(format string, a ...any) error {
	return fmt.Errorf("%w: %s; %s", ErrMisaligned, fmt.Sprintf(format, a...), misalignedHint)
}

// AssertAligned reports ErrMisaligned for a qcow2 image whose header, L1
// table or refcount table names a table at an offset that is not
// cluster-aligned. It reads only the header, the L1 table and the refcount
// table, so it is cheap enough for every use of an image, and it never
// writes. A file that is not qcow2, or whose header this package cannot
// parse, is not this check's to judge (nil).
func AssertAligned(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil || binary.BigEndian.Uint32(magic[:]) != Magic {
		return nil
	}
	h, err := readHeader(f)
	if err != nil {
		return nil
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	// Only a misalignment is judged here; a table this cannot read is for
	// Check, or qemu, to report.
	if err := checkTableAlignment(f, h, uint64(st.Size())); errors.Is(err, ErrMisaligned) {
		return err
	}
	return nil
}

// checkHeaderAlignment checks the two table offsets the header holds.
func checkHeaderAlignment(h *Header) error {
	cs := h.ClusterSize()
	if h.L1TableOffset%cs != 0 {
		return misaligned("L1 table offset %#x is not a multiple of the %d-byte cluster size", h.L1TableOffset, cs)
	}
	if h.RefcountTableOffset%cs != 0 {
		return misaligned("refcount table offset %#x is not a multiple of the %d-byte cluster size", h.RefcountTableOffset, cs)
	}
	return nil
}

// maxRefcountTableBytes is qemu's QCOW_MAX_REFTABLE_SIZE: qemu refuses to
// open an image whose refcount table is larger ("Reference count table too
// large"), so nothing here reads one.
const maxRefcountTableBytes = 8 << 20

// tableChunk is how much of a table is read at a time: the header claims a
// table's size, and only the file bounds it.
const tableChunk = 64 << 10

// checkTableAlignment checks every offset the header, the L1 table and the
// refcount table of a fileSize-byte image hold against the cluster size: each
// names a whole cluster (or a run of them) in the qcow2 spec. Reserved low
// bits are masked off the way qemu masks them, so what is judged is the
// offset qemu would use. Both tables are bounded by the file before anything
// is read, the refcount table by qemu's limit too, and each is read in
// tableChunk pieces, so a crafted header allocates nothing large.
func checkTableAlignment(f io.ReaderAt, h *Header, fileSize uint64) error {
	if err := checkHeaderAlignment(h); err != nil {
		return err
	}
	if fileSize > math.MaxInt64 {
		return fmt.Errorf("invalid file size %d", fileSize)
	}
	if err := validateHeaderRanges(h, int64(fileSize)); err != nil {
		return err
	}
	cs := h.ClusterSize()
	if err := forEachEntry(f, h.L1TableOffset, uint64(h.L1Size)*8, func(i, e uint64) error {
		if off := e & 0x00fffffffffffe00; off%cs != 0 {
			return misaligned("L1[%d] names an L2 table at %#x, not a multiple of the %d-byte cluster size", i, off, cs)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("L1 table: %w", err)
	}
	rctBytes := uint64(h.RefcountTableClusters) * cs
	if end := h.RefcountTableOffset + rctBytes; end < h.RefcountTableOffset || end > fileSize {
		return fmt.Errorf("refcount table extends beyond file")
	}
	if rctBytes > maxRefcountTableBytes {
		return fmt.Errorf("refcount table is %d bytes, over qemu's %d-byte limit", rctBytes, maxRefcountTableBytes)
	}
	if err := forEachEntry(f, h.RefcountTableOffset, rctBytes, func(i, e uint64) error {
		if off := e &^ 0x1ff; off%cs != 0 {
			return misaligned("refcount table[%d] names a refcount block at %#x, not a multiple of the %d-byte cluster size", i, off, cs)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("refcount table: %w", err)
	}
	return nil
}

// forEachEntry calls fn with the index and value of each big-endian 64-bit
// entry in the length bytes at off, reading tableChunk bytes at a time.
func forEachEntry(f io.ReaderAt, off, length uint64, fn func(i, e uint64) error) error {
	buf := make([]byte, min(length, tableChunk))
	for done := uint64(0); done < length; {
		n := min(length-done, tableChunk)
		if _, err := f.ReadAt(buf[:n], int64(off+done)); err != nil {
			return err
		}
		for j := uint64(0); j+8 <= n; j += 8 {
			if err := fn((done+j)/8, binary.BigEndian.Uint64(buf[j:])); err != nil {
				return err
			}
		}
		done += n
	}
	return nil
}
