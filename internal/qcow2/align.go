package qcow2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrMisaligned marks a qcow2 image naming a table or cluster at an offset
// the qcow2 spec requires to be cluster-aligned. qemu refuses such an image
// as corrupt ("L2 table offset ... unaligned"), so a guest booted from it
// sees I/O errors. `lv image build` wrote images like this from any disk
// whose data spans more than one L2 table (over 512 MiB at the default 64 KiB
// clusters) until the convert placed its L2 tables on cluster boundaries;
// such an image has to be built again. Nothing here repairs one.
var ErrMisaligned = errors.New("qcow2 metadata not cluster-aligned")

// misalignedHint is appended to every ErrMisaligned report.
const misalignedHint = "qemu refuses this image as corrupt; an image made by lv image build from a disk over 512 MiB before this was fixed looks like this, and must be built again"

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

// checkTableAlignment checks every offset the header, the L1 table and the
// refcount table of a fileSize-byte image hold against the cluster size: each names a whole cluster
// (or a run of them) in the qcow2 spec. Reserved low bits are masked off
// the way qemu masks them, so what is judged is the offset qemu would use.
func checkTableAlignment(f io.ReaderAt, h *Header, fileSize uint64) error {
	if err := checkHeaderAlignment(h); err != nil {
		return err
	}
	cs := h.ClusterSize()
	if h.L1Size > 0 {
		l1 := make([]byte, uint64(h.L1Size)*8)
		if _, err := f.ReadAt(l1, int64(h.L1TableOffset)); err != nil {
			return fmt.Errorf("read L1 table: %w", err)
		}
		for i := uint64(0); i < uint64(h.L1Size); i++ {
			if off := binary.BigEndian.Uint64(l1[i*8:]) & 0x00fffffffffffe00; off%cs != 0 {
				return misaligned("L1[%d] names an L2 table at %#x, not a multiple of the %d-byte cluster size", i, off, cs)
			}
		}
	}
	// Bounded by the file before it is allocated: the cluster count is the
	// header's to claim.
	rctBytes := uint64(h.RefcountTableClusters) * cs
	if end := h.RefcountTableOffset + rctBytes; end < h.RefcountTableOffset || end > fileSize {
		return fmt.Errorf("refcount table extends beyond file")
	}
	rct := make([]byte, rctBytes)
	if _, err := f.ReadAt(rct, int64(h.RefcountTableOffset)); err != nil {
		return fmt.Errorf("read refcount table: %w", err)
	}
	for i := 0; i+8 <= len(rct); i += 8 {
		if off := binary.BigEndian.Uint64(rct[i:]) &^ 0x1ff; off%cs != 0 {
			return misaligned("refcount table[%d] names a refcount block at %#x, not a multiple of the %d-byte cluster size", i/8, off, cs)
		}
	}
	return nil
}
