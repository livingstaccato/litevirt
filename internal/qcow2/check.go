package qcow2

import (
	"encoding/binary"
	"fmt"
	"os"
)

// checkModelledIncompat is the incompatible feature bits Check's layout model
// holds for: dirty (0), corrupt (1) and compression type (3).
const checkModelledIncompat = 1<<0 | 1<<1 | 1<<3

// Check validates the internal consistency of a qcow2 file: magic/version,
// L1/L2 table bounds, cluster alignment of every table and standard data
// cluster (ErrMisaligned), backing-file metadata, and — reconstructed from the active
// L1/L2/data plus the refcount metadata — that every referenced cluster's recorded
// refcount matches its reference count.
//
// SCOPE: this models the images THIS package writes (litevirt-native: no internal
// snapshots, no other shared-cluster qcow2 features). It is a fail-loud tripwire
// for the writer, NOT a general `qemu-img check` replacement — an image using
// features this writer never produces (internal snapshots, bitmaps, external data
// files) could legitimately have refcounts this reconstruction does not model.
func Check(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return CheckFile(f)
}

// CheckFile observes the caller-held original descriptor; it never reopens its path.
func CheckFile(f *os.File) error {

	h, err := readHeader(f)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fileSize := uint64(fi.Size())
	clusterSize := h.ClusterSize()

	// readHeader has already bounded cluster_bits and every header-controlled
	// offset/length against the file; validateHeaderRanges is the one copy of those
	// rules. This used to repeat them, and the copies drifted — the duplicate L1
	// bound here computed offset+length without an overflow check, so it accepted
	// exactly the wrapped range the shared version rejects.
	if err := validateHeaderRanges(h, fi.Size()); err != nil {
		return err
	}
	if h.Size == 0 {
		return fmt.Errorf("virtual size is 0")
	}
	// The walk below models the standard layout. An incompatible feature
	// that changes it (an external data file, extended L2 entries) would be
	// misread — a subcluster bitmap taken for an offset, say — and blamed on
	// the wrong cause, so it is refused by name. Dirty, corrupt and the
	// compression type leave the layout as it is.
	if h.Version >= 3 {
		if other := h.IncompatibleFeatures &^ checkModelledIncompat; other != 0 {
			return fmt.Errorf("unsupported qcow2 incompatible features %#x: this check does not model them", other)
		}
	}
	if h.RefcountOrder > 6 {
		return fmt.Errorf("invalid refcount_order %d", h.RefcountOrder)
	}

	l1Bytes := uint64(h.L1Size) * 8

	// Every table and data cluster sits on a cluster boundary (qcow2 spec).
	// The refcount model below cannot see a violation — it marks the cluster
	// an offset starts in, the same way the writer does — so a compressed
	// convert that put L2 tables at sector offsets passed this check while
	// qemu refused the image. Judged first, so the report names the cause.
	// This also bounds the refcount table (by the file and qemu's limit)
	// before it is read below.
	if err := checkTableAlignment(f, h, fileSize); err != nil {
		return err
	}
	rcTableBytes := uint64(h.RefcountTableClusters) * clusterSize

	refcountBits := uint32(1) << h.RefcountOrder
	entriesPerBlock := clusterSize * 8 / uint64(refcountBits)
	if entriesPerBlock == 0 {
		return fmt.Errorf("invalid refcount geometry (order %d, cluster %d)", h.RefcountOrder, clusterSize)
	}
	totalClusters := (fileSize + clusterSize - 1) / clusterSize

	// expected[c] counts how many times cluster c is referenced by the image
	// structure. It is built during the L1/L2 walk below and compared against the
	// on-disk refcounts at the end. This is the check that actually catches a
	// metadata cluster left uncounted (the create/resize refcount bugs) — the prior
	// Check validated only that offsets stayed in-bounds, so those bugs sailed
	// through and reached disk, where qemu later reused an in-use cluster.
	expected := make([]uint64, totalClusters)
	mark := func(cluster uint64) {
		if cluster < totalClusters {
			expected[cluster]++
		}
	}

	// Metadata clusters: header, refcount table, L1 table (refcount blocks are
	// marked after the table is read, below).
	mark(0)
	for i := uint64(0); i < uint64(h.RefcountTableClusters); i++ {
		mark(h.RefcountTableOffset/clusterSize + i)
	}
	l1Clusters := (l1Bytes + clusterSize - 1) / clusterSize
	for i := uint64(0); i < l1Clusters; i++ {
		mark(h.L1TableOffset/clusterSize + i)
	}

	// Validate L1 → L2 references are within file bounds and mark L2 + data clusters.
	l1 := make([]byte, l1Bytes)
	if _, err := f.ReadAt(l1, int64(h.L1TableOffset)); err != nil {
		return fmt.Errorf("read L1 table: %w", err)
	}

	for i := uint64(0); i < uint64(h.L1Size); i++ {
		l1Entry := binary.BigEndian.Uint64(l1[i*8 : i*8+8])
		l2Offset := l1Entry & 0x00fffffffffffe00
		if l2Offset == 0 {
			continue
		}
		if l2Offset+clusterSize > fileSize {
			return fmt.Errorf("L1[%d] points to L2 at %d, beyond file end %d",
				i, l2Offset, fileSize)
		}
		mark(l2Offset / clusterSize)

		// Validate L2 entries.
		l2 := make([]byte, clusterSize)
		if _, err := f.ReadAt(l2, int64(l2Offset)); err != nil {
			return fmt.Errorf("read L2 at %d: %w", l2Offset, err)
		}

		l2Entries := clusterSize / 8
		for j := uint64(0); j < l2Entries; j++ {
			l2Entry := binary.BigEndian.Uint64(l2[j*8 : j*8+8])
			if l2Entry == 0 {
				continue
			}
			if l2Entry&(1<<62) != 0 {
				// Compressed — validate host offset is within file.
				csizeShift := 62 - (h.ClusterBits - 8)
				csizeMask := (uint64(1) << (h.ClusterBits - 8)) - 1
				offsetMask := (uint64(1) << csizeShift) - 1
				sectors := ((l2Entry >> csizeShift) & csizeMask) + 1
				hostOffset := l2Entry & offsetMask
				// qemu's extent: the sectors counted from the one the run
				// starts in, less the bytes of it before the run. qemu
				// packs runs at byte offsets; this writer at sector ones.
				endByte := hostOffset + sectors*512 - hostOffset&511
				if endByte > fileSize {
					return fmt.Errorf("L2[%d][%d] compressed data at %d+%d exceeds file",
						i, j, hostOffset, sectors*512)
				}
				startCluster := hostOffset / clusterSize
				endCluster := (endByte + clusterSize - 1) / clusterSize
				for c := startCluster; c < endCluster; c++ {
					mark(c)
				}
			} else {
				hostOffset := l2Entry & 0x00fffffffffffe00
				if hostOffset%clusterSize != 0 {
					return misaligned("L2[%d][%d] names a data cluster at %#x, not a multiple of the %d-byte cluster size",
						i, j, hostOffset, clusterSize)
				}
				if hostOffset > 0 {
					if hostOffset+clusterSize > fileSize {
						return fmt.Errorf("L2[%d][%d] data cluster at %d exceeds file",
							i, j, hostOffset)
					}
					mark(hostOffset / clusterSize)
				}
			}
		}
	}

	// Validate refcount table entries and mark the refcount block clusters.
	rcTable := make([]byte, rcTableBytes)
	if _, err := f.ReadAt(rcTable, int64(h.RefcountTableOffset)); err != nil {
		return fmt.Errorf("read refcount table: %w", err)
	}

	rcEntries := rcTableBytes / 8
	blockOffsets := make([]uint64, rcEntries)
	for i := uint64(0); i < rcEntries; i++ {
		blockOffset := binary.BigEndian.Uint64(rcTable[i*8 : i*8+8])
		blockOffsets[i] = blockOffset
		if blockOffset == 0 {
			continue
		}
		if blockOffset+clusterSize > fileSize {
			return fmt.Errorf("refcount table[%d] points to block at %d, beyond file",
				i, blockOffset)
		}
		mark(blockOffset / clusterSize)
	}

	// Compare the reconstructed reference counts against the recorded refcounts.
	// A referenced cluster recorded with a LOWER refcount (typically 0) is the
	// corruption vector — qemu will hand it to a new allocation while it is in use.
	// A HIGHER recorded refcount is a leak (wasted space). Both mean the writer
	// produced an inconsistent image, so flag either.
	blockCache := make(map[uint64][]byte)
	for c := uint64(0); c < totalClusters; c++ {
		blockIdx := c / entriesPerBlock
		var actual uint64
		if blockIdx < rcEntries && blockOffsets[blockIdx] != 0 {
			blk, ok := blockCache[blockIdx]
			if !ok {
				blk = make([]byte, clusterSize)
				if _, err := f.ReadAt(blk, int64(blockOffsets[blockIdx])); err != nil {
					return fmt.Errorf("read refcount block %d: %w", blockIdx, err)
				}
				blockCache[blockIdx] = blk
			}
			actual = readRefcount(blk, c%entriesPerBlock, refcountBits)
		}
		if actual != expected[c] {
			return fmt.Errorf("refcount mismatch at cluster %d: recorded %d, referenced %d times",
				c, actual, expected[c])
		}
	}

	return nil
}
