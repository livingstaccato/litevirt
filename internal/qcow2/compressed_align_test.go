package qcow2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// compressedSource writes a sparse raw file of virtualSize bytes holding a
// compressible, non-zero pattern in each of the given clusters, and a qcow2
// overlay declaring it as a raw backing. Converting the overlay is a
// compressed convert of exactly that content.
func compressedSource(t *testing.T, dir string, virtualSize, clusterSize uint64, clusters []uint64) (raw, overlay string) {
	t.Helper()
	raw = filepath.Join(dir, "src.raw")
	overlay = filepath.Join(dir, "src.qcow2")
	f, err := os.Create(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(virtualSize)); err != nil {
		t.Fatal(err)
	}
	for _, c := range clusters {
		// Varies per cluster, so every compressed run has its own length
		// and the write position lands mid-cluster.
		pat := bytes.Repeat([]byte(fmt.Sprintf("litevirt cluster %d ", c)), int(clusterSize)/8)
		if _, err := f.WriteAt(pat[:clusterSize], int64(c*clusterSize)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBackingFormat(overlay, raw, "raw", virtualSize, nil); err != nil {
		t.Fatal(err)
	}
	return raw, overlay
}

// assertLayoutAligned walks an image independently of Check and fails on any
// offset the qcow2 spec requires to be cluster-aligned that is not: the L1
// and refcount table offsets in the header, every L1 entry (an L2 table),
// every standard L2 entry (a data cluster) and every refcount table entry (a
// refcount block). It returns the number of L2 tables and of compressed
// entries, so a caller can show the case it means to cover was reached.
func assertLayoutAligned(t *testing.T, path string) (l2Tables, compressed int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	cs := h.ClusterSize()
	if h.L1TableOffset%cs != 0 {
		t.Errorf("header l1_table_offset %#x not cluster-aligned (%d)", h.L1TableOffset, cs)
	}
	if h.RefcountTableOffset%cs != 0 {
		t.Errorf("header refcount_table_offset %#x not cluster-aligned (%d)", h.RefcountTableOffset, cs)
	}
	l1 := make([]byte, uint64(h.L1Size)*8)
	if _, err := f.ReadAt(l1, int64(h.L1TableOffset)); err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < uint64(h.L1Size); i++ {
		l2Off := binary.BigEndian.Uint64(l1[i*8:]) & 0x00fffffffffffe00
		if l2Off == 0 {
			continue
		}
		l2Tables++
		if l2Off%cs != 0 {
			t.Errorf("L1[%d] -> L2 table at %#x, not cluster-aligned (%d)", i, l2Off, cs)
			continue
		}
		l2 := make([]byte, cs)
		if _, err := f.ReadAt(l2, int64(l2Off)); err != nil {
			t.Fatal(err)
		}
		for j := uint64(0); j < cs/8; j++ {
			e := binary.BigEndian.Uint64(l2[j*8:])
			if e == 0 {
				continue
			}
			if e&(1<<62) != 0 {
				compressed++
				continue
			}
			if d := e & 0x00fffffffffffe00; d%cs != 0 {
				t.Errorf("L2[%d][%d] -> data at %#x, not cluster-aligned (%d)", i, j, d, cs)
			}
		}
	}
	rct := make([]byte, uint64(h.RefcountTableClusters)*cs)
	if _, err := f.ReadAt(rct, int64(h.RefcountTableOffset)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i+8 <= len(rct); i += 8 {
		if b := binary.BigEndian.Uint64(rct[i:]); b%cs != 0 {
			t.Errorf("refcount table[%d] -> block at %#x, not cluster-aligned (%d)", i/8, b, cs)
		}
	}
	return l2Tables, compressed
}

// compressedCases put data under more than one L2 table, the shape `lv image
// build` corrupted: the first L2 table is allocated at an aligned offset, and
// every later one after a compressed write.
var compressedCases = []struct {
	name        string
	clusterBits uint32
	virtual     uint64
	clusters    []uint64
}{
	// 4 KiB clusters: one L2 table covers 2 MiB.
	{"4KiB-clusters", 12, 8 << 20, []uint64{0, 1, 512, 513, 1024, 2047}},
	// The default 64 KiB clusters: one L2 table covers 512 MiB, the size
	// the lab saw the damage start at.
	{"64KiB-clusters", 0, 640 << 20, []uint64{0, 1, 8192, 8193, 10239}},
}

// A compressed convert of an image under more than one L2 table must place
// every L2 table at a cluster boundary. It used to place each one after the
// first at whatever 512-byte boundary the last compressed cluster ended on,
// which qemu refuses as "L2 table offset ... unaligned" — and Convert's own
// Check passed it.
func TestConvertCompressed_MultipleL2TablesAreClusterAligned(t *testing.T) {
	for _, tc := range compressedCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := &Options{ClusterBits: tc.clusterBits}
			cs := opts.clusterSize()
			_, src := compressedSource(t, dir, tc.virtual, cs, tc.clusters)
			dst := filepath.Join(dir, "dst.qcow2")
			if err := Convert(context.Background(), src, dst, opts); err != nil {
				t.Fatalf("Convert: %v", err)
			}
			l2Tables, compressed := assertLayoutAligned(t, dst)
			if l2Tables < 2 {
				t.Fatalf("case reached %d L2 tables, needs at least 2 to cover the bug", l2Tables)
			}
			if compressed != len(tc.clusters) {
				t.Fatalf("%d compressed clusters, want %d: the case must be a compressed convert", compressed, len(tc.clusters))
			}
			// The content survives (read back through this package).
			chain, err := openChain(dst, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer closeChain(chain)
			for _, c := range tc.clusters {
				data, ok, err := readChainCluster(chain, c*cs, cs)
				if err != nil || !ok {
					t.Fatalf("cluster %d: allocated=%v err=%v", c, ok, err)
				}
				want := bytes.Repeat([]byte(fmt.Sprintf("litevirt cluster %d ", c)), int(cs)/8)[:cs]
				if !bytes.Equal(data, want) {
					t.Fatalf("cluster %d: content differs after convert", c)
				}
			}
		})
	}
}

// qemu is the oracle the bug report came from: its check and a compare
// against the raw source must both pass on a compressed multi-L2 convert.
// Skips without qemu-img.
func TestQEMUCompat_ConvertCompressedMultipleL2Tables(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	for _, tc := range compressedCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := &Options{ClusterBits: tc.clusterBits}
			raw, src := compressedSource(t, dir, tc.virtual, opts.clusterSize(), tc.clusters)
			dst := filepath.Join(dir, "dst.qcow2")
			if err := Convert(context.Background(), src, dst, opts); err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if out, err := exec.Command("qemu-img", "check", dst).CombinedOutput(); err != nil {
				t.Fatalf("qemu-img check: %v\n%s", err, out)
			}
			if out, err := exec.Command("qemu-img", "compare", "-f", "raw", "-F", "qcow2", raw, dst).CombinedOutput(); err != nil {
				t.Fatalf("qemu-img compare raw source vs converted image: %v\n%s", err, out)
			}
		})
	}
}

// convertedFixture returns a converted 4 KiB-cluster image with data under
// three L2 tables, compressed unless uncompressed is set.
func convertedFixture(t *testing.T, uncompressed bool) string {
	t.Helper()
	dir := t.TempDir()
	_, src := compressedSource(t, dir, 8<<20, 4096, []uint64{0, 1, 512, 1024})
	dst := filepath.Join(dir, "dst.qcow2")
	if err := Convert(context.Background(), src, dst, &Options{ClusterBits: 12, Uncompressed: uncompressed}); err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return dst
}

// rewriteRefcounts recomputes the refcounts of a patched image with the
// writer's own rebuild, so the only thing wrong with it is the patch: the
// state the old writer left, where the refcounts and Check agreed with each
// other about a layout qemu refuses.
func rewriteRefcounts(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := rebuildRefcounts(f, h, uint64(st.Size()), uint32(1)<<h.RefcountOrder); err != nil {
		t.Fatal(err)
	}
}

func put64(t *testing.T, path string, off int64, v uint64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatal(err)
	}
}

func get64(t *testing.T, path string, off int64) uint64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b [8]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint64(b[:])
}

// appendUnaligned copies length bytes from off to a new offset past the end of the
// file, 512 bytes past a cluster boundary, and returns that offset.
func appendUnaligned(t *testing.T, path string, off int64, length, cs uint64) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	at := (uint64(len(b))+cs-1)/cs*cs + 512
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(b[off:uint64(off)+length], int64(at)); err != nil {
		t.Fatal(err)
	}
	return at
}

// Check refuses an image with any table or cluster at an offset the qcow2
// spec requires cluster-aligned, and says so — with the refcounts otherwise
// consistent, which is how the old `lv image build` output looked to it.
func TestCheck_RejectsUnalignedMetadata(t *testing.T) {
	const cs = 4096
	cases := []struct {
		name         string
		uncompressed bool
		patch        func(t *testing.T, path string, h *Header)
	}{
		{"L2 table named by L1", false, func(t *testing.T, p string, h *Header) {
			// L1[1]: the second L2 table, moved the way the old writer
			// placed it — sector-aligned, inside a cluster.
			e := get64(t, p, int64(h.L1TableOffset)+8)
			at := appendUnaligned(t, p, int64(e&0x00fffffffffffe00), cs, cs)
			put64(t, p, int64(h.L1TableOffset)+8, at|1<<63)
			rewriteRefcounts(t, p)
		}},
		{"data cluster named by L2", true, func(t *testing.T, p string, h *Header) {
			l2 := get64(t, p, int64(h.L1TableOffset)) & 0x00fffffffffffe00
			d := get64(t, p, int64(l2)) & 0x00fffffffffffe00
			at := appendUnaligned(t, p, int64(d), cs, cs)
			put64(t, p, int64(l2), at|1<<63)
			rewriteRefcounts(t, p)
		}},
		{"refcount block named by the refcount table", false, func(t *testing.T, p string, h *Header) {
			b := get64(t, p, int64(h.RefcountTableOffset))
			at := appendUnaligned(t, p, int64(b), cs, cs)
			put64(t, p, int64(h.RefcountTableOffset), at)
		}},
		{"L1 table named by the header", false, func(t *testing.T, p string, h *Header) {
			put64(t, p, 40, h.L1TableOffset+512)
		}},
		{"refcount table named by the header", false, func(t *testing.T, p string, h *Header) {
			put64(t, p, 48, h.RefcountTableOffset+512)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := convertedFixture(t, tc.uncompressed)
			if err := Check(p); err != nil {
				t.Fatalf("fixture fails Check before the patch: %v", err)
			}
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			h, err := readHeader(f)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			tc.patch(t, p, h)
			err = Check(p)
			if !errors.Is(err, ErrMisaligned) {
				t.Fatalf("Check = %v, want ErrMisaligned", err)
			}
			if !strings.Contains(err.Error(), "cluster") {
				t.Fatalf("Check error does not name the cluster alignment: %v", err)
			}
		})
	}
}

// AssertAligned is the cheap use-time check (header, L1 and refcount table
// only): it finds the damage the old `lv image build` left, and passes the
// images this package writes and non-qcow2 files.
func TestAssertAligned(t *testing.T) {
	good := convertedFixture(t, false)
	if err := AssertAligned(good); err != nil {
		t.Fatalf("AssertAligned on a good image: %v", err)
	}
	notQcow2 := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(notQcow2, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AssertAligned(notQcow2); err != nil {
		t.Fatalf("AssertAligned on a raw file: %v", err)
	}

	bad := convertedFixture(t, false)
	f, err := os.Open(bad)
	if err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	e := get64(t, bad, int64(h.L1TableOffset)+8)
	put64(t, bad, int64(h.L1TableOffset)+8, (e&0x00fffffffffffe00+512)|1<<63)
	if err := AssertAligned(bad); !errors.Is(err, ErrMisaligned) {
		t.Fatalf("AssertAligned on an unaligned L2 table = %v, want ErrMisaligned", err)
	}
}
