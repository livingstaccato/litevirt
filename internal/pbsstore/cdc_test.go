package pbsstore

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"path/filepath"
	"testing"
)

func cdcData(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func pushCDC(t *testing.T, repo *Repo, ts string, data []byte) *Manifest {
	t.Helper()
	m, err := PushDisk(context.Background(), repo, bytes.NewReader(data), PushOptions{
		VMName: "web", DiskName: "rootfs", Timestamp: ts, ContentDefined: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newChunkIDs(prev, next *Manifest) (fresh, total int) {
	have := map[string]bool{}
	for _, c := range prev.Chunks {
		have[c.ID] = true
	}
	for _, c := range next.Chunks {
		if !have[c.ID] {
			fresh++
		}
	}
	return fresh, len(next.Chunks)
}

// The property container replication relies on: an archive taken after a
// change in the middle of the stream (a file that grew shifts every later byte
// of a tar) shares every chunk past the change with the archive taken before
// it, so only the chunks around the change are new.
func TestPushDiskContentDefined_AnInsertionChangesOnlyTheChunksAroundIt(t *testing.T) {
	repo, err := Init(filepath.Join(t.TempDir(), "r"))
	if err != nil {
		t.Fatal(err)
	}
	before := cdcData(1, 24<<20)
	after := append(append(append([]byte(nil), before[:5<<20]...), cdcData(2, 1000)...), before[5<<20:]...)

	m1 := pushCDC(t, repo, "2026-01-01T00:00:00Z", before)
	m2 := pushCDC(t, repo, "2026-01-01T00:01:00Z", after)
	fresh, total := newChunkIDs(m1, m2)
	if fresh > 2 {
		t.Fatalf("a 1000-byte insertion made %d of %d chunks new; content-defined cuts resynchronise after it", fresh, total)
	}
	if total < 12 {
		t.Fatalf("24 MiB cut into only %d chunks; the average must be near 1 MiB for this test to mean anything", total)
	}
}

// Every chunk respects the bounds the validator and every reader assume, the
// cuts are deterministic, and the stream reads back byte for byte.
func TestPushDiskContentDefined_BoundsAndRoundTrip(t *testing.T) {
	repo, err := Init(filepath.Join(t.TempDir(), "r"))
	if err != nil {
		t.Fatal(err)
	}
	data := append(cdcData(3, 9<<20), make([]byte, 9<<20)...) // a zero run forces max-size cuts
	m := pushCDC(t, repo, "2026-01-01T00:00:00Z", data)
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("a content-defined manifest must validate as any other: %v", err)
	}
	for i, c := range m.Chunks {
		if c.Size > cdcMaxSize || (c.Size < cdcMinSize && i != len(m.Chunks)-1) {
			t.Fatalf("chunk %d size %d outside [%d, %d]", i, c.Size, cdcMinSize, cdcMaxSize)
		}
	}
	again := pushCDC(t, repo, "2026-01-01T00:01:00Z", data)
	if fresh, _ := newChunkIDs(m, again); fresh != 0 {
		t.Fatalf("the same stream cut differently the second time (%d new chunks)", fresh)
	}
	r, err := NewManifestReader(repo, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("the content-defined manifest does not read back as the stream")
	}
}

// A stream shorter than the minimum is one chunk, and an empty one none.
func TestReadChunksContentDefined_ShortStreams(t *testing.T) {
	for _, n := range []int{0, 1, cdcMinSize} {
		var sizes []int
		if err := ReadChunksContentDefined(bytes.NewReader(make([]byte, n)), func(_ int64, d []byte) error {
			sizes = append(sizes, len(d))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		want := 1
		if n == 0 {
			want = 0
		}
		if len(sizes) != want || (want == 1 && sizes[0] != n) {
			t.Fatalf("stream of %d bytes: chunks %v", n, sizes)
		}
	}
}
