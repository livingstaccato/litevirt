package pbsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// compressible returns n bytes that zstd shrinks a lot but that are not all
// one value (so the test does not depend on a degenerate input).
func compressible(n int) []byte {
	pat := []byte("litevirt backup chunk payload 0123456789 abcdefghijklmnopqrstuvwxyz\n")
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, pat...)
	}
	return out[:n]
}

func readRepoMeta(t *testing.T, root string) RepoMeta {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "repo.json"))
	if err != nil {
		t.Fatalf("read repo.json: %v", err)
	}
	var m RepoMeta
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse repo.json: %v", err)
	}
	return m
}

func onDiskChunk(t *testing.T, r *Repo, id string) []byte {
	t.Helper()
	b, err := os.ReadFile(r.chunkPath(id))
	if err != nil {
		t.Fatalf("read chunk file: %v", err)
	}
	return b
}

// A compressed repo is marked so a binary that cannot read compressed chunks
// refuses the WHOLE repo at Open, rather than reading a compressed chunk as
// corrupt plaintext (and reporting bit-rot on verify). Every release before
// compression supports schema_version 1 only.
func TestCompressedRepo_MarkedForOlderReaders(t *testing.T) {
	dir := t.TempDir()
	if _, err := InitUngated(dir, InitOptions{Compression: CompressionZstd}); err != nil {
		t.Fatalf("InitWithOptions: %v", err)
	}
	meta := readRepoMeta(t, dir)
	if meta.Compression != CompressionZstd {
		t.Fatalf("repo.json compression = %q, want %q", meta.Compression, CompressionZstd)
	}
	const lastSchemaWithoutCompression = 1
	if meta.SchemaVersion <= lastSchemaWithoutCompression {
		t.Fatalf("repo.json schema_version = %d; a pre-compression binary (max %d) would open it and misread compressed chunks",
			meta.SchemaVersion, lastSchemaWithoutCompression)
	}
	if _, err := Open(dir); err != nil {
		t.Fatalf("this build must open its own compressed repo: %v", err)
	}
}

// An uncompressed repo stays exactly what earlier releases wrote: schema 1, no
// compression key, chunk files that are the plaintext verbatim. This is what
// keeps every existing repo — and repos created with --compression none —
// readable by an older binary during a rolling upgrade.
func TestUncompressedRepo_StaysReadableByOlderReaders(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	meta := readRepoMeta(t, dir)
	if meta.SchemaVersion != 1 || meta.Compression != "" {
		t.Fatalf("plain Init wrote schema=%d compression=%q, want 1 and empty", meta.SchemaVersion, meta.Compression)
	}
	data := compressible(ChunkSize)
	id, _, err := r.PutChunk(data)
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if !bytes.Equal(onDiskChunk(t, r, id), data) {
		t.Fatal("an uncompressed repo stored a chunk that is not the plaintext verbatim; an older reader would see corruption")
	}
}

func TestCompressedRepo_ChunkIsSmallerOnDiskAndRoundTrips(t *testing.T) {
	r, err := InitUngated(t.TempDir(), InitOptions{Compression: CompressionZstd})
	if err != nil {
		t.Fatalf("InitWithOptions: %v", err)
	}
	data := compressible(ChunkSize)
	id, created, err := r.PutChunk(data)
	if err != nil || !created {
		t.Fatalf("PutChunk: created=%v err=%v", created, err)
	}
	if id != ChunkID(data) {
		t.Fatal("chunk id must stay the BLAKE3 of the plaintext, so dedup spans compressed and uncompressed repos")
	}
	stored := onDiskChunk(t, r, id)
	if len(stored) >= len(data)/4 {
		t.Fatalf("stored %d bytes for a highly compressible %d-byte chunk", len(stored), len(data))
	}
	got, err := r.GetChunk(id)
	if err != nil {
		t.Fatalf("GetChunk: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("compressed chunk did not round-trip")
	}
}

// Data zstd cannot shrink is stored raw — no expansion on already-compressed
// guest data.
func TestCompressedRepo_IncompressibleStoredRaw(t *testing.T) {
	r, err := InitUngated(t.TempDir(), InitOptions{Compression: CompressionZstd})
	if err != nil {
		t.Fatalf("InitWithOptions: %v", err)
	}
	data := randomBytes(t, 1<<20)
	id, _, err := r.PutChunk(data)
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if !bytes.Equal(onDiskChunk(t, r, id), data) {
		t.Fatal("incompressible chunk was not stored verbatim")
	}
	got, err := r.GetChunk(id)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("GetChunk: err=%v equal=%v", err, bytes.Equal(got, data))
	}
}

// Guest data is arbitrary: a raw chunk may begin with the compressed-chunk
// magic. The chunk id (BLAKE3 of the plaintext) decides which reading is the
// chunk, so such data still round-trips — whether it was stored raw by an
// earlier release or as incompressible data by this one.
func TestCompressedRepo_RawChunkThatLooksCompressed(t *testing.T) {
	for _, tc := range []struct {
		name string
		init func(string) (*Repo, error)
	}{
		{"uncompressed", Init},
		{"compressed", func(d string) (*Repo, error) { return InitUngated(d, InitOptions{Compression: CompressionZstd}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := tc.init(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			// A real zstd frame of OTHER content behind the magic: decoding it
			// succeeds, and only the id check tells the two readings apart.
			enc, _ := zstd.NewWriter(nil)
			frame := enc.EncodeAll([]byte("not this chunk"), nil)
			// Exactly magic||frame, nothing after it, so DecodeAll succeeds and
			// returns other bytes (trailing data would make the decode fail and
			// the test would never reach the id check).
			data := append(append([]byte(nil), compressedChunkMagic...), frame...)
			if _, _, err := zstdCodec(); err != nil {
				t.Fatal(err)
			}
			if pt, err := zstdDec.DecodeAll(data[len(compressedChunkMagic):], nil); err != nil || string(pt) != "not this chunk" {
				t.Fatalf("precondition: the planted frame must decode cleanly (pt=%q err=%v)", pt, err)
			}
			id := ChunkID(data)
			// Plant it raw, as an earlier release (or an incompressible put) would.
			if err := os.MkdirAll(filepath.Dir(r.chunkPath(id)), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(r.chunkPath(id), data, 0o640); err != nil {
				t.Fatal(err)
			}
			got, err := r.GetChunk(id)
			if err != nil {
				t.Fatalf("GetChunk: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("raw chunk beginning with the magic was returned decoded")
			}
		})
	}
}

// A stored frame that decodes past ChunkSize is refused without allocating
// its claimed size — chunk files are untrusted (a shared or synced repo).
func TestCompressedRepo_DecompressionBounded(t *testing.T) {
	r, err := InitUngated(t.TempDir(), InitOptions{Compression: CompressionZstd})
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, ChunkSize*4)
	enc, _ := zstd.NewWriter(nil)
	stored := append(append([]byte(nil), compressedChunkMagic...), enc.EncodeAll(big, nil)...)
	id := ChunkID(big)
	if err := os.MkdirAll(filepath.Dir(r.chunkPath(id)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.chunkPath(id), stored, 0o640); err != nil {
		t.Fatal(err)
	}
	// The decoder itself stops at ChunkSize: it never materializes the
	// claimed 16 MiB (the post-decode length check is only a backstop).
	if _, _, err := zstdCodec(); err != nil {
		t.Fatal(err)
	}
	if _, derr := zstdDec.DecodeAll(stored[len(compressedChunkMagic):], nil); derr == nil {
		t.Fatal("the shared decoder decoded a frame larger than ChunkSize; its memory ceiling is gone")
	}
	_, err = r.GetChunk(id)
	if err == nil {
		t.Fatal("a frame decoding to 4x ChunkSize was accepted")
	}
	if !errors.Is(err, ErrChunkMismatch) {
		t.Fatalf("want ErrChunkMismatch for an oversized frame, got %v", err)
	}
}

// Compression sits under encryption: the plaintext is compressed, then sealed.
func TestCompressedEncryptedRepo_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	r, err := InitUngated(dir, InitOptions{Encryption: EncryptionModeAESGCM, Compression: CompressionZstd})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetKey(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	src := compressible(ChunkSize*2 + 4321)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	stored := onDiskChunk(t, r, m.Chunks[0].ID)
	if len(stored) >= ChunkSize/4 {
		t.Fatalf("encrypted+compressed chunk is %d bytes; compression did not happen before sealing", len(stored))
	}
	if bytes.Contains(stored, []byte("litevirt backup chunk payload")) {
		t.Fatal("cleartext on disk in an encrypted repo")
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, src) {
		t.Fatal("encrypted+compressed round-trip mismatch")
	}
	// Reopened from disk, the repo still knows both modes.
	r2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.IsEncrypted() || r2.Compression() != CompressionZstd {
		t.Fatalf("reopened repo: encrypted=%v compression=%q", r2.IsEncrypted(), r2.Compression())
	}
}

// Turning compression on for an existing repo keeps every backup it already
// holds restorable, compresses new chunks, and marks the repo for older
// readers.
func TestSetCompression_UpgradesExistingRepo(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := compressible(ChunkSize + 100)
	mOld, err := PushDisk(context.Background(), r, bytes.NewReader(old), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-10-09T01:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetCompressionUngated(CompressionZstd); err != nil {
		t.Fatalf("SetCompression: %v", err)
	}
	meta := readRepoMeta(t, dir)
	if meta.Compression != CompressionZstd || meta.SchemaVersion < 2 {
		t.Fatalf("after SetCompression: schema=%d compression=%q", meta.SchemaVersion, meta.Compression)
	}

	r2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The pre-upgrade backup, stored raw, still restores.
	dst := filepath.Join(t.TempDir(), "old")
	if err := RestoreToFile(context.Background(), r2, mOld, dst, RestoreOptions{}); err != nil {
		t.Fatalf("restore pre-upgrade backup: %v", err)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, old) {
		t.Fatal("pre-upgrade backup changed")
	}
	// A new chunk is compressed.
	fresh := compressible(ChunkSize - 7)
	fresh[0] = 'X'
	id, _, err := r2.PutChunk(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(onDiskChunk(t, r2, id), compressedChunkMagic) {
		t.Fatal("a chunk written after SetCompression(zstd) is not compressed")
	}
	// Verify reads both kinds cleanly.
	if _, err := PushDisk(context.Background(), r2, bytes.NewReader(fresh), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := Verify(context.Background(), r2)
	if err != nil || len(st.Mismatches) != 0 || len(st.Missing) != 0 {
		t.Fatalf("verify after upgrade: %+v err=%v", st, err)
	}

	// Turning it off again stops compressing new chunks but cannot drop the
	// marker: compressed chunks are already in the repo.
	if err := r2.SetCompression(CompressionNone); err != nil {
		t.Fatal(err)
	}
	meta = readRepoMeta(t, dir)
	if meta.Compression != "" || meta.SchemaVersion < 2 {
		t.Fatalf("after SetCompression(none): schema=%d compression=%q (the schema marker must stay)", meta.SchemaVersion, meta.Compression)
	}
	plain := compressible(ChunkSize - 9)
	plain[0] = 'Y'
	id, _, err = r2.PutChunk(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDiskChunk(t, r2, id), plain) {
		t.Fatal("SetCompression(none) still compressed a new chunk")
	}
}

func TestInitWithOptions_RejectsUnknownCompression(t *testing.T) {
	_, err := InitWithOptions(t.TempDir(), InitOptions{Compression: "lz4"})
	if err == nil || !strings.Contains(err.Error(), "lz4") {
		t.Fatalf("want an error naming the unknown mode, got %v", err)
	}
}

// A repo from a future release is still refused with a message that says
// what to do.
func TestOpen_RefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatal(err)
	}
	meta := readRepoMeta(t, dir)
	meta.SchemaVersion = MaxRepoSchemaVersion + 1
	if err := writeJSONAtomic(filepath.Join(dir, "repo.json"), meta); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open accepted a repo newer than this build supports")
	}
}

// Sync between a compressed and an uncompressed repo moves plaintext, so a
// DR copy can differ in compression from its source.
func TestSyncRepo_AcrossCompressionModes(t *testing.T) {
	src, err := InitUngated(t.TempDir(), InitOptions{Compression: CompressionZstd})
	if err != nil {
		t.Fatal(err)
	}
	dst, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := compressible(ChunkSize + 55)
	m, err := PushDisk(context.Background(), src, bytes.NewReader(data), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T02:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SyncRepo(context.Background(), src, dst); err != nil {
		t.Fatalf("SyncRepo: %v", err)
	}
	if !bytes.Equal(onDiskChunk(t, dst, m.Chunks[0].ID), data[:ChunkSize]) {
		t.Fatal("the uncompressed destination stored a compressed chunk; its older readers could not read it")
	}
}

// zstd is the release feature backup_zstd's data: the ungated entry points
// refuse it, so only the grant-taking writers (and the explicitly named
// override) can make a repo compressed.
func TestUngatedWritersRefuseZstd(t *testing.T) {
	dir := t.TempDir()
	if _, err := InitWithOptions(filepath.Join(dir, "a"), InitOptions{Compression: CompressionZstd}); !errors.Is(err, ErrZstdNeedsGate) {
		t.Fatalf("InitWithOptions(zstd) = %v, want ErrZstdNeedsGate", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "repo.json")); err == nil {
		t.Fatal("a refused init created repo.json")
	}
	r, err := Init(filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetCompression(CompressionZstd); !errors.Is(err, ErrZstdNeedsGate) {
		t.Fatalf("SetCompression(zstd) = %v, want ErrZstdNeedsGate", err)
	}
	if r.Compression() != CompressionNone || r.Meta().SchemaVersion != 1 {
		t.Fatal("a refused SetCompression changed the repo")
	}
}
