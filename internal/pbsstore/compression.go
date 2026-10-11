package pbsstore

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// Chunk compression.
//
// A repo whose repo.json says "compression": "zstd" compresses each chunk's
// plaintext with zstd before it is sealed (when encrypted) and written. The
// chunk id stays the BLAKE3 of the PLAINTEXT, so dedup is unchanged and spans
// compressed and uncompressed repos, and every transfer (sync, peer streaming)
// still moves plaintext.
//
// Older readers. A release before compression supports repo schema_version 1
// only and reads a chunk file as the plaintext verbatim; handed a compressed
// chunk it would report a hash mismatch, i.e. "bit-rot", and its Verify would
// flag every compressed chunk. So a compressed repo carries
// schema_version 2, which every such release refuses at Open with "repository
// schema-version 2 newer than supported 1" — before it reads (or, in GC,
// deletes) anything. The marker is permanent: once compressed chunks may exist,
// turning compression off stops compressing new chunks but keeps schema 2.
// An uncompressed repo stays schema 1 and byte-identical to what earlier
// releases wrote, which is why compression is opt-in for an existing repo.
//
// Stored format of a compressed chunk: compressedChunkMagic || zstd frame.
// A chunk that zstd cannot shrink is stored raw. Guest data is arbitrary, so a
// raw chunk may itself begin with the magic; the id decides — a decoded result
// is used only if it hashes to the chunk id, otherwise the stored bytes must.

const (
	// CompressionNone is an uncompressed repo (the empty value in repo.json).
	CompressionNone = "none"
	// CompressionZstd compresses chunk plaintext with zstd.
	CompressionZstd = "zstd"

	// repoSchemaCompressed is the repo.json schema_version of a repo that may
	// hold compressed chunks. Releases before compression support 1 only.
	repoSchemaCompressed = 2
	// MaxRepoSchemaVersion is the newest repo.json schema this build opens.
	MaxRepoSchemaVersion = repoSchemaCompressed
)

// compressedChunkMagic prefixes every compressed chunk file (before
// encryption). "LVz" plus a format byte, so a later codec can take 0x02.
var compressedChunkMagic = []byte{'L', 'V', 'z', 0x01}

// NormalizeCompression maps a user-supplied mode to its repo.json value: ""
// for none, CompressionZstd for zstd.
func NormalizeCompression(mode string) (string, error) {
	switch mode {
	case "", CompressionNone:
		return "", nil
	case CompressionZstd:
		return CompressionZstd, nil
	default:
		return "", fmt.Errorf("unsupported compression mode %q (want %q or %q)", mode, CompressionZstd, CompressionNone)
	}
}

var (
	zstdOnce sync.Once
	zstdEnc  *zstd.Encoder
	zstdDec  *zstd.Decoder
	zstdErr  error
)

// zstdCodec returns the shared encoder/decoder. EncodeAll and DecodeAll are
// safe for concurrent use. The decoder's memory ceiling bounds what one
// stored frame can make us allocate: a chunk is at most ChunkSize, so a frame
// claiming more is refused rather than decoded.
func zstdCodec() (*zstd.Encoder, *zstd.Decoder, error) {
	zstdOnce.Do(func() {
		zstdEnc, zstdErr = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderConcurrency(1))
		if zstdErr != nil {
			return
		}
		zstdDec, zstdErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(0),
			zstd.WithDecoderMaxMemory(ChunkSize),
			zstd.WithDecoderMaxWindow(ChunkSize))
	})
	return zstdEnc, zstdDec, zstdErr
}

// compressForStorage returns what PutChunk stores for plaintext before
// encryption: the compressed form when the repo compresses and it is
// smaller, otherwise the plaintext itself.
func (r *Repo) compressForStorage(plaintext []byte) ([]byte, error) {
	if r.meta.Compression != CompressionZstd {
		return plaintext, nil
	}
	enc, _, err := zstdCodec()
	if err != nil {
		return nil, fmt.Errorf("zstd encoder: %w", err)
	}
	out := make([]byte, len(compressedChunkMagic), len(compressedChunkMagic)+len(plaintext)/2)
	copy(out, compressedChunkMagic)
	out = enc.EncodeAll(plaintext, out)
	if len(out) >= len(plaintext) {
		return plaintext, nil
	}
	return out, nil
}

// decodeStored turns a chunk file's (decrypted) bytes back into the plaintext
// whose BLAKE3 is id. It returns ErrChunkMismatch when neither reading
// matches. Decoding is attempted in any repo — the id makes it unambiguous —
// so a repo whose compression was turned off still reads what it holds.
func decodeStored(id string, stored []byte) ([]byte, error) {
	if bytes.HasPrefix(stored, compressedChunkMagic) {
		if _, dec, err := zstdCodec(); err == nil {
			if pt, derr := dec.DecodeAll(stored[len(compressedChunkMagic):], nil); derr == nil &&
				len(pt) <= ChunkSize && ChunkID(pt) == id {
				return pt, nil
			}
		}
	}
	if got := ChunkID(stored); got != id {
		return nil, fmt.Errorf("%w: stored=%s actual=%s", ErrChunkMismatch, id, got)
	}
	return stored, nil
}

// Compression reports the repo's compression mode: CompressionZstd, or
// CompressionNone.
func (r *Repo) Compression() string {
	if r.meta.Compression == "" {
		return CompressionNone
	}
	return r.meta.Compression
}

// SetCompression changes whether NEW chunks are compressed and persists it in
// repo.json. Turning compression on raises the repo to schema_version 2, so
// releases before compression refuse the repo at Open instead of misreading
// it; that cannot be undone, because compressed chunks may exist from then on.
// Turning it off only stops compressing new chunks. Existing chunks are never
// rewritten either way.
//
// Turning it ON is refused here: that is the release feature backup_zstd's
// data, written through EnableCompressionWithGrant (the daemon's gate) or the
// operator's explicit --force override, SetCompressionUngated.
func (r *Repo) SetCompression(mode string) error {
	if mode == CompressionZstd {
		return ErrZstdNeedsGate
	}
	return r.setCompression(mode)
}

func (r *Repo) setCompression(mode string) error {
	norm, err := NormalizeCompression(mode)
	if err != nil {
		return err
	}
	meta := r.meta
	meta.Compression = norm
	if norm != "" && meta.SchemaVersion < repoSchemaCompressed {
		meta.SchemaVersion = repoSchemaCompressed
	}
	if err := writeJSONAtomic(metaPath(r.root), meta); err != nil {
		return fmt.Errorf("write repo.json: %w", err)
	}
	r.meta = meta
	return nil
}

// InitWithGrant creates a zstd-compressed repository. It is a writer of the
// release feature backup_zstd: a compressed repo is schema_version 2, which a
// release without compression refuses, so the repo's creation is the data the
// feature's used bit must precede. g comes from the release-feature gate
// (grpcapi.Server.WithReleaseFeature). opts.Compression must be zstd; an
// uncompressed repo needs no grant and is InitWithOptions.
func InitWithGrant(root string, opts InitOptions, g capabilities.FeatureGrant) (*Repo, error) {
	if err := g.Check(capabilities.FeatureBackupZstd); err != nil {
		return nil, err
	}
	if opts.Compression != CompressionZstd {
		return nil, fmt.Errorf("InitWithGrant creates a %s repository, not %q", CompressionZstd, opts.Compression)
	}
	return initRepo(root, opts)
}

// InitUngated creates a repository of any format with NO release-feature gate
// and so records no use of backup_zstd. It exists for `lv backup repo init
// --force`, the operator's override for a repository no older host reads; the
// name is the warning. Nothing else may call it.
func InitUngated(root string, opts InitOptions) (*Repo, error) { return initRepo(root, opts) }

// SetCompressionUngated is SetCompression without the zstd refusal and with no
// gate: the `set-compression zstd --force` override. See InitUngated.
func (r *Repo) SetCompressionUngated(mode string) error { return r.setCompression(mode) }

// ErrZstdNeedsGate is returned when zstd is requested through a function that
// does not pass the release-feature gate.
var ErrZstdNeedsGate = errors.New("zstd compression is the release feature backup_zstd: create it through the daemon's gate (InitWithGrant, EnableCompressionWithGrant) or the explicit --force override")

// EnableCompressionWithGrant turns zstd on for an existing repository, raising
// it to schema_version 2: the other writer of backup_zstd's data. See
// InitWithGrant. Turning compression off is SetCompression and needs no grant.
func (r *Repo) EnableCompressionWithGrant(g capabilities.FeatureGrant) error {
	if err := g.Check(capabilities.FeatureBackupZstd); err != nil {
		return err
	}
	return r.setCompression(CompressionZstd)
}
