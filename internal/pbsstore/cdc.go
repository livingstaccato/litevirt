package pbsstore

import (
	"errors"
	"io"
)

// Content-defined chunking.
//
// PushDisk cuts its stream into fixed ChunkSize windows, which is right for a
// disk image: a write changes bytes in place, so every window but the written
// ones keeps its offset and its id. A tar stream is not like that. A file that
// grows by one byte shifts every later byte of the archive, so every later
// fixed window changes and its chunk is new: an archive of a container whose log
// grew is a near-complete resend against an archive taken a minute earlier.
//
// Here a chunk ends where the content says so instead: a rolling hash over the
// last 64 bytes is tested at every byte, and a chunk ends where it matches. An
// insertion or a size change moves only the boundaries near it; past the next
// match the cuts fall where they fell before, on the same bytes, so the chunks
// there have the same ids and dedup against what the target already holds.
//
// The chunks it produces are ordinary ChunkRefs (offset and size, size never
// above ChunkSize), so a manifest built this way is read, validated, synced and
// restored by every build exactly as a fixed-size one is. The gear table and the
// parameters below decide where the cuts fall; changing them does not break a
// restore, it only makes the next archive share fewer chunks with the earlier
// ones.
const (
	// cdcMinSize is the shortest chunk (except a stream's last), and where the
	// hash starts looking: cuts never fall closer together than this.
	cdcMinSize = 256 << 10
	// cdcMaskBits sets the average chunk at about 2^cdcMaskBits bytes past the
	// minimum (1 MiB).
	cdcMaskBits = 20
	// cdcMaxSize is the longest chunk: a stream with no match for this long (a
	// run of zeroes) is cut here, which keeps every chunk within ChunkSize.
	cdcMaxSize = ChunkSize
)

// cdcMask tests the hash's high bits: the gear hash shifts left, so its high
// bits depend on the whole 64-byte window, its low bits only on the last few.
const cdcMask = uint64(1<<cdcMaskBits-1) << (64 - cdcMaskBits)

// gearTable maps each byte value to a fixed pseudo-random word (splitmix64 from
// a fixed seed). It is part of the chunk boundary function: frozen.
var gearTable = func() (t [256]uint64) {
	x := uint64(0x6c69746576697274) // "litevirt"
	for i := range t {
		x += 0x9e3779b97f4a7c15
		z := x
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		t[i] = z ^ (z >> 31)
	}
	return t
}()

// cdcCut returns the length of the chunk that starts at data[0]. data holds at
// least cdcMaxSize bytes unless it is the stream's tail.
func cdcCut(data []byte) int {
	n := len(data)
	if n <= cdcMinSize {
		return n
	}
	if n > cdcMaxSize {
		n = cdcMaxSize
	}
	var h uint64
	for i := cdcMinSize; i < n; i++ {
		h = (h << 1) + gearTable[data[i]]
		if h&cdcMask == 0 {
			return i + 1
		}
	}
	return n
}

// ReadChunksContentDefined streams r as content-defined chunks (see above),
// calling fn with each chunk's offset in the stream and its bytes. The slice is
// reused: fn must not retain it.
func ReadChunksContentDefined(r io.Reader, fn func(offset int64, data []byte) error) error {
	buf := make([]byte, 2*cdcMaxSize)
	start, end := 0, 0
	eof := false
	var off int64
	for {
		if !eof && end-start < cdcMaxSize {
			if start > 0 {
				copy(buf, buf[start:end])
				end -= start
				start = 0
			}
			for !eof && end < len(buf) {
				n, err := r.Read(buf[end:])
				end += n
				switch {
				case errors.Is(err, io.EOF):
					eof = true
				case err != nil:
					return err
				}
			}
		}
		if end == start {
			return nil
		}
		c := cdcCut(buf[start:end])
		if err := fn(off, buf[start:start+c]); err != nil {
			return err
		}
		off += int64(c)
		start += c
	}
}
