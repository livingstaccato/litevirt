package qcow2

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// extBackingFormat is the qcow2 header extension naming the backing file's
// format.
const extBackingFormat = 0xe2792aca

// BackingFormatExtensionCount reports how many backing-format header
// extensions the qcow2 image at path carries. A well-formed image has at most
// one; with two, this package's parser (first wins) and qemu (last wins) can
// disagree on the backing file's format, so a caller that judges a header and
// then hands the file to qemu must refuse more than one. A list that runs past
// the first 4 KiB is an error, never a guess.
func BackingFormatExtensionCount(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("read image header: %w", err)
	}
	head = head[:n]
	if len(head) < 72 || binary.BigEndian.Uint32(head[0:4]) != Magic {
		return 0, fmt.Errorf("not a qcow2 image")
	}
	off := 72 // v2: extensions follow the fixed 72-byte header
	if binary.BigEndian.Uint32(head[4:8]) >= 3 {
		if len(head) < 104 {
			return 0, fmt.Errorf("truncated qcow2 v3 header")
		}
		off = int(binary.BigEndian.Uint32(head[100:104]))
		if off < 104 {
			off = 104
		}
	}
	count := 0
	for i := 0; i < 64; i++ {
		if off+8 > len(head) {
			return 0, fmt.Errorf("header extensions run past the first 4 KiB")
		}
		typ := binary.BigEndian.Uint32(head[off : off+4])
		l := int(binary.BigEndian.Uint32(head[off+4 : off+8]))
		if typ == 0 {
			return count, nil
		}
		if typ == extBackingFormat {
			count++
		}
		off += 8 + (l+7)/8*8
	}
	return 0, fmt.Errorf("too many header extensions")
}
