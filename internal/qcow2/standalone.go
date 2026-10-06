package qcow2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// incompatExternalDataFile is qcow2 v3 incompatible feature bit 2: guest data
// lives in another file, named by a header extension.
const incompatExternalDataFile = 1 << 2

// extDataFileName is the qcow2 header extension holding the external data
// file's name.
const extDataFileName = 0x44415441

// hasHeaderExtension walks the header extensions that follow a v3 header of
// headerLen bytes, within head, and reports whether one of type want exists.
// A list that runs past head is treated as present (refuse what cannot be
// read).
func hasHeaderExtension(head []byte, headerLen int, want uint32) bool {
	off := headerLen
	if off < 104 {
		off = 104
	}
	for i := 0; i < 64; i++ {
		if off+8 > len(head) {
			return true
		}
		typ := binary.BigEndian.Uint32(head[off : off+4])
		n := int(binary.BigEndian.Uint32(head[off+4 : off+8]))
		if typ == 0 {
			return false
		}
		if typ == want {
			return true
		}
		off += 8 + (n+7)/8*8
	}
	return true
}

// AssertStandalone reports an error when the image at path would make qemu
// open another file: a qcow2 backing file or external data file, or a VMDK
// whose extents name other files. Images that arrive from a caller (an import,
// a pull) must be standalone; otherwise a guest booted from them reads
// whatever file the image header names on the host.
func AssertStandalone(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	head := make([]byte, 4096)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read image header: %w", err)
	}
	head = head[:n]

	switch {
	case len(head) >= 4 && binary.BigEndian.Uint32(head[0:4]) == Magic:
		if len(head) < 20 {
			return fmt.Errorf("truncated qcow2 header")
		}
		if binary.BigEndian.Uint64(head[8:16]) != 0 || binary.BigEndian.Uint32(head[16:20]) != 0 {
			return fmt.Errorf("image names a backing file; only standalone images are accepted (flatten it first: qemu-img convert -O qcow2)")
		}
		if binary.BigEndian.Uint32(head[4:8]) >= 3 {
			if len(head) < 104 {
				return fmt.Errorf("truncated qcow2 v3 header")
			}
			if binary.BigEndian.Uint64(head[72:80])&incompatExternalDataFile != 0 {
				return fmt.Errorf("image keeps its data in an external file; only standalone images are accepted")
			}
			// The data file's NAME is a header extension; refuse an image that
			// carries one even with the feature bit cleared.
			if hasHeaderExtension(head, int(binary.BigEndian.Uint32(head[100:104])), extDataFileName) {
				return fmt.Errorf("image names an external data file; only standalone images are accepted")
			}
		}
	case bytes.HasPrefix(head, []byte("KDMV")), bytes.Contains(head, []byte("# Disk DescriptorFile")):
		return fmt.Errorf("VMDK images can name other files as extents; convert it to qcow2 or raw first")
	}
	return nil
}
