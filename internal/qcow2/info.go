package qcow2

import (
	"encoding/binary"
	"fmt"
	"os"
)

// ImageInfo holds metadata read from a qcow2 image.
type ImageInfo struct {
	VirtualSize   uint64
	ClusterSize   uint32
	BackingFile   string
	BackingFormat string
	ActualSize    int64 // on-disk size from os.Stat
	Format        string
}

// Info reads metadata from a qcow2 image without opening the full file.
func Info(path string) (*ImageInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h, err := readHeader(f)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat qcow2 image: %w", err)
	}
	if err := validateHeaderRanges(h, st.Size()); err != nil {
		return nil, err
	}

	info := &ImageInfo{
		VirtualSize: h.Size,
		ClusterSize: uint32(h.ClusterSize()),
		Format:      "qcow2",
	}

	// Read backing file path.
	if h.BackingFileOffset > 0 && h.BackingFileSize > 0 {
		buf := make([]byte, h.BackingFileSize)
		if _, err := f.ReadAt(buf, int64(h.BackingFileOffset)); err != nil {
			return nil, fmt.Errorf("read backing file path: %w", err)
		}
		info.BackingFile = string(buf)
	}

	// Parse header extensions for backing format.
	info.BackingFormat = readBackingFormat(f, h)

	// Actual size on disk.
	info.ActualSize = st.Size()

	return info, nil
}

// readBackingFormat scans header extensions for the backing format string.
//
// The extensions start where BackingFormatExtensionCount and qemu start them:
// right after the 72-byte v2 header, or after a v3 header's declared length
// (at least 104). A v2 header has no header_length field — bytes 100-104 are
// already the extension area — so reading it there would let this package
// and qemu disagree on the backing format.
func readBackingFormat(f *os.File, h *Header) string {
	offset := int64(72)
	if h.Version >= 3 {
		offset = int64(h.HeaderLength)
		if offset < 104 {
			offset = 104
		}
	}
	clusterEnd := int64(h.ClusterSize())

	for offset+8 <= clusterEnd {
		var extHdr [8]byte
		if _, err := f.ReadAt(extHdr[:], offset); err != nil {
			break
		}
		extType := binary.BigEndian.Uint32(extHdr[0:4])
		extLen := binary.BigEndian.Uint32(extHdr[4:8])

		if extType == ExtEndOfArea {
			break
		}

		padded := (extLen + 7) &^ 7
		if extType == ExtBackingFormat && extLen > 0 && extLen < 256 {
			data := make([]byte, extLen)
			if _, err := f.ReadAt(data, offset+8); err == nil {
				return string(data)
			}
		}

		offset += 8 + int64(padded)
	}

	return ""
}
