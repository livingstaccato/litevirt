package corrosion

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"
)

// A cut record contains raw framed SQL values, not base64-wrapped JSON. This
// leaves 512 KiB above a full 3 MiB prefix for receipt/column framing. It is a
// STORAGE bound; a future page must separately budget its entire wire wrapper.
const maxAutomationCutRecordBytes = 7 << 19
const maxAutomationCutMetadataBytes = 128 << 10
const automationCutCodec = 1

// Deliberately independent of CurrentSchemaVersion: new provenance requires an
// explicit inventory review. A future live schema cannot relabel an old cut.
const automationCutSourceSchema = 69

type automationCutInventory struct {
	Section string
	Codec   int
	Records int64
	Bytes   int64
	Digest  string
}
type automationCutMetadata struct {
	Codec        int
	SourceSchema int
	ID           string
	Source       string
	Incarnation  string
	Generation   int64
	MembersHash  string
	Head         AutomationPrefix
	Inventory    []automationCutInventory
}

func automationCutFrame(domain string, parts ...[]byte) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("LVCUT\x01")
	all := append([][]byte{[]byte(domain)}, parts...)
	for _, p := range all {
		if len(p) > maxAutomationCutRecordBytes || b.Len() > maxAutomationCutRecordBytes-4-len(p) {
			return nil, fmt.Errorf("automation cut record exceeds bound")
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(len(p)))
		b.Write(p)
	}
	return b.Bytes(), nil
}
func automationCutInteger(n int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return b[:]
}

// Field order/types are part of the section's v1 codec. No map iteration or
// SQL JSON conversion can silently coerce BLOBs, NULLs or accepted payloads.
func encodeAutomationCutRecord(section string, ordinal int64, row Row) ([]byte, error) {
	if ordinal <= 0 {
		return nil, fmt.Errorf("invalid cut ordinal")
	}
	parts := [][]byte{automationCutInteger(ordinal)}
	for _, v := range row.Values {
		var p []byte
		switch v := v.(type) {
		case nil:
			p = []byte{0}
		case int64:
			p = append([]byte{1}, automationCutInteger(v)...)
		case string:
			if !utf8.ValidString(v) {
				return nil, fmt.Errorf("invalid cut text")
			}
			p = append([]byte{2}, []byte(v)...)
		case []byte:
			p = append([]byte{3}, v...)
		default:
			return nil, fmt.Errorf("unsupported cut field type %T", v)
		}
		parts = append(parts, p)
	}
	return automationCutFrame(section, parts...)
}
func automationCutRoot(m automationCutMetadata) ([]byte, string, error) {
	b, err := json.Marshal(m)
	if err != nil || len(b) > maxAutomationCutMetadataBytes {
		return nil, "", fmt.Errorf("cut metadata exceeds bound")
	}
	framed, err := automationCutFrame("content-inventory/v1", b)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(framed)
	return b, hex.EncodeToString(sum[:]), nil
}
func addAutomationCutSize(inv *automationCutInventory, n int) error {
	if inv.Records == math.MaxInt64 || n < 0 || inv.Bytes > math.MaxInt64-int64(n) {
		return fmt.Errorf("cut inventory overflow")
	}
	inv.Records++
	inv.Bytes += int64(n)
	return nil
}
