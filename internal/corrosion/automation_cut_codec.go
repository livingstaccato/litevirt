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
const automationCutSourceSchema = 91

// Explicit source descriptors: 69/1 retains its original inventory and root.
// 70/1 adds only outgoing job pins/publication wrappers/public trust evidence,
// which refer to already completed cuts and are excluded to avoid recursion.
// 71/1 adds inert receiver attempts and page staging, excluded because they
// establish no active import, anchor, membership or use authority. These are
// receiver staging, NOT egress. 72/1 adds only inert semantic references and
// causal audit results, introducing no active native/import origin mode.
// 73/1 adds eight local derived projections: stage="" is active, nonempty
// stages are isolated audit state. All are reconstructed from the unchanged
// certified history inventory; no projection row confers import authority.
// 74/1 adds only originating local lifetime observations and private credential
// issuance observations. Both tables and their fifteen invalidate-only triggers
// are excluded: they cannot establish cross-node lifecycle or credential proof.
// Credential digests are never public cut content or certified identity facts.
// 75/1 adds only inert local audit snapshots and fixed-roster aggregate indexes;
// these are excluded from source content and confer no import or custody proof.
// 69..75 above are archived descriptor meanings, independent of the relocated
// unshipped SQL migration numbers. They must never be relabeled or re-encoded.
// 76/1 explicitly inventories the current union: incoming credential retirement
// ordering plus SQL automation69..76. Fence secrets/retirement observations,
// local lifecycle/credential observations, projections and aggregate indexes
// remain excluded; the certified section/field codec and archived roots stay
// unchanged. Credential retirement does not certify a transferable identity.
// Future lifecycle source-proof transfer and active import receipts require a
// new inventory and provenance audit; accepting74 does not provide that proof.
// 77/1 adds three causal key-transition projections, reconstructed from the
// unchanged certified history sections. Archived69-76 bytes remain unchanged.
// 78/1 adds node-local receiver-established signed floor artifacts, excluded
// from public cut content. Archived69-77 descriptors and all bytes stay fixed.
// 79/1 inventories the union with shipped hosts.incarnation at SQL69 and
// relocated private SQL70..79. Host rows and their admission keys are excluded
// from cut content; the nine certified sections and codec remain unchanged.
// Archived69..78 descriptors keep their exact meanings, bytes and roots.
// 80/1 adds inert supplemental delivery/object/completion pins after the
// shipped host-incarnation/private-migration union. These pins are excluded
// from source authority; archived69..79 meanings, bytes and roots stay fixed.
// 81/1 corrects only the derived recipient host-number domain. Derived rows
// remain excluded; the same nine sections/codec1 and archived69..80 stay fixed.
// 82/1 inventories published SG70 plus private SQL71..82. SG project ownership
// is excluded from certified automation identity and authority; the nine
// sections/codec1 and archived69..81 meanings, bytes and roots remain fixed.
// 83/1 inventories published project-incarnation SQL71 plus private SQL72..83.
// Project rows, incarnation-bound grants and quotas remain outside the nine
// certified sections: a replicated project incarnation supplies no automation
// identity, lifecycle proof or native permit. Archived69..82 descriptors,
// including82/1 SG70/private71..82, retain their exact meanings and roots.
// 84/1 adds derived target operations and complete-key reservations, rebuilt
// from the unchanged nine certified history sections. They are audited locally
// but excluded from exported authority; no new section, codec or native permit.
// Archived69..83 descriptor meanings and roots remain unchanged.
// 85/1 inventories the incoming token-account incarnation stamp, its additive
// invalidate-only trigger and local issuance/authentication/anti-entropy/account
// checks and retirement. These add no certified section or private33 authority;
// archived69..84 meanings, bytes, roots and codec remain unchanged.
// 86/1 adds four local execution projections reconstructed from the same nine
// certified sections. No new authority section, codec or native permit. Archived
// 69..85 descriptors and roots stay fixed; current private layout has37 parts.
// 87/1 inventories published fence SSH at SQL72 plus relocated private SQL73..87.
// Fence host rows and keys remain outside the same nine certified sections;
// archived69..86 descriptors, roots and layouts keep their exact meanings.
// 88/1 adds the local derived continuity projection. Nine certified sections
// and archived69..87 bytes/meanings stay fixed; private current layout is38.
// 89/1 adds excluded local issuance mode/attachment columns. Nine public
// sections/codec remain fixed; the frozen88 private38 inventory stays literal.
// 90/1 adds only a required physical desired-admission index and its schema
// ledger unit. Neither is a certified section or private-layout row. Archived
// 69..89 bytes/roots, nine public sections/codec1 and private38 remain fixed.
// 91/1 adds only the replicated catalog birth incarnation columns of images
// and storage_pools, which are in no certified section or private-layout row.
// Archived 69..90 bytes/roots, nine public sections/codec1 and private38
// remain fixed.
func supportedAutomationCutDescriptor(schema, codec int) bool {
	return codec == 1 && (schema == 69 || schema == 70 || schema == 71 || schema == 72 || schema == 73 || schema == 74 || schema == 75 || schema == 76 || schema == 77 || schema == 78 || schema == 79 || schema == 80 || schema == 81 || schema == 82 || schema == 83 || schema == 84 || schema == 85 || schema == 86 || schema == 87 || schema == 88 || schema == 89 || schema == 90 || schema == 91)
}

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
