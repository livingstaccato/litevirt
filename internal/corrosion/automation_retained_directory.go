package corrosion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"math"
)

type retainedObjectDescriptor struct {
	Version              int
	Kind                 string
	LayoutDigest         string
	OriginalIdentity     string
	Source               string
	Incarnation          string
	ComponentInventories []automationCutInventory
}

type retainedDirectoryEntry struct {
	Ordinal    int64
	Descriptor retainedObjectDescriptor
}

func retainedObjectLayout(kind string) string {
	if kind == "local" {
		return retainedLocalLayoutDigest()
	}
	sections, _, _ := retainedObjectSections(kind)
	if len(sections) == 0 {
		return ""
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/retained-object-layout/v1"), []byte(kind))
	for _, section := range sections {
		sourceHash(h, []byte(section), automationCutInteger(1))
	}
	if kind == "source" || kind == "native" {
		for _, d := range automationCutSections {
			sourceHash(h, []byte(d.table), []byte(d.columns))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Positive metadata limits mark bounded chunk components; zero marks a framed
// record section with a section-domain seed. Identifiers are compiled, not SQL.
func retainedObjectSections(kind string) (sections []string, limits []int64, stream retainedStreamKind) {
	switch kind {
	case "header":
		return []string{"header/v1"}, []int64{maxRetainedHeaderBytes}, retainedMetadataStream
	case "receipt":
		return []string{"receipt/v1"}, []int64{maxRetainedReceiptBytes}, retainedMetadataStream
	case "binding":
		return []string{"binding/v1"}, []int64{maxReceiverBindingBytes}, retainedMetadataStream
	case "local":
		for _, d := range aggregateLocalTables() {
			sections = append(sections, d.descriptor().name)
			limits = append(limits, 0)
		}
		return sections, limits, retainedLocalStream
	case "source":
		sections = []string{"source-artifact/v1", "source-trust/v1", "source-membership/v1"}
		limits = append(limits, receiverMetadataLimits[:]...)
		stream = retainedSourceStream
	case "native":
		sections = []string{"native-cut/v1"}
		limits = []int64{maxAutomationCutMetadataBytes}
		stream = retainedNativeStream
	default:
		return nil, nil, 0
	}
	for _, d := range automationCutSections {
		sections = append(sections, d.name)
		limits = append(limits, 0)
	}
	return sections, limits, stream
}

// The local object's admitted digest selects compiled columns/section order;
// metadata never authors SQL. Non-local objects keep their existing layout.
func retainedDescriptorSections(d retainedObjectDescriptor) (sections []string, limits []int64, stream retainedStreamKind) {
	if d.Kind != "local" {
		return retainedObjectSections(d.Kind)
	}
	tables, err := retainedLocalTablesForDigest(d.LayoutDigest)
	if err != nil {
		return nil, nil, 0
	}
	for _, table := range tables {
		sections = append(sections, table.descriptor().name)
		limits = append(limits, 0)
	}
	return sections, limits, retainedLocalStream
}

func decodeRetainedObject(raw []byte) (retainedObjectDescriptor, error) {
	var v retainedObjectDescriptor
	if err := retainedCanonical(raw, maxAutomationCutMetadataBytes, &v); err != nil {
		return v, err
	}
	sections, limits, kind := retainedDescriptorSections(v)
	layoutOK := v.LayoutDigest == retainedObjectLayout(v.Kind)
	if v.Kind == "local" {
		_, err := retainedLocalTablesForDigest(v.LayoutDigest)
		layoutOK = err == nil
	}
	validOriginal := receiverDigest(v.OriginalIdentity)
	if kind == retainedNativeStream {
		validOriginal = retainedNativeIdentity(v.OriginalIdentity)
	}
	if v.Version != 1 || kind == 0 || !layoutOK || !validOriginal ||
		!retainedField(v.Source, 253) || !retainedField(v.Incarnation, 128) || len(v.ComponentInventories) != len(sections) {
		return v, errors.New("unsupported retained object identity or layout")
	}
	var total, records int64
	for i, inv := range v.ComponentInventories {
		if inv.Section != sections[i] || inv.Codec != 1 || inv.Records < 0 || inv.Bytes < 0 || !receiverDigest(inv.Digest) ||
			inv.Bytes > math.MaxInt64-total || inv.Records > math.MaxInt64-records || inv.Bytes < inv.Records {
			return v, errors.New("invalid retained ordered component inventory")
		}
		total += inv.Bytes
		records += inv.Records
		if limits[i] > 0 {
			if inv.Bytes <= 0 || inv.Bytes > limits[i] || inv.Records != (inv.Bytes+AutomationExportChunkBytes-1)/AutomationExportChunkBytes {
				return v, errors.New("retained metadata inventory exceeds bound")
			}
		} else if inv.Records == 0 {
			h := sha256.New()
			frame, _ := automationCutFrame("section/v1", []byte(inv.Section))
			h.Write(frame)
			if inv.Bytes != 0 || inv.Digest != hex.EncodeToString(h.Sum(nil)) {
				return v, errors.New("retained empty section inventory differs")
			}
		} else {
			bound := int64(maxAutomationCutRecordBytes)
			if kind == retainedLocalStream {
				bound = maxAggregateLocalRecordBytes
			}
			if inv.Bytes/inv.Records > bound || (inv.Bytes/inv.Records == bound && inv.Bytes%inv.Records != 0) {
				return v, errors.New("retained record byte inventory exceeds bound")
			}
		}
	}
	return v, nil
}

func retainedNativeIdentity(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id
}

// Counts and roots have typed, ordered, non-circular preimages. The complete
// directory includes the receipt; its evidence graph excludes only the receipt.
type retainedDirectoryDigest struct {
	directory, graph                                                    hash.Hash
	objects, evidenceObjects, bodyBytes, evidenceBytes, descriptorBytes int64
	header, receipt, binding, local                                     bool
	finished, failed                                                    bool
}

func (d *retainedDirectoryDigest) add(ordinal int64, raw []byte) error {
	fail := func(err error) error { d.failed = true; return err }
	if d.finished || d.failed || d.objects == math.MaxInt64 || ordinal != d.objects+1 {
		return fail(errors.New("retained directory ordinal or lifecycle differs"))
	}
	v, err := decodeRetainedObject(raw)
	if err != nil {
		return fail(err)
	}
	var singleton *bool
	switch v.Kind {
	case "header":
		singleton = &d.header
	case "receipt":
		singleton = &d.receipt
	case "binding":
		singleton = &d.binding
	case "local":
		singleton = &d.local
	}
	if singleton != nil && *singleton {
		return fail(errors.New("duplicate retained singleton object"))
	}
	entry, _ := json.Marshal(retainedDirectoryEntry{ordinal, v})
	if len(entry) > maxAutomationCutMetadataBytes || int64(len(entry)) > math.MaxInt64-d.descriptorBytes {
		return fail(errors.New("retained directory entry bytes exceed bound"))
	}
	var size int64
	for _, inv := range v.ComponentInventories {
		size += inv.Bytes
	}
	if size > math.MaxInt64-d.bodyBytes || (v.Kind != "receipt" && size > math.MaxInt64-d.evidenceBytes) {
		return fail(errors.New("retained directory byte overflow"))
	}
	if d.directory == nil {
		d.directory = sha256.New()
		d.graph = sha256.New()
		sourceHash(d.directory, []byte("litevirt/retained-directory/v1"))
		sourceHash(d.graph, []byte("litevirt/retained-evidence-graph/v1"))
	}
	if singleton != nil {
		*singleton = true
	}
	d.objects = ordinal
	d.bodyBytes += size
	d.descriptorBytes += int64(len(entry))
	sourceHash(d.directory, []byte("object"), automationCutInteger(ordinal), raw)
	if v.Kind != "receipt" {
		d.evidenceObjects++
		d.evidenceBytes += size
		sourceHash(d.graph, []byte("object"), automationCutInteger(ordinal), raw)
	}
	return nil
}
func (d *retainedDirectoryDigest) finish() (directory, graph string, objects, evidenceObjects, bodyBytes, evidenceBytes int64, err error) {
	if d.failed || d.finished || !d.header || !d.receipt || !d.binding || !d.local || d.directory == nil {
		return "", "", 0, 0, 0, 0, errors.New("retained directory incomplete or already consumed")
	}
	d.finished = true
	sourceHash(d.directory, []byte("end"), automationCutInteger(d.objects), automationCutInteger(d.descriptorBytes), automationCutInteger(d.bodyBytes))
	sourceHash(d.graph, []byte("end"), automationCutInteger(d.evidenceObjects), automationCutInteger(d.evidenceBytes))
	return hex.EncodeToString(d.directory.Sum(nil)), hex.EncodeToString(d.graph.Sum(nil)), d.objects, d.evidenceObjects, d.bodyBytes, d.evidenceBytes, nil
}
