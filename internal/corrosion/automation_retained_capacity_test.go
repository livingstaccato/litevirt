package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// Actual durable bounded page storage, not semantic/adopted metadata. The full
// shared semantic verifier remains mandatory and refuses these synthetic rows.
func TestRetainedManyPageLocalBodyLifetime(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := retainedDescriptorInput("local")
	descriptor.Source = a.request.Target
	descriptor.Incarnation = a.facts.Incarnation
	section := 2
	layout := aggregateLocalTables()[section]
	record := func(n int64) []byte {
		value := "value"
		if n == 65 {
			value = strings.Repeat("x", maxAutomationCutRecordBytes-1024)
		}
		row := Row{Columns: aggregateLocalColumns(layout.columns), Values: []any{n, strings.Repeat("a", 64), value, "certificate", "receipt", int64(1)}}
		raw, e := encodeAggregateLocalRecord(layout.descriptor().name, n, row)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	hash := sha256.New()
	prefix, _ := automationCutFrame("section/v1", []byte(descriptor.ComponentInventories[section].Section))
	hash.Write(prefix)
	for n := int64(1); n <= 130; n++ {
		raw := record(n)
		hash.Write(raw)
		descriptor.ComponentInventories[section].Records++
		descriptor.ComponentInventories[section].Bytes += int64(len(raw))
	}
	descriptor.ComponentInventories[section].Digest = hex.EncodeToString(hash.Sum(nil))
	body := retainedAdversarialHolder(t, a)
	var entries [][]byte
	var directory retainedDirectoryDigest
	for i, kind := range []string{"header", "receipt", "binding", "local"} {
		d := retainedDescriptorInput(kind)
		if kind == "local" {
			d = descriptor
		}
		d.Source = body.Donor
		d.Incarnation = body.DonorIncarnation
		raw, _ := json.Marshal(d)
		if err = directory.add(int64(i+1), raw); err != nil {
			t.Fatal(err)
		}
		entry, _ := json.Marshal(retainedDirectoryEntry{int64(i + 1), d})
		entries = append(entries, entry)
	}
	body.DirectoryRoot, _, body.DirectoryObjects, _, _, _, err = directory.finish()
	if err != nil {
		t.Fatal(err)
	}
	body.DirectoryBytes = directory.descriptorBytes
	envelope := retainedSignAdversarial(t, a.pair, body, retainedHolderDomain)
	active := receiverActive(t, r.client)
	if _, err = r.stageRetained(ctx, a, envelope, retainedPage{Object: 0, Component: 0, Records: entries, Terminal: true}); err != nil {
		t.Fatal(err)
	}
	for s := 0; s < section; s++ {
		if _, err = r.stageRetained(ctx, a, envelope, retainedPage{Object: 4, Component: s, Terminal: true}); err != nil {
			t.Fatal(err)
		}
	}
	reads := aggregateInstrument(t, r)
	reads.enabled = true
	evidence := &retainedHeapEvidence{}
	observed := context.WithValue(ctx, retainedHeapTestKey{}, evidence)
	for n := int64(1); n <= 130; n++ {
		page := retainedPage{Object: 4, Component: section, Position: n - 1, Records: [][]byte{record(n)}, Terminal: n == 130}
		got, err := r.stageRetained(observed, a, envelope, page)
		if err != nil || got.Records != n {
			t.Fatal("actual retained local page", n, err)
		}
		if n == 65 {
			if _, err = r.stageRetained(ctx, a, envelope, page); err != nil {
				t.Fatal("near-bound exact retry", err)
			}
		}
	}
	reads.enabled = false
	if reads.maxRows != 1 || reads.maxBytes < 2<<20 || reads.maxBytes > maxAggregateLocalRecordBytes || len(reads.bad) > 0 {
		t.Fatal("actual retained SQL bounds", reads.maxRows, reads.maxBytes, reads.bad)
	}
	if evidence.probes < 1 || evidence.maxLiveBytes > 1<<20 {
		t.Fatalf("prior retained decoded body survived next read: probes=%d bytes=%d stacks=%v", evidence.probes, evidence.maxLiveBytes, evidence.stacks)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("retained page capacity changed ACTIVE")
	}
	t.Logf("actual130 FULL local pages nearbody=%d, readqueries=%d maxRows=%d maxField=%d; postGC next-body probes=%d priorDecodedLive=%d stacks=%v", len(record(65)), reads.queries, reads.maxRows, reads.maxBytes, evidence.probes, evidence.maxLiveBytes, evidence.stacks)
}

type retainedHeapTestKey struct{}
type retainedHeapEvidence struct {
	probes       int
	maxLiveBytes int64
	stacks       []string
}

func (e *retainedHeapEvidence) beforeNextBody() {
	var callers [64]uintptr
	n := runtime.Callers(2, callers[:])
	frames := runtime.CallersFrames(callers[:n])
	terminal := false
	for {
		frame, more := frames.Next()
		terminal = terminal || strings.Contains(frame.Function, "retainedComponentTerminal")
		if !more {
			break
		}
	}
	if !terminal {
		return
	}
	runtime.GC()
	runtime.GC()
	count, _ := runtime.MemProfile(nil, true)
	records := make([]runtime.MemProfileRecord, count+64)
	count, ok := runtime.MemProfile(records, true)
	if !ok {
		return
	}
	var live int64
	var stacks []string
	for _, record := range records[:count] {
		if record.InUseBytes() < 1<<20 {
			continue
		}
		f := runtime.CallersFrames(record.Stack())
		decoded, retained := false, false
		stack := ""
		for {
			frame, more := f.Next()
			stack += frame.Function + " "
			decoded = decoded || strings.Contains(frame.Function, "decodeAutomationFramedRow") || strings.Contains(frame.Function, "encodeAggregateLocalRecord")
			retained = retained || strings.Contains(frame.Function, "retainedComponentTerminal")
			if !more {
				break
			}
		}
		if decoded && retained {
			live += record.InUseBytes()
			stacks = append(stacks, stack)
		}
	}
	e.probes++
	if live > e.maxLiveBytes {
		e.maxLiveBytes = live
		e.stacks = stacks
	}
}
