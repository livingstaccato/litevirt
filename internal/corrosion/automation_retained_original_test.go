package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestRetainedOriginalAggregatePreimage(t *testing.T) {
	producer, r, q, _, _ := receiverFixture(t)
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := strings.Repeat("a", 64)
	// This tests the consumed format against a real original receiver binding.
	// Synthetic metadata here never represents an audited aggregate or import.
	member := a.request.Sources[0]
	audit := sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(member.Name), []byte(d), []byte(d))
	publication, _, err := producer.client.readSourcePublication(context.Background(), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	roster := []aggregateRosterEntry{{member.Name, member.Incarnation, audit, d, d, publication.manifest.Cut.ID, d}}
	rawRoster, _ := json.Marshal(roster)
	local := sourceDigest([]byte("litevirt/local-audit/v1"), []byte(a.id), []byte(d))
	coverage := sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(d), rawRoster)
	h := retainedAggregateHeader{1, "automation-original-aggregate", retainedLocalLayoutDigest(), a.id, a.request.Job, a.request.Revision,
		a.request.Target, a.facts.Incarnation, 1, sourceDigest(a.binding), 2, d, local, d, d, AutomationPrefix{}, roster, coverage}
	raw, _ := json.Marshal(h)
	decoded, err := decodeRetainedHeader(raw)
	if err != nil {
		t.Fatalf("canonical original header refused: %v", err)
	}
	p, id, err := decoded.originalBinding(a.binding)
	if err != nil {
		t.Fatalf("exact original aggregate preimage refused: %v", err)
	}
	head, _ := json.Marshal(h.Head)
	want := sourceDigest([]byte("litevirt/receiver-aggregate/v1"), []byte(a.id), a.binding, []byte(local), []byte(d), head, []byte(coverage), rawRoster)
	if id != want || p.id != a.id {
		t.Fatal("original C preimage changed")
	}
	for name, mutate := range map[string]func(*retainedAggregateHeader){
		"attempt":          func(v *retainedAggregateHeader) { v.Attempt = d },
		"job":              func(v *retainedAggregateHeader) { v.Job = "other" },
		"revision":         func(v *retainedAggregateHeader) { v.Revision++ },
		"host":             func(v *retainedAggregateHeader) { v.Host = "other" },
		"incarnation":      func(v *retainedAggregateHeader) { v.Incarnation = "other" },
		"binding-digest":   func(v *retainedAggregateHeader) { v.BindingDigest = d },
		"local-id":         func(v *retainedAggregateHeader) { v.LocalID = d },
		"local-dependency": func(v *retainedAggregateHeader) { v.LocalDependency = strings.Repeat("b", 64) },
		"coverage":         func(v *retainedAggregateHeader) { v.Coverage = d },
		"roster-audit": func(v *retainedAggregateHeader) {
			v.Roster = append([]aggregateRosterEntry(nil), v.Roster...)
			v.Roster[0].Audit = d
		},
		"roster-source": func(v *retainedAggregateHeader) {
			v.Roster = append([]aggregateRosterEntry(nil), v.Roster...)
			v.Roster[0].Source = "other"
		},
		"roster-empty": func(v *retainedAggregateHeader) { v.Roster = nil },
	} {
		t.Run(name, func(t *testing.T) {
			v := h
			mutate(&v)
			raw, _ := json.Marshal(v)
			decoded, err := decodeRetainedHeader(raw)
			if err == nil {
				_, _, err = decoded.originalBinding(a.binding)
			}
			if err == nil {
				t.Fatal("spliced original preimage accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*retainedAggregateHeader){
		"layout":         func(v *retainedAggregateHeader) { v.LayoutDigest = d },
		"version":        func(v *retainedAggregateHeader) { v.Version++ },
		"purpose":        func(v *retainedAggregateHeader) { v.Purpose = "other" },
		"binding-object": func(v *retainedAggregateHeader) { v.BindingObject = 0 },
		"local-object":   func(v *retainedAggregateHeader) { v.LocalRowsObject = v.BindingObject },
		"head-empty":     func(v *retainedAggregateHeader) { v.Head.Digest = d },
	} {
		t.Run(name, func(t *testing.T) {
			v := h
			mutate(&v)
			raw, _ := json.Marshal(v)
			if _, err := decodeRetainedHeader(raw); err == nil {
				t.Fatal("unsupported original header accepted")
			}
		})
	}
}

func TestRetainedOriginalWholeElectorate(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3})
	before := receiverActive(t, f.local.c)
	for _, n := range []int{3, 2} {
		t.Run(fmt.Sprintf("original-%d-of-five", n), func(t *testing.T) {
			// Consumed original-binding metadata, not a produced import or live attempt.
			// Membership and the complete five-voter denominator are genuinely chosen.
			var binding receiverAttemptBinding
			if err := json.Unmarshal(f.attempt.binding, &binding); err != nil {
				t.Fatal(err)
			}
			binding.Intent.Sources = binding.Intent.Sources[:n]
			raw, _ := json.Marshal(binding)
			id := sourceDigest([]byte("litevirt/receiver-attempt/v1"), raw)
			d := strings.Repeat("a", 64)
			h := retainedAggregateHeader{Version: 1, Purpose: "automation-original-aggregate", LayoutDigest: retainedLocalLayoutDigest(), Attempt: id, Job: binding.Intent.Job, Revision: binding.Intent.Revision, Host: binding.Intent.Target, Incarnation: binding.Facts.Incarnation, BindingObject: 1, BindingDigest: sourceDigest(raw), LocalRowsObject: 2, LocalInventoryDigest: d, LocalDependency: d, LocalCoverage: d}
			h.LocalID = sourceDigest([]byte("litevirt/local-audit/v1"), []byte(id), []byte(d))
			for i, m := range binding.Intent.Sources {
				h.Roster = append(h.Roster, aggregateRosterEntry{m.Name, m.Incarnation, sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(id), []byte(m.Name), []byte(f.requests[i].Publication), []byte(d)), f.requests[i].Publication, d, strings.Repeat("a", 32), d})
			}
			roster, _ := json.Marshal(h.Roster)
			h.Coverage = sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(d), roster)
			header, _ := json.Marshal(h)
			decoded, err := decodeRetainedHeader(header)
			if err != nil {
				t.Fatal("canonical hostile header setup", err)
			}
			_, _, err = decoded.originalBinding(raw)
			if n == 3 && err != nil {
				t.Fatal("complete three-of-five original binding refused", err)
			}
			if n == 2 && err == nil {
				t.Fatal("two-of-five retained original counted as complete majority")
			}
			if receiverActive(t, f.local.c) != before {
				t.Fatal("retained whole-electorate check changed ACTIVE")
			}
		})
	}
}

func TestRetainedOriginal83HeaderLayoutBinding(t *testing.T) {
	producer, r, q, _, _ := receiverFixture(t)
	_ = producer
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A minimal canonical header uses a real original binding; this is not a
	// proof that its synthetic empty aggregate is accepted by full reconstruction.
	d := strings.Repeat("a", 64)
	member := a.request.Sources[0]
	audit := sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(member.Name), []byte(d), []byte(d))
	h := retainedAggregateHeader{Version: 1, Purpose: "automation-original-aggregate", LayoutDigest: retainedLocalLayout83Digest(), Attempt: a.id, Job: a.request.Job, Revision: a.request.Revision, Host: a.request.Target, Incarnation: a.facts.Incarnation, BindingObject: 1, BindingDigest: sourceDigest(a.binding), LocalRowsObject: 2, LocalInventoryDigest: d, LocalID: d, LocalDependency: d, LocalCoverage: d, Coverage: d, Roster: []aggregateRosterEntry{{Source: member.Name, Incarnation: member.Incarnation, Audit: audit, Publication: d, Cut: "0123456789abcdef0123456789abcdef", Root: d, Coverage: d}}}
	raw, _ := json.Marshal(h)
	if _, err := decodeRetainedHeader(raw); err != nil {
		t.Fatal("RETAINED83_HEADER_REFUSED", err)
	}
	// Layout binding is checked before consulting scratch/current evidence.
	descriptor := retainedDescriptorInput("local")
	descriptor.OriginalIdentity = h.LocalID
	descriptor.Source = h.Host
	descriptor.Incarnation = h.Incarnation
	err = r.client.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, err := auditRetainedLocal(context.Background(), tx, receiverAuditContext{a.id, a.request, a.facts}, h, retainedFrameAddress{}, descriptor, retainedDirectoryReader{}, "unused")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "retained local semantic context differs") {
		t.Fatal("RETAINED83_MIXED_HEADER_OBJECT_ACCEPTED", err)
	}
}

func TestRetainedOriginal83SchemaLayoutMismatch(t *testing.T) {
	for _, tc := range []struct {
		layout string
		schema int64
	}{{retainedLocalLayout83Digest(), 84}, {retainedLocalLayout83Digest(), 85}, {retainedLocalLayoutDigest(), 83}} {
		observation := aggregateLocalObservation{retained: true, layoutDigest: tc.layout}
		err := observation.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), tc.schema}})
		if err == nil || !strings.Contains(err.Error(), "schema/layout differs") {
			t.Fatal("RETAINED83_SCHEMA_LAYOUT_MISMATCH_ACCEPTED", err)
		}
	}
}

// Format-level positive cases only. Genuine old84 frames require the separately
// accepted signed84 exporter; this matrix is not historical export evidence.
func TestRetainedOriginal84And85SharedLayout(t *testing.T) {
	for _, version := range []int64{84, 85} {
		t.Run(fmt.Sprintf("schema%d", version), func(t *testing.T) {
			observation := aggregateLocalObservation{retained: true, layoutDigest: retainedLocalLayoutDigest()}
			if err := observation.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), version}}); err != nil {
				t.Fatal("retained33 schema refused", version, err)
			}
		})
	}
}
