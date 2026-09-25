package metrics

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func seedFence(t *testing.T, db *corrosion.Client, id, method, result string) {
	t.Helper()
	if err := corrosion.InsertFenceLog(context.Background(), db, corrosion.FenceLogRecord{
		ID: id, HostName: "node-4", Method: method, Result: result,
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
}

func fenceSeries(t *testing.T, db *corrosion.Client) map[[2]string]float64 {
	t.Helper()
	c := newCollector(db, nil, nil, "host-a")
	ch := make(chan prometheus.Metric, 200)
	c.Collect(ch)
	close(ch)
	out := map[[2]string]float64{}
	for m := range ch {
		if !containsStr(m.Desc().String(), "litevirt_fences_total") {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			t.Fatalf("write: %v", err)
		}
		var method, assurance string
		for _, lp := range dm.GetLabel() {
			switch lp.GetName() {
			case "method":
				method = lp.GetValue()
			case "assurance":
				assurance = lp.GetValue()
			}
		}
		out[[2]string{method, assurance}] = dm.GetCounter().GetValue()
	}
	return out
}

// Fences are counted by what they ESTABLISH, so a cluster recovering on fences
// nobody verified is visible as a number.
//
// fencing_log's result column writes "fenced" for an IPMI power-off that was
// observed off and for an SSH poweroff nobody checked. The only existing fence
// metric counted failures, so every one of those unverified successes was
// invisible — counted, if anywhere, as a success.
func TestCollect_FencesAreCountedByAssurance(t *testing.T) {
	db := initTestDB(t)
	seedFence(t, db, "f1", "ipmi", "fenced")
	seedFence(t, db, "f2", "ssh", "fenced")
	seedFence(t, db, "f3", "ssh", "fenced")
	seedFence(t, db, "f4", "best-effort-ssh", "fenced")
	seedFence(t, db, "f5", "manual", "manual-confirmed")
	seedFence(t, db, "f6", "ssh", "partial")

	got := fenceSeries(t, db)

	want := map[[2]string]float64{
		{"ipmi", corrosion.FenceVerified}:            1,
		{"ssh", corrosion.FenceRequested}:            2,
		{"best-effort-ssh", corrosion.FenceAssumed}:  1,
		{"manual", corrosion.FenceOperatorConfirmed}: 1,
		{"ssh", corrosion.FenceFailed}:               1,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("litevirt_fences_total{method=%q,assurance=%q} = %v, want %v", k[0], k[1], got[k], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d series %v, want %d", len(got), got, len(want))
	}
}

// No fences, no series — rather than a zero series for every combination,
// which would make the label set a claim about strategies this cluster never
// used.
func TestCollect_NoFencesNoSeries(t *testing.T) {
	db := initTestDB(t)
	if got := fenceSeries(t, db); len(got) != 0 {
		t.Errorf("got %v with an empty fencing_log, want no series", got)
	}
}
