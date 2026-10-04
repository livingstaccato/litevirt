package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func ackRow(class string, on, off []string) *pb.DivergenceRow {
	r := &pb.DivergenceRow{Table: "leader_lease_terms", Pk: "dual_run_detector2", Class: class,
		TieAcknowledgedOn: on, TieUnacknowledgedOn: off}
	for _, h := range append(append([]string{}, on...), off...) {
		r.PerNode = append(r.PerNode, &pb.NodeRowMeta{Host: h, UpdatedAt: "t", RowHash: "hash-" + h})
	}
	return r
}

func lineWith(out, needle string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// Only acknowledged ties: the summary reads clean, exactly as a clean scan
// does, and the ties are still listed, as acknowledged, with their evidence.
func TestRenderDivergence_AcknowledgedOnlyReadsClean(t *testing.T) {
	rep := &pb.DivergenceReport{NodesScanned: []string{"node-1", "node-2"}, Samples: 2, Stable: true,
		Rows: []*pb.DivergenceRow{ackRow("acknowledged_tie", []string{"node-1", "node-2"}, nil)}}
	out := captureStdout(t, func() { renderDivergenceReport(rep) })
	if !strings.Contains(out, "\nno divergence detected.") {
		t.Errorf("an acknowledged-only scan does not read clean:\n%s", out)
	}
	if strings.Contains(out, "Diverging rows") {
		t.Errorf("an acknowledged tie is counted as a diverging row:\n%s", out)
	}
	if !strings.Contains(out, "Acknowledged ties (1)") {
		t.Errorf("the acknowledged tie is not listed:\n%s", out)
	}
	if l := lineWith(out, "dual_run_detector2"); !strings.Contains(l, "acknowledged_tie") || !strings.Contains(l, "node-1=t/hash-node-1") {
		t.Errorf("the acknowledged row lost its class or evidence: %q", l)
	}
}

// Acknowledged on some hosts only: a divergence, and the line names the hosts
// still to acknowledge.
func TestRenderDivergence_PartlyAcknowledgedNamesTheRest(t *testing.T) {
	rep := &pb.DivergenceReport{NodesScanned: []string{"node-1", "node-2", "node-3"}, Samples: 2, Stable: true,
		Rows: []*pb.DivergenceRow{ackRow("stuck_different", []string{"node-1", "node-2"}, []string{"node-3"})}}
	out := captureStdout(t, func() { renderDivergenceReport(rep) })
	if strings.Contains(out, "no divergence detected") {
		t.Errorf("a partly acknowledged tie read clean:\n%s", out)
	}
	if !strings.Contains(out, "Diverging rows (1)") {
		t.Errorf("a partly acknowledged tie is not counted as a divergence:\n%s", out)
	}
	if l := lineWith(out, "dual_run_detector2"); !strings.Contains(l, "stuck_different") || !strings.Contains(l, "not acknowledged on node-3") {
		t.Errorf("the row does not name the host still to acknowledge: %q", l)
	}
}

// A divergence with no acknowledgement anywhere renders exactly as before.
func TestRenderDivergence_OtherDivergenceUnchanged(t *testing.T) {
	rep := &pb.DivergenceReport{NodesScanned: []string{"a", "b"}, Samples: 2, Stable: true,
		Rows: []*pb.DivergenceRow{{Table: "vms", Pk: "web", Class: "stuck_different", PerNode: []*pb.NodeRowMeta{
			{Host: "a", UpdatedAt: "t1", RowHash: "h1"}, {Host: "b", UpdatedAt: "t2", RowHash: "h2"}}}}}
	out := captureStdout(t, func() { renderDivergenceReport(rep) })
	if !strings.Contains(out, "Diverging rows (1)") || strings.Contains(out, "no divergence detected") {
		t.Errorf("a plain divergence changed how it reads:\n%s", out)
	}
	if strings.Contains(out, "acknowledged") {
		t.Errorf("a plain divergence mentions acknowledgement:\n%s", out)
	}
	if l := lineWith(out, "web"); !strings.HasSuffix(strings.TrimRight(l, " "), "a=t1/h1  b=t2/h2") {
		t.Errorf("plain row line changed: %q", l)
	}
}
