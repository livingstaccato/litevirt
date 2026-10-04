package grpcapi

import (
	"reflect"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func ackDigest(host string, tables ...*pb.TableDigest) *pb.StateDigestResponse {
	return &pb.StateDigestResponse{HostName: host, Tables: tables}
}

func ackTable(name string, ties, acked int32, residual string) *pb.TableDigest {
	return &pb.TableDigest{Name: name, Hash: "h", UnresolvedTies: ties, AcknowledgedTies: acked, AcknowledgedResidual: residual}
}

func divRow(table, pk string, class corrosion.DivergenceClass, hosts ...string) *pb.DivergenceRow {
	r := &pb.DivergenceRow{Table: table, Pk: pk, Class: string(class)}
	for _, h := range hosts {
		r.PerNode = append(r.PerNode, &pb.NodeRowMeta{Host: h, RowHash: "hash-" + h})
	}
	return r
}

// A lease-term row that every host holding it has acknowledged, in a table
// whose residuals agree everywhere, is the tie `lv cluster converge` lists as
// ACKNOWLEDGED: doctor classes it acknowledged_tie, and names no host as still
// to acknowledge it.
func TestAnnotateAcknowledgedTies_AcknowledgedEverywhere(t *testing.T) {
	verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
		ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "v2:same")),
		ackDigest("node-2", ackTable("leader_lease_terms", 1, 1, "v2:same")),
		ackDigest("node-3", ackTable("leader_lease_terms", 1, 1, "v2:same")),
	})
	row := divRow("leader_lease_terms", "dual_run_detector2", corrosion.ClassStuckDifferent, "node-1", "node-2", "node-3")
	annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)

	if row.GetClass() != string(corrosion.ClassAcknowledgedTie) {
		t.Errorf("class = %q, want %q", row.GetClass(), corrosion.ClassAcknowledgedTie)
	}
	if got := row.GetTieAcknowledgedOn(); !reflect.DeepEqual(got, []string{"node-1", "node-2", "node-3"}) {
		t.Errorf("tie_acknowledged_on = %v, want every host", got)
	}
	if got := row.GetTieUnacknowledgedOn(); len(got) != 0 {
		t.Errorf("tie_unacknowledged_on = %v, want none", got)
	}
}

// The lab's case: rebuilt hosts came back with empty acknowledgement tables, so
// the tie is acknowledged on some hosts only. It stays a divergence, and the
// row names exactly the hosts that have not acknowledged it — one tracking the
// tie live, one tracking nothing at all.
func TestAnnotateAcknowledgedTies_PartlyAcknowledgedNamesTheRest(t *testing.T) {
	verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
		ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "v2:same")),
		ackDigest("node-2", ackTable("leader_lease_terms", 1, 0, "")),
		ackDigest("node-3", ackTable("leader_lease_terms", 1, 1, "v2:same")),
		ackDigest("node-4", ackTable("leader_lease_terms", 0, 0, "")),
	})
	row := divRow("leader_lease_terms", "dual_run_detector2", corrosion.ClassStuckDifferent,
		"node-1", "node-2", "node-3", "node-4")
	annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)

	if row.GetClass() != string(corrosion.ClassStuckDifferent) {
		t.Errorf("class = %q: a tie not acknowledged everywhere must stay %q",
			row.GetClass(), corrosion.ClassStuckDifferent)
	}
	if got := row.GetTieUnacknowledgedOn(); !reflect.DeepEqual(got, []string{"node-2", "node-4"}) {
		t.Errorf("tie_unacknowledged_on = %v, want [node-2 node-4]", got)
	}
	if got := row.GetTieAcknowledgedOn(); !reflect.DeepEqual(got, []string{"node-1", "node-3"}) {
		t.Errorf("tie_acknowledged_on = %v, want [node-1 node-3]", got)
	}
}

// Every host vouches, but the residuals disagree: something besides the
// acknowledged rows differs, and from table-level evidence the row may be it.
// Converge keeps such a table a SAFETY-FAULT, so doctor keeps the row's class.
// A row held by a host that sent no digest at all cannot be vouched for
// either.
func TestAnnotateAcknowledgedTies_UnprovenStaysADivergence(t *testing.T) {
	t.Run("residuals differ", func(t *testing.T) {
		verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
			ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "v2:one")),
			ackDigest("node-2", ackTable("leader_lease_terms", 1, 1, "v2:two")),
		})
		row := divRow("leader_lease_terms", "failover7", corrosion.ClassStuckDifferent, "node-1", "node-2")
		annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)
		if row.GetClass() != string(corrosion.ClassStuckDifferent) {
			t.Errorf("class = %q: drift beside acknowledged ties read as acknowledged", row.GetClass())
		}
		if len(row.GetTieUnacknowledgedOn()) != 0 {
			t.Errorf("tie_unacknowledged_on = %v: both hosts acknowledged", row.GetTieUnacknowledgedOn())
		}
	})
	t.Run("no host sent a residual", func(t *testing.T) {
		// Every tie acknowledged, but no host could vouch for the rest of
		// the table (an older build sends no residual): nothing proves the
		// row is the acknowledged one.
		verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
			ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "")),
			ackDigest("node-2", ackTable("leader_lease_terms", 1, 1, "")),
		})
		row := divRow("leader_lease_terms", "failover7", corrosion.ClassStuckDifferent, "node-1", "node-2")
		annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)
		if row.GetClass() != string(corrosion.ClassStuckDifferent) {
			t.Errorf("class = %q: acknowledged without a residual read as proven", row.GetClass())
		}
		if got := row.GetTieUnacknowledgedOn(); !reflect.DeepEqual(got, []string{"node-1", "node-2"}) {
			t.Errorf("tie_unacknowledged_on = %v, want both hosts: neither can vouch", got)
		}
	})
	t.Run("a host counts a live tie beside its residual", func(t *testing.T) {
		// A host never sends a residual with a live tie, but if one did, its
		// count is the one to believe: the live tie is unacknowledged there.
		verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
			ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "v2:same")),
			ackDigest("node-2", ackTable("leader_lease_terms", 2, 1, "v2:same")),
		})
		row := divRow("leader_lease_terms", "failover7", corrosion.ClassStuckDifferent, "node-1", "node-2")
		annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)
		if row.GetClass() != string(corrosion.ClassStuckDifferent) {
			t.Errorf("class = %q: a live tie read as acknowledged", row.GetClass())
		}
		if got := row.GetTieUnacknowledgedOn(); !reflect.DeepEqual(got, []string{"node-2"}) {
			t.Errorf("tie_unacknowledged_on = %v, want [node-2]", got)
		}
	})
	t.Run("a host sent no digest", func(t *testing.T) {
		verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
			ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "v2:same")),
			ackDigest("node-2", ackTable("leader_lease_terms", 1, 1, "v2:same")),
		})
		row := divRow("leader_lease_terms", "failover7", corrosion.ClassStuckDifferent, "node-1", "node-2", "node-3")
		annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)
		if row.GetClass() != string(corrosion.ClassStuckDifferent) {
			t.Errorf("class = %q: a host that sent no digest was taken as acknowledging", row.GetClass())
		}
		if got := row.GetTieUnacknowledgedOn(); !reflect.DeepEqual(got, []string{"node-3"}) {
			t.Errorf("tie_unacknowledged_on = %v, want [node-3]", got)
		}
	})
}

// A divergence in a table where nobody acknowledged anything is untouched,
// even beside an acknowledged lease-term tie.
func TestAnnotateAcknowledgedTies_OtherDivergenceUnchanged(t *testing.T) {
	verdicts := corrosion.TieAckVerdicts([]*pb.StateDigestResponse{
		ackDigest("node-1", ackTable("leader_lease_terms", 1, 1, "v2:same"), ackTable("vms", 0, 0, "")),
		ackDigest("node-2", ackTable("leader_lease_terms", 1, 1, "v2:same"), ackTable("vms", 0, 0, "")),
	})
	row := divRow("vms", "web", corrosion.ClassStuckDifferent, "node-1", "node-2")
	annotateAcknowledgedTies([]*pb.DivergenceRow{row}, verdicts)
	if row.GetClass() != string(corrosion.ClassStuckDifferent) {
		t.Errorf("vms row class = %q, want it unchanged", row.GetClass())
	}
	if len(row.GetTieAcknowledgedOn()) != 0 || len(row.GetTieUnacknowledgedOn()) != 0 {
		t.Errorf("vms row annotated: acknowledged_on=%v unacknowledged_on=%v",
			row.GetTieAcknowledgedOn(), row.GetTieUnacknowledgedOn())
	}
}
