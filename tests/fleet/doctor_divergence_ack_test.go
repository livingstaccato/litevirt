package fleet

import (
	"context"
	"reflect"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// diagnose runs `lv doctor divergence` through via and returns the report's
// rows by table.
func diagnose(t *testing.T, c *Cluster, via *Node) map[string][]*pb.DivergenceRow {
	t.Helper()
	rep, err := c.SelfClient(via).DiagnoseDivergence(context.Background(), &pb.DiagnoseDivergenceRequest{})
	if err != nil {
		t.Fatalf("DiagnoseDivergence via %s: %v", via.Name, err)
	}
	if len(rep.GetNodesScanned()) != len(c.Nodes) {
		t.Fatalf("scanned %v, want every node", rep.GetNodesScanned())
	}
	out := map[string][]*pb.DivergenceRow{}
	for _, r := range rep.GetRows() {
		out[r.GetTable()] = append(out[r.GetTable()], r)
	}
	return out
}

// TestFleet_DoctorDivergence_AgreesWithConvergeOnAcknowledgedTies: `lv
// cluster converge` lists a lease-term tie every host has acknowledged as
// ACKNOWLEDGED and counts it converged, while `lv doctor divergence` went on
// calling the same row stuck_different with no sign that anyone had reviewed
// it. The lab also had the opposite case, rebuilt hosts with empty
// acknowledgement tables, where the tie is acknowledged on some hosts only.
//
//   - acknowledged on two of three hosts: the row keeps its divergence class
//     and names the one host still to acknowledge;
//   - acknowledged on all three: the row is acknowledged_tie, still listed;
//   - a divergence in an unrelated table keeps its class and gains no
//     acknowledgement annotation, throughout.
func TestFleet_DoctorDivergence_AgreesWithConvergeOnAcknowledgedTies(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	const key, term = "dual_run_detector", int64(2)
	for _, n := range c.Nodes {
		seedUnreplicatedLeaseTerm(t, n, key, term, n.Name)
	}
	// A non-lease divergence: a label only the first node holds, written beneath the
	// replicator so it stays there.
	{
		n := c.Nodes[0]
		now := time.Now().UTC().Format(time.RFC3339Nano)
		n.DB.Mu().Lock()
		_, err := n.DB.DB().Exec(`INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?, ?, ?, ?)`,
			n.Name, "doctor-ack-probe", "only-here", now)
		n.DB.Mu().Unlock()
		if err != nil {
			t.Fatalf("seed host label: %v", err)
		}
	}
	passAll := func() {
		t.Helper()
		for _, n := range c.Nodes {
			if !corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx) {
				t.Fatalf("%s: anti-entropy pass did not run", n.Name)
			}
		}
	}
	passAll()
	// Anti-entropy carries the label everywhere; before each scan, take it
	// back off every node but the first.
	splitLabel := func() {
		t.Helper()
		for _, n := range c.Nodes[1:] {
			n.DB.Mu().Lock()
			_, err := n.DB.DB().Exec(`DELETE FROM host_labels WHERE key = 'doctor-ack-probe'`)
			n.DB.Mu().Unlock()
			if err != nil {
				t.Fatalf("%s: drop probe label: %v", n.Name, err)
			}
		}
	}

	acknowledge := func(n *Node) {
		t.Helper()
		admin := c.SelfClient(n)
		user := "doctorack-op-" + n.Name
		if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
			Username: user, Password: "doctorack-pass", Role: "operator",
		}); err != nil {
			t.Fatalf("%s: CreateUser: %v", n.Name, err)
		}
		tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: user, Name: "ack"})
		if err != nil || tok.GetToken() == "" {
			t.Fatalf("%s: CreateToken: %+v %v", n.Name, tok, err)
		}
		resp, err := c.bearerClient(n, tok.GetToken()).AcknowledgeLeaseTermTie(ctx,
			&pb.AcknowledgeLeaseTermTieRequest{Key: key, Term: term})
		if err != nil || !resp.GetAcknowledged() {
			t.Fatalf("%s: acknowledge: %+v %v", n.Name, resp, err)
		}
	}

	leaseRow := func(rows map[string][]*pb.DivergenceRow) *pb.DivergenceRow {
		t.Helper()
		if len(rows["leader_lease_terms"]) != 1 {
			t.Fatalf("want one leader_lease_terms row, got %v", rows["leader_lease_terms"])
		}
		return rows["leader_lease_terms"][0]
	}
	checkLabelRow := func(rows map[string][]*pb.DivergenceRow) {
		t.Helper()
		if len(rows["host_labels"]) != 1 {
			t.Fatalf("want the probe label as one host_labels row, got %v", rows["host_labels"])
		}
		r := rows["host_labels"][0]
		if r.GetClass() != string(corrosion.ClassMissingRow) {
			t.Errorf("host_labels row class = %q, want %q unchanged", r.GetClass(), corrosion.ClassMissingRow)
		}
		if len(r.GetTieAcknowledgedOn()) != 0 || len(r.GetTieUnacknowledgedOn()) != 0 {
			t.Errorf("host_labels row carries an acknowledgement annotation: on=%v off=%v",
				r.GetTieAcknowledgedOn(), r.GetTieUnacknowledgedOn())
		}
	}

	// Acknowledged on the first two nodes; the third is the rebuilt host.
	acknowledge(c.Nodes[0])
	acknowledge(c.Nodes[1])
	passAll()
	splitLabel()
	rows := diagnose(t, c, c.Nodes[0])
	r := leaseRow(rows)
	if r.GetClass() == string(corrosion.ClassAcknowledgedTie) {
		t.Errorf("a tie the third node never acknowledged was classed %q", r.GetClass())
	}
	if got := r.GetTieUnacknowledgedOn(); !reflect.DeepEqual(got, []string{c.Nodes[2].Name}) {
		t.Errorf("tie_unacknowledged_on = %v, want [%s]", got, c.Nodes[2].Name)
	}
	if got := r.GetTieAcknowledgedOn(); !reflect.DeepEqual(got, []string{c.Nodes[0].Name, c.Nodes[1].Name}) {
		t.Errorf("tie_acknowledged_on = %v, want [%s %s]", got, c.Nodes[0].Name, c.Nodes[1].Name)
	}
	checkLabelRow(rows)

	// Now everywhere.
	acknowledge(c.Nodes[2])
	passAll()
	splitLabel()
	rows = diagnose(t, c, c.Nodes[1])
	r = leaseRow(rows)
	if r.GetClass() != string(corrosion.ClassAcknowledgedTie) {
		t.Errorf("a tie every host acknowledged is %q, want %q (converge lists it ACKNOWLEDGED)",
			r.GetClass(), corrosion.ClassAcknowledgedTie)
	}
	if len(r.GetPerNode()) != len(c.Nodes) {
		t.Errorf("the acknowledged row lost its per-node evidence: %v", r.GetPerNode())
	}
	if got := r.GetTieUnacknowledgedOn(); len(got) != 0 {
		t.Errorf("tie_unacknowledged_on = %v, want none", got)
	}
	checkLabelRow(rows)
}
