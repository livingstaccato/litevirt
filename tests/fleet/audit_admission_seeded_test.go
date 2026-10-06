// Fleet scenario: a rebuilt host that has caught up only from other rebuilt,
// empty hosts must not vouch for another name's audit chain position.
//
// Re-review 2 (I-C): drill 6 rebuilds three hosts together. One that comes back
// under a NEW name holds nothing and so is not holding its audit rows; its first
// anti-entropy exchange can be with a rebuilt peer that is still empty, and that
// exchange completes. Admitting a name with history through it then answered
// "no history", vouched — and the re-added host forked its chain at seq 1.
// The admitting node must be SEEDED: it holds the cluster's history because it
// founded the cluster, was a member at upgrade, or exchanged with a seeded peer.
package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_AnAdmitterSeededOnlyByEmptyPeersRefuses:
//
//  1. x and z write four audit rows each; y writes none (its name is new to
//     the cluster's audit history);
//  2. x, y and z die and are removed with `lv host rm --dead`;
//  3. x is rebuilt and re-added under its old name (held: its record names
//     seq 4); y is rebuilt with no history (not held); z stays removed;
//  4. cut off from the survivors, y and x exchange: y has caught up, but only
//     from x, which is held and empty, so y is not seeded. Admitting z through
//     y is refused;
//  5. once y has exchanged with a survivor it is seeded, and admitting z through
//     it answers z's real position, seq 4, vouched.
func TestFleet_AnAdmitterSeededOnlyByEmptyPeersRefuses(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 4523})
	a, b := c.Nodes[0], c.Nodes[1]
	x, y, z := c.Nodes[2], c.Nodes[3], c.Nodes[4]
	survivors, lost := []*Node{a, b}, []*Node{x, y, z}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
		signNode(t, n)
	}

	// 1.
	for _, n := range []*Node{x, z} {
		for i := 1; i <= 4; i++ {
			auditRow(t, n, fmt.Sprintf("%s-old-%d", n.Name, i), "vm.start", "vm1")
		}
	}
	convergeByAntiEntropy(t, c, convergeTimeout)
	zSeq, zHash, err := corrosion.AuditChainTail(ctx, a.DB, z.Name)
	if err != nil || zSeq != 4 {
		t.Fatalf("fixture: %s's tail on %s = %d, %v; want 4", z.Name, a.Name, zSeq, err)
	}

	// 2.
	withOperatorPKI(t, a)
	for _, n := range lost {
		n.Stop()
		c.Kill(n)
	}
	for _, n := range lost {
		if err := a.DB.Execute(ctx,
			`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
			"confirm-"+n.Name, n.Name, "manual", "manual-confirmed",
			time.Now().Add(-12*time.Minute).UTC().Format(time.RFC3339), "operator confirmation"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpdateHostState(ctx, a.DB, n.Name, "fenced"); err != nil {
			t.Fatal(err)
		}
		if err := cli.HostRemoveDead(ctx, c.SelfClient(a), n.Name, false); err != nil {
			t.Fatalf("lv host rm --dead %s: %v", n.Name, err)
		}
	}

	// 3. x and y rebuilt and re-added through a survivor.
	rebuilt := []*Node{x, y}
	serials := map[string]string{}
	for _, n := range rebuilt {
		serial := rebuildWithEmptyDB(t, c, n, a)
		admitted, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
			Name: n.Name, Address: n.Address, CertSerial: serial,
		})
		if err != nil {
			t.Fatalf("admit %s: %v", n.Name, err)
		}
		rejoin, _, err := cli.AuditRejoinFile(cli.PKIDir(), n.Name, serial, admitted)
		if err != nil {
			t.Fatal(err)
		}
		if rejoin != nil {
			if err := os.WriteFile(filepath.Join(n.PKIDir, corrosion.AuditRejoinFileName), rejoin, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		serials[n.Name] = serial
	}
	rows, err := a.DB.Query(ctx, `SELECT * FROM hosts`)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range rebuilt {
		for _, r := range rows {
			marks := strings.TrimSuffix(strings.Repeat("?, ", len(r.Columns)), ", ")
			if _, err := n.DB.DB().Exec(`INSERT OR REPLACE INTO hosts (`+strings.Join(r.Columns, ", ")+`) VALUES (`+marks+`)`,
				r.Values...); err != nil {
				t.Fatal(err)
			}
		}
		bootRebuiltNode(t, n, serials[n.Name])
		n.DB.MarkReplicaStale("process started on a fresh database (fleet: modelled reinstall)")
		// The daemon's startup: the hold, then the seeded decision.
		if _, err := corrosion.ConfigureAuditHold(ctx, n.DB, n.PKIDir, n.Name, ""); err != nil {
			t.Fatalf("%s: ConfigureAuditHold: %v", n.Name, err)
		}
		if seeded, err := corrosion.DecideAuditSeeded(ctx, n.DB, n.Name); err != nil || seeded {
			t.Fatalf("%s: a fresh replica decided seeded=%v (%v)", n.Name, seeded, err)
		}
	}
	if !x.DB.AuditChainHeld(ctx, x.Name) || y.DB.AuditChainHeld(ctx, y.Name) {
		t.Fatal("fixture: want x held (re-added with history) and y not (no history)")
	}
	// x and y dial each other where they serve; restored before convergence.
	type portKey struct{ at, of string }
	ports := map[portKey]int64{}
	for _, n := range rebuilt {
		for _, o := range rebuilt {
			r, err := n.DB.Query(ctx, `SELECT grpc_port FROM hosts WHERE name = ?`, o.Name)
			if err != nil || len(r) != 1 {
				t.Fatalf("%s: read %s's port: %v", n.Name, o.Name, err)
			}
			ports[portKey{n.Name, o.Name}] = r[0].Int64("grpc_port")
			if _, err := n.DB.DB().Exec(`UPDATE hosts SET grpc_port = ? WHERE name = ?`, o.Port, o.Name); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, s := range survivors {
		for _, n := range rebuilt {
			c.SetLinkFaultBoth(s, n, LinkFault{Block: true})
		}
	}

	// 4.
	corrosion.NewAntiEntropy(y.DB, y.PKIDir, 0).RunOnce(ctx)
	if ok, why := y.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("fixture: %s did not complete an exchange with %s: %s", y.Name, x.Name, why)
	}
	if y.DB.AuditSeeded(ctx) {
		t.Fatalf("%s became seeded from an exchange with %s, which is held and empty", y.Name, x.Name)
	}
	_, err = c.SelfClient(y).AdmitHost(ctx, &pb.AdmitHostRequest{Name: z.Name, Address: z.Address, CertSerial: "0a0b0c0d"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("admitting %s through %s, seeded only by a held empty peer: %v, want Unavailable", z.Name, y.Name, err)
	}

	// 5.
	for k, p := range ports {
		if _, err := c.Node(k.at).DB.DB().Exec(`UPDATE hosts SET grpc_port = ? WHERE name = ?`, p, k.of); err != nil {
			t.Fatal(err)
		}
	}
	// z stays dead: clear only the survivors' links to x and y.
	for _, s := range survivors {
		for _, n := range rebuilt {
			c.SetLinkFaultBoth(s, n, LinkFault{})
		}
	}
	live := []*Node{a, b, x, y}
	deadline := time.Now().Add(2 * convergeTimeout)
	for {
		for _, n := range live {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		apart, err := divergence(live)
		if err != nil {
			t.Fatal(err)
		}
		if len(apart) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the live nodes did not converge; tables still apart: %v", apart)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !y.DB.AuditSeeded(ctx) {
		t.Fatalf("%s is not seeded after exchanging with the survivors", y.Name)
	}
	resp, err := c.SelfClient(y).AdmitHost(ctx, &pb.AdmitHostRequest{Name: z.Name, Address: z.Address, CertSerial: "0a0b0c0d"})
	if err != nil {
		t.Fatalf("admitting %s through a seeded %s: %v", z.Name, y.Name, err)
	}
	if !resp.GetAuditPositionProven() || resp.GetAuditTailSeq() != zSeq || resp.GetAuditTailHash() != zHash {
		t.Fatalf("admitting %s through %s answered %+v; want seq %d hash %s, vouched", z.Name, y.Name, resp, zSeq, zHash)
	}
}
