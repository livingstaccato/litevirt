// Fleet scenario: hosts removed for good, rebuilt on empty databases and re-added
// under their OLD names keep one audit chain each, and `lv audit verify` stays
// clean on every node.
//
// Observed on the kvm003-f3 lab (drill 6, 2026-10-03 and -04): drill 6 destroys
// three of five nodes and rebuilds them together. Every rebuilt daemon wrote its
// first audited actions within seconds of starting, on an audit_log that held
// none of its own history. InsertAuditLog chained them onto that empty tail —
// seq 1, prev_hash "" — a second chain under a name that already had one, so
// every node reported a hash mismatch and duplicated seqs for good. Its key
// adoption, still before anti-entropy had delivered that history, started the
// new signing contract at seq 0 and put every unsigned row the host wrote before
// it first signed under the contract: 98 "unsigned after signed" findings on a
// log nobody touched.
//
// The three rebuild TOGETHER is the case that matters: an anti-entropy exchange
// between two rebuilt nodes completes while both are empty, so "one exchange has
// completed" says nothing about whether a node holds its own history. What it
// waits for comes from the admitting node instead (AdmitHostResponse, signed by
// `lv host add` into the new machine's pki dir).
package fleet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_AuditChainSurvivesThreeRebuildsUnderTheSameNames:
//
//  1. each of c, d and e writes two unsigned rows, starts signing, writes two
//     signed rows and publishes a chain head; every node verifies clean;
//  2. all three die, are fence-confirmed and removed with `lv host rm --dead`,
//     which CA-retires each key at seq 4;
//  3. the three machines are rebuilt on empty databases with new keys and
//     re-added under the same names; `lv host add` writes each one's signed
//     admission record. They boot cut off from the survivors, and each audits
//     two actions straight away and tries to adopt its key;
//  4. anti-entropy runs among the three rebuilt nodes only: their exchanges
//     complete against peers as empty as themselves, and nothing may land;
//  5. the links heal and anti-entropy delivers the history; the held rows land,
//     each key is adopted, and each node audits one more action;
//  6. all five nodes verify the log clean, and each rebuilt host's new rows
//     continue its old chain at seq 5, 6 and 7.
func TestFleet_AuditChainSurvivesThreeRebuildsUnderTheSameNames(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 4519})
	a := c.Nodes[0]
	survivors, lost := c.Nodes[:2], c.Nodes[2:]
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}

	// 1.
	for _, n := range lost {
		for i := 1; i <= 2; i++ {
			auditRow(t, n, fmt.Sprintf("%s-old-unsigned-%d", n.Name, i), "vm.start", "vm1")
		}
	}
	for _, n := range c.Nodes {
		signNode(t, n)
	}
	for _, n := range lost {
		for i := 1; i <= 2; i++ {
			auditRow(t, n, fmt.Sprintf("%s-old-signed-%d", n.Name, i), "vm.stop", "vm1")
		}
		if err := corrosion.PublishAuditChainHead(ctx, n.DB, n.Name); err != nil {
			t.Fatalf("publish %s's chain head: %v", n.Name, err)
		}
	}
	convergeByAntiEntropy(t, c, convergeTimeout)
	for _, n := range c.Nodes {
		if res := verifyOn(t, n); res.Tampered() || res.Unverified() {
			t.Fatalf("fixture: %s does not verify the log clean before the rebuild: %+v", n.Name, res)
		}
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
			t.Fatalf("fence-confirm %s: %v", n.Name, err)
		}
		if err := corrosion.UpdateHostState(ctx, a.DB, n.Name, "fenced"); err != nil {
			t.Fatalf("record %s fenced: %v", n.Name, err)
		}
		if err := cli.HostRemoveDead(ctx, c.SelfClient(a), n.Name, false); err != nil {
			t.Fatalf("lv host rm --dead %s: %v", n.Name, err)
		}
		if k := rowCount(t, a, `SELECT count(*) AS n FROM audit_key_lifecycle
			WHERE host_name = ? AND event = 'retired' AND by_key_id = 'cluster-ca' AND at_seq = 4`, n.Name); k != 1 {
			t.Fatalf("fixture: `lv host rm` recorded %d CA retirement(s) of %s's key at seq 4, want 1", k, n.Name)
		}
	}

	// 3. Rebuilt and re-added; `lv host add` writes the admission record.
	keyrings := map[string]*corrosion.AuditKeyring{}
	serials := map[string]string{}
	for _, n := range lost {
		serial := rebuildWithEmptyDB(t, c, n, a)
		admitted, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
			Name: n.Name, Address: n.Address, CertSerial: serial,
		})
		if err != nil {
			t.Fatalf("admit %s again: %v", n.Name, err)
		}
		if admitted.GetAuditTailSeq() != 4 {
			t.Fatalf("%s admitted with audit tail %d, want 4", n.Name, admitted.GetAuditTailSeq())
		}
		rejoin, err := cli.AuditRejoinFile(cli.PKIDir(), n.Name, admitted)
		if err != nil {
			t.Fatalf("sign %s's admission record: %v", n.Name, err)
		}
		if err := os.WriteFile(filepath.Join(n.PKIDir, corrosion.AuditRejoinFileName), rejoin, 0o644); err != nil {
			t.Fatal(err)
		}
		serials[n.Name] = serial
	}
	// Every admission, and each rebuilt machine's boot write, has reached the
	// other rebuilt machines' hosts tables — as replication between them
	// delivers it — so the three can dial and authenticate each other.
	deliverHosts := func(from *Node, where string, args ...any) {
		rows, err := from.DB.Query(ctx, `SELECT * FROM hosts`+where, args...)
		if err != nil {
			t.Fatalf("read %s's host rows: %v", from.Name, err)
		}
		for _, n := range lost {
			if n == from {
				continue
			}
			for _, r := range rows {
				marks := strings.TrimSuffix(strings.Repeat("?, ", len(r.Columns)), ", ")
				if _, err := n.DB.DB().Exec(`INSERT OR REPLACE INTO hosts (`+strings.Join(r.Columns, ", ")+`) VALUES (`+marks+`)`,
					r.Values...); err != nil {
					t.Fatalf("deliver a host row to %s: %v", n.Name, err)
				}
			}
		}
	}
	deliverHosts(a, "")
	for _, n := range lost {
		bootRebuiltNode(t, n, serials[n.Name])
		n.DB.MarkReplicaStale("process started on a fresh database (fleet: modelled reinstall)")
	}
	for _, n := range lost {
		deliverHosts(n, ` WHERE name = ?`, n.Name)
	}
	// The fleet's nodes serve on their own ports, which an admission (7443)
	// does not record, so for step 4 each rebuilt node dials the others where
	// they are. Put back before the cluster converges: the rows are not logged.
	type portKey struct{ at, of string }
	ports := map[portKey]int64{}
	for _, n := range lost {
		for _, o := range lost {
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
	restorePorts := func() {
		for k, p := range ports {
			if _, err := c.Node(k.at).DB.DB().Exec(`UPDATE hosts SET grpc_port = ? WHERE name = ?`, p, k.of); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Cut off from the survivors, not from each other.
	for _, s := range survivors {
		for _, n := range lost {
			c.SetLinkFaultBoth(s, n, LinkFault{Block: true})
		}
	}
	for _, n := range lost {
		// The daemon's startup wiring, in its order.
		cfg, err := corrosion.ConfigureAuditHold(ctx, n.DB, n.PKIDir, n.Name,
			filepath.Join(t.TempDir(), corrosion.AuditHoldDirName))
		if err != nil || cfg.Target != 4 {
			t.Fatalf("%s: ConfigureAuditHold = %+v, %v; want target 4", n.Name, cfg, err)
		}
		kr := loadKeyring(t, n)
		keyrings[n.Name] = kr
		n.DB.SetAuditKeyring(kr)
		if err := corrosion.PublishAuditChainHead(ctx, n.DB, n.Name); err != nil {
			t.Fatalf("startup head on %s: %v", n.Name, err)
		}
		auditRow(t, n, n.Name+"-new-1", "cluster.lease_term_tie.acknowledge", "failover")
		auditRow(t, n, n.Name+"-new-2", "ct.start", "ct1")
		if err := adoptOn(ctx, n, kr); !errors.Is(err, corrosion.ErrAuditChainNotCaughtUp) {
			t.Fatalf("%s adopted its key before its audit history arrived (err=%v)", n.Name, err)
		}
	}

	// 4. The rebuilt nodes exchange with each other only.
	for _, n := range lost {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	caughtUp := 0
	for _, n := range lost {
		if ok, _ := n.DB.ReplicaCaughtUp(); ok {
			caughtUp++
		}
		if held, err := n.DB.LandHeldAudit(ctx, n.Name); err != nil || !held {
			t.Fatalf("%s stopped holding after exchanging only with other empty rebuilt nodes (held=%v, %v)",
				n.Name, held, err)
		}
		if k := rowCount(t, n, `SELECT count(*) AS n FROM audit_log WHERE host_name = ?`, n.Name); k != 0 {
			t.Fatalf("%s appended %d row(s) to its own chain before its history arrived", n.Name, k)
		}
	}
	if caughtUp == 0 {
		t.Fatal("fixture: no rebuilt node completed an exchange with another; step 4 tested nothing")
	}

	// 5.
	restorePorts()
	c.ClearLinkFaults()
	convergeByAntiEntropy(t, c, 2*convergeTimeout)
	for _, n := range lost {
		// runAuditHold's poll lands the held rows; then the adoption.
		if held, err := n.DB.LandHeldAudit(ctx, n.Name); err != nil || held {
			t.Fatalf("%s still holds its audit rows after its history arrived (%v)", n.Name, err)
		}
		if err := adoptOn(ctx, n, keyrings[n.Name]); err != nil {
			t.Fatalf("adopt %s's key once caught up: %v", n.Name, err)
		}
		auditRow(t, n, n.Name+"-new-3", "vm.repair-owner", "vm1")
	}
	convergeByAntiEntropy(t, c, 2*convergeTimeout)

	// 6.
	for _, v := range c.Nodes {
		res := verifyOn(t, v)
		if res.Tampered() || res.Unverified() {
			t.Errorf("%s: the rebuilt hosts' chains do not verify clean:\n  broken_at=%q seq_gaps=%v\n  "+
				"unsigned_after_signed=%v\n  retired_key_use=%v truncated=%v never_adopted=%v",
				v.Name, res.BrokenAt, res.SeqGaps, res.UnsignedAfterSigned,
				res.RetiredKeyUse, res.TruncatedHosts, res.NeverAdopted)
		}
		for _, n := range lost {
			for i := 1; i <= 3; i++ {
				id := fmt.Sprintf("%s-new-%d", n.Name, i)
				rows, err := v.DB.Query(ctx, `SELECT seq, signature FROM audit_log WHERE id = ?`, id)
				if err != nil || len(rows) != 1 {
					t.Fatalf("%s: read %s: %d rows, %v", v.Name, id, len(rows), err)
				}
				if got, want := rows[0].Int64("seq"), int64(4+i); got != want {
					t.Errorf("%s: %s is at seq %d, want %d (after the four rows the old machine wrote)",
						v.Name, id, got, want)
				}
				if rows[0].String("signature") == "" {
					t.Errorf("%s: %s is unsigned", v.Name, id)
				}
			}
		}
	}
}

func loadKeyring(t *testing.T, n *Node) *corrosion.AuditKeyring {
	t.Helper()
	kr, err := corrosion.LoadAuditKeyring(n.PKIDir, n.Name)
	if err != nil {
		t.Fatalf("LoadAuditKeyring(%s): %v", n.Name, err)
	}
	return kr
}

func adoptOn(ctx context.Context, n *Node, kr *corrosion.AuditKeyring) error {
	_, err := corrosion.AdoptAuditKey(ctx, n.DB, kr, n.Name)
	return err
}
