// Fleet scenario: a host removed for good, rebuilt on an empty database and
// re-added under its OLD name keeps one audit chain, and `lv audit verify`
// stays clean on every node.
//
// Observed on the kvm003-f3 lab (drill 6, 2026-10-03 and -04): every rebuilt
// node's daemon wrote its first audited actions within seconds of starting, on
// an audit_log that held none of its own history yet. InsertAuditLog chained
// them onto that empty tail — seq 1, prev_hash "" — a second chain under a host
// name that already had one, so every node reported a hash mismatch and
// duplicated sequence numbers for good. Its key adoption, recorded once the
// daemon's 45 s settle had passed and still before anti-entropy had delivered
// that history, started the new signing contract at seq 0, which put every
// unsigned row the host wrote before it first signed under the contract:
// 98 "unsigned after signed" findings on a log nobody touched.
package fleet

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_AuditChainSurvivesARebuildUnderTheSameName:
//
//  1. d writes three unsigned rows, starts signing, writes three signed rows and
//     publishes a chain head; every node holds all of it and verifies clean;
//  2. d dies, is fence-confirmed and removed with `lv host rm --dead`, which
//     CA-retires its key at seq 6;
//  3. the machine is rebuilt on an empty database with a new key, re-added
//     under the same name and booted. Nothing has replicated into it yet. Its
//     daemon publishes its startup head (which reads its own chain tail) and
//     audits two actions straight away, then tries to adopt its key;
//  4. anti-entropy catches it up, the held rows land and the key is adopted,
//     and it audits one more action;
//  5. every node verifies the log clean, and d's new rows continue its old
//     chain at seq 7, 8 and 9.
func TestFleet_AuditChainSurvivesARebuildUnderTheSameName(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 4517})
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}

	// 1. History from before d signed, then signed history.
	for i := 1; i <= 3; i++ {
		auditRow(t, d, fmt.Sprintf("old-unsigned-%d", i), "vm.start", "vm1")
	}
	for _, n := range c.Nodes {
		signNode(t, n)
	}
	for i := 1; i <= 3; i++ {
		auditRow(t, d, fmt.Sprintf("old-signed-%d", i), "vm.stop", "vm1")
	}
	if err := corrosion.PublishAuditChainHead(ctx, d.DB, d.Name); err != nil {
		t.Fatalf("publish %s's chain head: %v", d.Name, err)
	}
	convergeByAntiEntropy(t, c, convergeTimeout)
	for _, n := range c.Nodes {
		if res := verifyOn(t, n); res.Tampered() || res.Unverified() {
			t.Fatalf("fixture: %s does not verify the log clean before the rebuild: %+v", n.Name, res)
		}
	}

	// 2. d is lost, confirmed off and removed for good.
	d.Stop()
	c.Kill(d)
	if err := a.DB.Execute(ctx,
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"confirm-"+d.Name, d.Name, "manual", "manual-confirmed",
		time.Now().Add(-12*time.Minute).UTC().Format(time.RFC3339), "operator confirmation"); err != nil {
		t.Fatalf("fence-confirm %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatalf("record %s fenced: %v", d.Name, err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	if n := rowCount(t, a, `SELECT count(*) AS n FROM audit_key_lifecycle
		WHERE host_name = ? AND event = 'retired' AND by_key_id = 'cluster-ca' AND at_seq = 6`, d.Name); n != 1 {
		t.Fatalf("fixture: `lv host rm` recorded %d CA retirement(s) of %s's key at seq 6, want 1", n, d.Name)
	}

	// 3. The rebuilt machine, re-added under the same name.
	serial := rebuildWithEmptyDB(t, c, d, a)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: serial,
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	// Nothing reaches the new machine yet: its daemon has just started.
	for _, p := range c.Nodes {
		if p != d {
			c.SetLinkFault(p, d, LinkFault{Block: true})
		}
	}
	bootRebuiltNode(t, d, serial)
	d.DB.MarkReplicaStale("process started on a fresh database (fleet: modelled reinstall)")
	// The daemon's startup wiring: `lv host add` configured join peers.
	d.DB.HoldAuditUntilCaughtUp(corrosion.AuditHoldConfig{
		Host: d.Name, Joiner: true, SpoolDir: filepath.Join(t.TempDir(), corrosion.AuditHoldDirName),
	})

	// wireAuditKeyring: the rebuilt machine's new key signs from the start.
	kr := loadKeyring(t, d)
	d.DB.SetAuditKeyring(kr)
	// runAuditChainHeads publishes once at startup, reading the chain tail.
	if err := corrosion.PublishAuditChainHead(ctx, d.DB, d.Name); err != nil {
		t.Fatalf("startup head on %s: %v", d.Name, err)
	}
	auditRow(t, d, "new-1", "cluster.lease_term_tie.acknowledge", "failover")
	auditRow(t, d, "new-2", "ct.start", "ct1")
	// Held: nothing of d's has been written on the empty replica.
	if n := rowCount(t, d, `SELECT count(*) AS n FROM audit_log WHERE host_name = ?`, d.Name); n != 0 {
		t.Fatalf("%s appended %d audit row(s) to its own chain before it had caught up from its peers", d.Name, n)
	}
	// finishAuditKeyLifecycle, once its settle has passed: on 4ca641c2 this
	// adopted from the empty replica, at seq 0.
	if err := adoptOn(ctx, d, kr); !errors.Is(err, corrosion.ErrAuditChainNotCaughtUp) {
		t.Fatalf("%s adopted its key before its audit chain caught up (err=%v)", d.Name, err)
	}

	// 4. Catch-up.
	c.ClearLinkFaults()
	convergeByAntiEntropy(t, c, 2*convergeTimeout)
	if ok, why := d.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("%s did not catch up: %s", d.Name, why)
	}
	// awaitAuditChainCaughtUp's poll lands the held rows; then the adoption.
	if d.DB.AuditChainHeld(ctx, d.Name) {
		t.Fatalf("%s still holds its audit rows after catching up", d.Name)
	}
	if err := adoptOn(ctx, d, kr); err != nil {
		t.Fatalf("adopt %s's key once caught up: %v", d.Name, err)
	}
	auditRow(t, d, "new-3", "vm.repair-owner", "vm1")
	convergeByAntiEntropy(t, c, 2*convergeTimeout)

	// 5.
	for _, n := range []*Node{a, b, d} {
		res := verifyOn(t, n)
		if res.Tampered() || res.Unverified() {
			t.Errorf("%s: the rebuilt %s's chain does not verify clean:\n  broken_at=%q seq_gaps=%v\n  "+
				"unsigned_after_signed=%v\n  retired_key_use=%v truncated=%v never_adopted=%v",
				n.Name, d.Name, res.BrokenAt, res.SeqGaps, res.UnsignedAfterSigned,
				res.RetiredKeyUse, res.TruncatedHosts, res.NeverAdopted)
		}
		for i, id := range []string{"new-1", "new-2", "new-3"} {
			rows, err := n.DB.Query(ctx, `SELECT seq, signature FROM audit_log WHERE id = ?`, id)
			if err != nil || len(rows) != 1 {
				t.Fatalf("%s: read %s: %d rows, %v", n.Name, id, len(rows), err)
			}
			if got, want := rows[0].Int64("seq"), int64(7+i); got != want {
				t.Errorf("%s: %s is at seq %d, want %d (after the six rows the old machine wrote)",
					n.Name, id, got, want)
			}
			if rows[0].String("signature") == "" {
				t.Errorf("%s: %s is unsigned", n.Name, id)
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
