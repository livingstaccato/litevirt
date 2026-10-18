// Fleet scenario: a host removed while it was down, then re-added with its
// old data directory intact (colonelpanik/litevirt#267 review, I-1).
package fleet

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// restartWithNewCert stands in for an operator repairing n and re-adding it
// with `lv host add` while its disk, and so its database, survived: a new host
// certificate and a fresh daemon on the SAME database, which still holds n's
// live hosts row from before the removal. Returns the new serial; the daemon
// has not booted yet.
func restartWithNewCert(t *testing.T, c *Cluster, n *Node) string {
	t.Helper()
	if n.replStarted {
		n.repl.Stop()
		n.replStarted = false
	}
	n.Stop()
	c.mintHostCert(n)
	serial, err := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
	if err != nil {
		t.Fatalf("read %s's new certificate serial: %v", n.Name, err)
	}
	n.rebindPort(t)
	if n.stopServerLoops != nil {
		n.stopServerLoops()
	}
	c.buildServer(n)
	return serial
}

// TestFleet_HostRuntime_AStaleDBReaddReadsItsRealReport: d is removed while it
// is down — every other node retires its host_runtime row as it applies the
// re-admission — and comes back on its old database, where its own row is
// still live. Its boot report must bring the row back on every node: with both
// runtime tokens latched the report no longer writes hosts, so a row left
// retired would leave every node reading the re-admission's reset hosts
// columns (no version, schema 0, no totals) until the daemon next restarts.
// The hosts and host_membership rows, not host_runtime, decide that d is a
// member.
//
// Mutation: the boot report uses the partial upsert, which does not clear
// deleted_at — red.
func TestFleet_HostRuntime_AStaleDBReaddReadsItsRealReport(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2680})
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		retireMembership(t, n)
		retireRuntime(t, n)
	}
	settleByAntiEntropy(t, c, true)
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-before-rm", 16, 32, 48, true); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	// d joined long before it was removed, as in
	// TestFleet_StaleDBReaddConvergesOnTheReadmission: its row's created_at
	// says so on every node (written in place, never logged). Re-admitted
	// within seconds of its first admission instead, d sat inside the
	// incarnation rule's MaxSkewMS grace, the documented edge where its stale
	// row and the re-admission's tie on hosts for good.
	for _, n := range c.Nodes {
		if _, err := n.DB.DB().Exec(`UPDATE hosts SET created_at = '2026-01-01T00:00:00Z' WHERE name = ?`, d.Name); err != nil {
			t.Fatal(err)
		}
	}

	// d goes down; it is removed and re-added while it cannot hear either.
	c.Crash(d)
	survivors := []*Node{a, b}
	if err := corrosion.DeleteHost(ctx, a.DB, d.Name); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the removal on every survivor", func() bool {
		for _, n := range survivors {
			if h, err := corrosion.GetHost(ctx, n.DB, d.Name); err != nil || h != nil {
				return false
			}
		}
		return true
	})
	serial := restartWithNewCert(t, c, d)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: serial,
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the admission on every survivor, its runtime row retired", func() bool {
		for _, n := range survivors {
			h, err := corrosion.GetHost(ctx, n.DB, d.Name)
			if err != nil || h == nil || h.CertSerial != serial || h.Version == "v-before-rm" {
				return false
			}
		}
		return true
	})

	// d's daemon starts on its old database: its hosts row there is live and
	// names the removed machine's serial, so the own-row hold (as the daemon
	// configures it) holds its registration and boot report until the
	// re-admission reaches it; then it reports.
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	if st, err := d.DB.ConfigureOwnRowHold(ctx, corrosion.StaticInstalledCert(serial, "")); err != nil || !st.Held {
		t.Fatalf("%s booted on its old database without the own-row hold: %+v %v", d.Name, st, err)
	}
	ownRowReconcileLegacy(t, d, serial)
	// Every table converges — hosts included, which used to stay apart as an
	// unresolved control_plane tie, 10 runs out of 10 (eqts).
	convergeAll(t, c, d.Name+" booted on its old database", d)
	ref := hostsRowOf(t, a, d.Name)
	for _, n := range c.Nodes {
		if got := hostsRowOf(t, n, d.Name); fmt.Sprint(got) != fmt.Sprint(ref) || got["cert_serial"] != serial {
			t.Errorf("%s holds %s's hosts row as %v, %s as %v", n.Name, d.Name, got, a.Name, ref)
		}
		if k := n.DB.UnresolvedTieCount(); k != 0 {
			t.Errorf("%s tracks %d unresolved tie(s)", n.Name, k)
		}
	}

	for _, n := range c.Nodes {
		h, err := corrosion.GetHost(ctx, n.DB, d.Name)
		if err != nil || h == nil {
			t.Fatalf("%s: %s is not a member after its re-admission: %+v %v", n.Name, d.Name, h, err)
		}
		if h.Version != "v-stale-db" || h.SchemaVersion != corrosion.CurrentSchemaVersion || h.CPUTotal != 24 || h.DiskTotal != 96 {
			t.Errorf("%s reads %s as version=%q schema=%d cpu=%d disk=%d, want its boot report "+
				"(v-stale-db, %d, 24, 96): its host_runtime row was left retired",
				n.Name, d.Name, h.Version, h.SchemaVersion, h.CPUTotal, h.DiskTotal, corrosion.CurrentSchemaVersion)
		}
	}
}

// ownRowReconcileLegacy is ownRowReconcile before the release latches: the
// hold opens on the re-admission, then registration and the boot report run.
func ownRowReconcileLegacy(t *testing.T, d *Node, serial string) {
	t.Helper()
	ctx := context.Background()
	eventually(t, convergeTimeout, d.Name+"'s own-row hold to open", func() bool {
		corrosion.NewAntiEntropy(d.DB, d.PKIDir, 0).RunOnce(ctx)
		st, err := d.DB.EvaluateOwnRowHold(ctx, corrosion.OwnRowHeldSuperseded)
		return err == nil && !st.Held
	})
	if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("register %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-stale-db", 24, 48, 96, true); err != nil {
		t.Fatalf("boot report of %s: %v", d.Name, err)
	}
}
