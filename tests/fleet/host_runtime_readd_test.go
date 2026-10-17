// Fleet scenario: a host removed while it was down, then re-added with its
// old data directory intact (colonelpanik/litevirt#267 review, I-1).
package fleet

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

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
	l, err := net.Listen("tcp", net.JoinHostPort(n.Address, strconv.Itoa(n.Port)))
	if err != nil {
		t.Fatalf("rebind %s on port %d: %v", n.Name, n.Port, err)
	}
	n.Listener = l
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
	settleLatch(t, c)
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-before-rm", 16, 32, 48, true); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

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

	// d's daemon starts on its old database: its hosts row there is live, so
	// it re-records its serial instead of re-admitting, then reports.
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("register %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-stale-db", 24, 48, 96, true); err != nil {
		t.Fatalf("boot report of %s: %v", d.Name, err)
	}
	// Anti-entropy runs, as it does every minute: it is what spread a retired
	// row's tombstone over d's own live one. hosts itself is not this test's
	// subject (TestFleet_StaleDBReaddConvergesOnTheReadmission is);
	// host_runtime must converge.
	deadline := time.Now().Add(2 * convergeTimeout)
	for {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		apart, err := divergence(c.Nodes)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(apart, "host_runtime") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host_runtime did not converge; apart: %v", apart)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if apart, _ := divergence(c.Nodes); len(apart) > 0 {
		t.Logf("tables still apart after anti-entropy: %v", apart)
		for _, n := range c.Nodes {
			rows, _ := n.DB.Query(ctx, `SELECT * FROM hosts WHERE name = ?`, d.Name)
			for _, r := range rows {
				t.Logf("%s hosts row for %s: %v = %v", n.Name, d.Name, r.Columns, r.Values)
			}
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
