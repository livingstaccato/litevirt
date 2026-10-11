// Fleet scenario: a host removed while it was down and re-added while its data
// directory still held the OLD database converges on one hosts row, the
// re-admission's (#267 runtime-split re-review 1, Concern 2).
package fleet

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostsRowOf is n's stored hosts row for host, every column, as text.
func hostsRowOf(t *testing.T, n *Node, host string) map[string]string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT * FROM hosts WHERE name = ?`, host)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%s: read the hosts row of %s: %d rows, %v", n.Name, host, len(rows), err)
	}
	out := make(map[string]string, len(rows[0].Columns))
	for i, col := range rows[0].Columns {
		v := rows[0].Values[i]
		if v == nil {
			out[col] = "NULL"
			continue
		}
		if b, ok := v.([]byte); ok {
			v = string(b)
		}
		out[col] = fmt.Sprint(v)
	}
	return out
}

// TestFleet_StaleDBReaddConvergesOnTheReadmission: d is configured (labels, a
// region, a capacity override), goes down, is removed and re-added with a new
// certificate while it cannot hear either, and its daemon then starts on its
// OLD database. There its hosts row is live, so RegisterHost re-records the
// new serial instead of re-admitting, and every write it makes from then on
// is newer than the re-admission, which it can therefore never apply. The
// survivors apply those same writes over the re-admission's reset row, so
// both sides end up holding different content under one updated_at — a tie
// the hosts chain left unresolved (control_plane: grpc_port differs) for good.
//
// Every node must hold one hosts row for d, and it must be the re-admission's:
// no label, region or override of the machine removed under the name, and the
// admission's grpc_port.
//
// The "anti-entropy first" subtests take the other order: the survivors can
// dial d (it is admitted at the port it serves on), and their anti-entropy
// pass pulls d's whole row before any of d's replicated writes reach them.
// That row is newer than the re-admission, and taken whole it brought the
// removed machine's settings back on every survivor, with no tie to report.
//
// Mutations: (1) the re-admission does not stamp its incarnation on created_at
// — red, hosts stays apart (WAL first) or settles on the stale row
// (anti-entropy first); (2) the hosts tie chain does not order two
// incarnations by created_at — red (WAL first); (3) the hosts merge floor
// lets an older incarnation's newer row in — red (anti-entropy first).
func TestFleet_StaleDBReaddConvergesOnTheReadmission(t *testing.T) {
	for _, tc := range []struct {
		name             string
		retired, aeFirst bool
		seed             int64
	}{
		// Every hosts write the boot makes still lands on hosts itself.
		{name: "dual-write", seed: 2671},
		// Both copies retired: the boot report writes host_membership and
		// host_runtime alone, and RegisterHost's serial is the hosts write.
		{name: "both copies retired", retired: true, seed: 2672},
		{name: "dual-write, anti-entropy first", aeFirst: true, seed: 2673},
		{name: "both copies retired, anti-entropy first", retired: true, aeFirst: true, seed: 2674},
	} {
		t.Run(tc.name, func(t *testing.T) {
			staleDBReadd(t, tc.retired, tc.aeFirst, tc.seed)
		})
	}
}

func staleDBReadd(t *testing.T, retired, aeFirst bool, seed int64) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	if retired {
		for _, n := range c.Nodes {
			retireMembership(t, n)
			retireRuntime(t, n)
		}
		c.WaitConverged(t, convergeTimeout)
	}

	// The old machine's per-host settings, which the re-admission resets.
	if err := corrosion.SetHostLabel(ctx, a.DB, d.Name, "gpu", "a100"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostRegion(ctx, a.DB, d.Name, "rack-a"); err != nil {
		t.Fatal(err)
	}
	ratio := 4.0
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: d.Name, CpuOvercommit: &ratio, WatchdogDev: "/dev/watchdog0",
	}); err != nil {
		t.Fatalf("configure %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	// d joined the cluster long before it was removed, not within the second
	// this test takes: its row's created_at says so on every node (written in
	// place, never logged, so it replicates nowhere).
	for _, n := range c.Nodes {
		if _, err := n.DB.DB().Exec(`UPDATE hosts SET created_at = '2026-01-01T00:00:00Z' WHERE name = ?`, d.Name); err != nil {
			t.Fatal(err)
		}
	}
	if got := hostsRowOf(t, d, d.Name); got["labels"] == "NULL" || got["region"] != "rack-a" {
		t.Fatalf("fixture: %s's own row = %v, want the configured labels and region", d.Name, got)
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
	wantPort := "7443" // AdmitHost's RPC admits every host at the default port
	if aeFirst {
		// Admitted at the port d serves on, so the survivors can dial it.
		wantPort = fmt.Sprint(d.Port)
		if err := corrosion.AdmitHost(ctx, a.DB, corrosion.HostRecord{
			Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
			State: corrosion.HostStateJoining, CertSerial: serial,
		}); err != nil {
			t.Fatalf("admit %s again: %v", d.Name, err)
		}
	} else if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: serial,
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the admission on every survivor", func() bool {
		for _, n := range survivors {
			h, err := corrosion.GetHost(ctx, n.DB, d.Name)
			if err != nil || h == nil || h.CertSerial != serial {
				return false
			}
		}
		return true
	})
	intent := hostsRowOf(t, a, d.Name)
	if intent["labels"] != "NULL" || intent["region"] != "default" || intent["grpc_port"] != wantPort {
		t.Fatalf("fixture: the re-admission on %s = %v, want its reset row", a.Name, intent)
	}

	// d's daemon starts on its old database, before it has heard anything:
	// registerHost finds its own row live and re-records the serial, then the
	// boot report. Both are newer than the re-admission.
	if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("register %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-stale-db", 24, 48, 96, true); err != nil {
		t.Fatalf("boot report of %s: %v", d.Name, err)
	}
	if got := hostsRowOf(t, d, d.Name); got["region"] != "rack-a" {
		t.Fatalf("fixture: %s's own row = %v, want the stale database's (region rack-a)", d.Name, got)
	}
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	if aeFirst {
		// The survivors' anti-entropy reaches d before any of d's writes do:
		// d's replicator has not started. That the pull reached d at all is
		// shown by a probe label on a's row that only d holds until then.
		if err := corrosion.SetHostLabel(ctx, d.DB, a.Name, "ae-probe", d.Name); err != nil {
			t.Fatal(err)
		}
		for _, n := range survivors {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		for _, n := range survivors {
			if h, err := corrosion.GetHost(ctx, n.DB, a.Name); err != nil || h == nil || h.Labels["ae-probe"] != d.Name {
				t.Fatalf("fixture: %s's anti-entropy pass did not reach %s (reads %s as %+v, %v)", n.Name, d.Name, a.Name, h, err)
			}
			if got := hostsRowOf(t, n, d.Name); got["region"] != "default" || got["watchdog_dev"] != "NULL" {
				t.Errorf("%s took %s's stale row from its database over the re-admission: %v", n.Name, d.Name, got)
			}
		}
	}
	d.repl.Start(c.ctx)
	d.replStarted = true

	deadline := time.Now().Add(2 * convergeTimeout)
	for {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		apart, err := divergence(c.Nodes)
		if err != nil {
			t.Fatalf("divergence: %v", err)
		}
		if len(apart) == 0 {
			break
		}
		if time.Now().After(deadline) {
			for _, n := range c.Nodes {
				t.Logf("%s holds %s as %v", n.Name, d.Name, hostsRowOf(t, n, d.Name))
			}
			t.Fatalf("the cluster did not converge after %s booted on its old database; tables still apart: %v",
				d.Name, apart)
		}
		time.Sleep(200 * time.Millisecond)
	}

	want := hostsRowOf(t, a, d.Name)
	for _, n := range c.Nodes {
		got := hostsRowOf(t, n, d.Name)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s's hosts row for %s differs from %s's:\n %s: %v\n %s: %v",
				n.Name, d.Name, a.Name, n.Name, got, a.Name, want)
		}
		if got["labels"] != "NULL" || got["region"] != "default" || got["grpc_port"] != wantPort ||
			got["cpu_overcommit"] != "0" || got["watchdog_dev"] != "NULL" || got["cert_serial"] != serial ||
			got["deleted_at"] != "NULL" {
			t.Errorf("%s holds %s's row as %v; want the re-admission's (no labels, region default, "+
				"grpc_port %s, no overcommit, no watchdog, serial %s, live)", n.Name, d.Name, got, wantPort, serial)
		}
		h, err := corrosion.GetHost(ctx, n.DB, d.Name)
		if err != nil || h == nil {
			t.Fatalf("%s: %s is not a member after its re-admission: %+v %v", n.Name, d.Name, h, err)
		}
		if h.State != "active" {
			t.Errorf("%s reads %s as %q, want its boot state active", n.Name, d.Name, h.State)
		}
	}
	for _, n := range c.Nodes {
		if k := n.DB.UnresolvedTieCount(); k != 0 {
			t.Errorf("%s still tracks %d unresolved tie(s) once every table converged", n.Name, k)
		}
	}
}
