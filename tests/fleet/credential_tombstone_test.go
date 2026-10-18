// Fleet scenario: a host re-added while its data directory still held the OLD
// database must not bring the old machine's IPMI password back, on itself or
// anywhere else.
package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_RetiredFenceCredentialStaysRetired: d is configured for IPMI
// fencing (credentials_split_v1 latched), goes down, is removed and re-added
// with a new certificate, and its daemon starts on its old database. The
// re-admission retires d's credential row there, but d's own hosts row is
// newer than the admission, so it keeps the old machine's hosts.ipmi_pass.
//
// d's read path must not serve that column, and d's split pass, copy or
// clear, must not turn it back into a live credential row: that row would be
// stamped with d's newer hosts updated_at, replicate, and win LWW over the
// tombstone on every survivor.
//
// Mutations: (1) needsCopy reads a tombstone as "no row" — red on both
// subtests, the old password is live on every node; (2) the host read joins
// only a live credential row, so it falls back to the old column over a
// tombstone — red, d serves the old password.
func TestFleet_RetiredFenceCredentialStaysRetired(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clear bool
		seed  int64
	}{
		{name: "copy pass", seed: 5101},
		{name: "clear pass", clear: true, seed: 5102},
	} {
		t.Run(tc.name, func(t *testing.T) { retiredCredentialStaysRetired(t, tc.clear, tc.seed) })
	}
}

// staleReaddedHost builds the scenario every test here starts from: the last
// node, d, configured for IPMI with oldPass, removed and re-added while down,
// booted on its old database, and reached by the survivors' streams. On
// return d holds the retired credential row and its own stale hosts row with
// oldPass in the old column; d's replicator has not started.
func staleReaddedHost(t *testing.T, nodes int, clearLatched bool, seed int64, oldPass string) (*Cluster, *Node) {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true, FaultSeed: seed})
	a, d := c.Nodes[0], c.Nodes[nodes-1]
	survivors := c.Nodes[:nodes-1]
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	c.WaitConverged(t, convergeTimeout)

	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: d.Name, FenceStrategy: "ipmi", IpmiAddress: "10.77.1.15", IpmiUser: "probe", IpmiPass: oldPass,
	}); err != nil {
		t.Fatalf("configure IPMI on %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if fs := fenceSettingsOf(t, n, d.Name); fs.pass != oldPass || fs.credRow != oldPass {
			t.Fatalf("fixture: %s holds pass %s, credential row %s for %s, want the configured password",
				n.Name, redacted(fs.pass), redacted(fs.credRow), d.Name)
		}
	}

	// d joined long before it was removed, not within the second this test
	// takes (written in place, never logged; see staleDBReadd).
	for _, n := range c.Nodes {
		if _, err := n.DB.DB().Exec(`UPDATE hosts SET created_at = '2026-01-01T00:00:00Z' WHERE name = ?`, d.Name); err != nil {
			t.Fatal(err)
		}
	}

	// d goes down; it is removed and re-added while it cannot hear either.
	c.Crash(d)
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
	// Admitted at the port d serves on, so the survivors' streams reach it.
	if err := corrosion.AdmitHost(ctx, a.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: corrosion.HostStateJoining, CertSerial: serial,
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
	if clearLatched {
		// credentials_clear_v1 latches while d is away; d's old database still
		// holds the password in the old column.
		for _, n := range c.Nodes {
			n.DB.SetCredentialsClearGate(func() bool { return true })
		}
	}

	// d's daemon starts on its old database and re-records its serial: its
	// hosts row is live and newer than the admission.
	if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("register %s: %v", d.Name, err)
	}
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	// The survivors' streams reach d: the admission retires d's credential row
	// there, and its hosts half matches nothing (d's row is live).
	eventually(t, convergeTimeout, "the credential retirement on "+d.Name, func() bool {
		return !fenceSettingsOf(t, d, d.Name).hasCredRow
	})
	if got := hostsRowOf(t, d, d.Name); got["ipmi_pass"] != oldPass {
		t.Fatalf("fixture: %s's own hosts row holds ipmi_pass %s, want the old machine's still in place",
			d.Name, redacted(got["ipmi_pass"]))
	}
	return c, d
}

// assertRetiredEverywhere: every node holds d's credential row retired, and
// reads it as retired with no password — not merely "not the old password",
// which a live EMPTY row would also pass while fencing with no password.
func assertRetiredEverywhere(t *testing.T, nodes []*Node, d *Node) {
	t.Helper()
	for _, n := range nodes {
		fs := fenceSettingsOf(t, n, d.Name)
		if fs.hasCredRow {
			t.Errorf("%s holds a live credential row for %s (%s)", n.Name, d.Name, redacted(fs.credRow))
		}
		h, err := corrosion.GetHost(context.Background(), n.DB, d.Name)
		if err != nil || h == nil {
			t.Fatalf("%s: GetHost(%s): %v", n.Name, d.Name, err)
		}
		if h.IPMIPass != "" || !h.IPMIPassRetired {
			t.Errorf("%s reads %s's IPMI password as %s, retired %v; want none, retired",
				n.Name, d.Name, redacted(h.IPMIPass), h.IPMIPassRetired)
		}
	}
}

func retiredCredentialStaysRetired(t *testing.T, clearLatched bool, seed int64) {
	ctx := context.Background()
	const oldPass = "Old-Machine-Pass-5101"
	c, d := staleReaddedHost(t, 3, clearLatched, seed, oldPass)

	// Channel 2: d's own reader, which feeds its fence paths.
	if fs := fenceSettingsOf(t, d, d.Name); fs.pass == oldPass {
		t.Errorf("%s reads its own IPMI password as the old machine's once its credential row is retired", d.Name)
	}

	// Channel 1: d's split pass runs (the daemon runs it every cycle), then d
	// rejoins replication and every node converges.
	rep, err := d.DB.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("%s's split pass: %v", d.Name, err)
	}
	if rep.Copied != 0 {
		t.Errorf("%s's split pass copied %d secrets over the retired credential row, want 0", d.Name, rep.Copied)
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	convergeByAntiEntropy(t, c, 2*convergeTimeout)

	assertRetiredEverywhere(t, c.Nodes, d)
}

// TestFleet_AJoinerWithoutTheTombstoneDoesNotRevive (review I-1(a)): e took
// d's stale hosts row on a public pull before any sensitive pull, so it holds
// the old machine's password in the old column and no credential row at all.
// It cannot tell that from a password never copied, so its split pass must
// copy nothing until it has merged the sensitive lane — by which time it holds
// the tombstone. Its state is set in place, as that first public pull would
// leave it.
//
// Mutation: drop the sensitive-merge gate from the copy pass — red, e's copy
// is newer than the tombstone and sensitive anti-entropy carries it to every
// node.
func TestFleet_AJoinerWithoutTheTombstoneDoesNotRevive(t *testing.T) {
	ctx := context.Background()
	const oldPass = "Old-Machine-Pass-5103"
	c, d := staleReaddedHost(t, 4, false, 5103, oldPass)
	e := c.Nodes[2]

	rows, err := d.DB.Query(ctx, `SELECT * FROM hosts WHERE name = ?`, d.Name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s's stale row: %d %v", d.Name, len(rows), err)
	}
	r := rows[0]
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(r.Columns)), ", ")
	if _, err := e.DB.DB().Exec(`INSERT OR REPLACE INTO hosts (`+strings.Join(r.Columns, ", ")+`) VALUES (`+marks+`)`,
		r.Values...); err != nil {
		t.Fatalf("give %s the stale row: %v", e.Name, err)
	}
	if _, err := e.DB.DB().Exec(`DELETE FROM host_fence_credentials WHERE host_name = ?`, d.Name); err != nil {
		t.Fatal(err)
	}
	e.DB.MarkSensitiveLaneUnmergedForTests()
	if got := hostsRowOf(t, e, d.Name); got["ipmi_pass"] != oldPass {
		t.Fatalf("fixture: %s holds ipmi_pass %s for %s, want the stale row's", e.Name, redacted(got["ipmi_pass"]), d.Name)
	}

	rep, err := e.DB.SplitCredentials(ctx)
	if err != nil {
		t.Fatalf("%s's split pass: %v", e.Name, err)
	}
	if rep.Copied != 0 {
		t.Errorf("%s copied %d secrets before merging the sensitive lane, want 0", e.Name, rep.Copied)
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	convergeByAntiEntropy(t, c, 2*convergeTimeout)
	if ok, err := e.DB.MayCopyHostCredentials(ctx); err != nil || !ok {
		t.Fatalf("%s never recorded a sensitive-lane merge", e.Name)
	}
	// Its next pass, now merged, holds the tombstone and copies nothing.
	if _, err := e.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	convergeByAntiEntropy(t, c, 2*convergeTimeout)
	assertRetiredEverywhere(t, c.Nodes, d)
}

// TestFleet_APreviousBuildsReviveIsRefused (review I-1(b)): d runs the
// previous build, whose split pass reads the tombstone as "no row" and copies
// the old column back: its own row goes live, and it logs the credential upsert
// alone, stamped with its stale hosts row's newer updated_at. Every receiver
// on this build must keep its tombstone. That build's writer cannot be fixed;
// the entry, which carries no operator password write, is what is refused.
//
// Then anti-entropy runs: d still holds the live row, newer than the
// tombstone, and every survivor's sensitive pull from d finds it. A row
// carries no entry to judge, so no row merge turns a retired credential live.
//
// Mutations: remove the receiver's WAL revive guard — red at the WAL-lane
// check; remove the anti-entropy merge guard — red after the pulls.
func TestFleet_APreviousBuildsReviveIsRefused(t *testing.T) {
	ctx := context.Background()
	const oldPass = "Old-Machine-Pass-5104"
	c, d := staleReaddedHost(t, 3, false, 5104, oldPass)
	a := c.Nodes[0]
	survivors := c.Nodes[:2]

	// The previous build's pass on d: its own row revived in place, and the
	// entry it logs.
	stale := hostsRowOf(t, d, d.Name)["updated_at"]
	if _, err := d.DB.DB().Exec(`UPDATE host_fence_credentials SET ipmi_pass = ?, deleted_at = NULL, updated_at = ?
		WHERE host_name = ?`, oldPass, stale, d.Name); err != nil {
		t.Fatal(err)
	}
	if err := d.DB.Execute(ctx, corrosion.HostFenceCredentialUpsertSQL, d.Name, oldPass, stale); err != nil {
		t.Fatalf("the previous build's copy: %v", err)
	}
	// A later write in d's stream shows each survivor has applied the one
	// before it.
	if err := corrosion.SetHostLabel(ctx, d.DB, a.Name, "revive-probe", d.Name); err != nil {
		t.Fatal(err)
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	eventually(t, convergeTimeout, "d's stream on every survivor", func() bool {
		for _, n := range survivors {
			h, err := corrosion.GetHost(ctx, n.DB, a.Name)
			if err != nil || h == nil || h.Labels["revive-probe"] != d.Name {
				return false
			}
		}
		return true
	})
	assertRetiredEverywhere(t, survivors, d)

	// The sensitive lane: every survivor pulls from d (and from each other)
	// several times over.
	for range 3 {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
	}
	if fs := fenceSettingsOf(t, d, d.Name); !fs.hasCredRow {
		t.Fatalf("fixture: %s no longer holds the previous build's live row; the pulls proved nothing", d.Name)
	}
	assertRetiredEverywhere(t, survivors, d)
}
