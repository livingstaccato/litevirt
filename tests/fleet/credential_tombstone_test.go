// Fleet scenario: a host re-added while its data directory still held the OLD
// database must not bring the old machine's IPMI password back, on itself or
// anywhere else.
package fleet

import (
	"context"
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

func retiredCredentialStaysRetired(t *testing.T, clearLatched bool, seed int64) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	c.WaitConverged(t, convergeTimeout)

	const oldPass = "Old-Machine-Pass-5101"
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

	for _, n := range c.Nodes {
		fs := fenceSettingsOf(t, n, d.Name)
		if fs.hasCredRow && fs.credRow == oldPass {
			t.Errorf("%s holds a live credential row for %s with the old machine's password", n.Name, d.Name)
		}
		if fs.pass == oldPass {
			t.Errorf("%s reads %s's IPMI password as the old machine's", n.Name, d.Name)
		}
	}
}
