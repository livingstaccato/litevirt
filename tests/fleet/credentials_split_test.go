// Fleet scenarios: secret columns on the sensitive lane
// (colonelpanik/litevirt#268) across a rolling upgrade.
//
// hosts.ipmi_pass, users.password_hash and tokens.token_hash move to
// host_fence_credentials, user_credentials and token_credentials once
// credentials_split_v1 latches. The hazards are all multi-node — a peer that
// cannot decode a credential-table statement, a peer that reads only the old
// column, a node whose latch formed before its neighbour's — so they are driven
// here, over real replication between independent replicas.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

var credentialTables = []string{"host_fence_credentials", "user_credentials", "token_credentials"}

func configureIPMI(t *testing.T, c *Cluster, via *Node, host, pass string) {
	t.Helper()
	if _, err := c.SelfClient(via).ConfigureHost(context.Background(), &pb.ConfigureHostRequest{
		Name: host, FenceStrategy: "ipmi", IpmiAddress: "10.0.1.20", IpmiUser: "root", IpmiPass: pass,
	}); err != nil {
		t.Fatalf("configure IPMI on %s via %s: %v", host, via.Name, err)
	}
}

// oldColumn is what a PREVIOUS-RELEASE node reads for a secret: the column on
// the public row, and nothing else. This harness runs one binary, so an old
// reader is stood in for by the exact query that release's reader runs.
func oldColumn(t *testing.T, n *Node, query string, args ...interface{}) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), query, args...)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%s: %q: rows=%d err=%v", n.Name, query, len(rows), err)
	}
	for _, v := range rows[0].Values {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func assertNoCredentialStatements(t *testing.T, n *Node) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", n.Name, err)
	}
	for _, r := range rows {
		for _, tbl := range credentialTables {
			if strings.Contains(r.String("stmts"), tbl) {
				t.Fatalf("%s put a %s statement on its replication stream before the latch. A "+
					"previous-release peer has no ledger entry for it, so its apply fails closed and "+
					"its watermark stalls:\n%s", n.Name, tbl, r.String("stmts"))
			}
		}
	}
}

// TestFleet_CredentialsSplit_AnIPMIFenceReadsThePasswordMidRoll: an IPMI fence
// authenticates with the CURRENT password at every stage of a roll.
//
// Stage 1, nothing latched — the state for as long as any previous-release
// host is listening. The password must stay in hosts.ipmi_pass, where that
// host's fencer reads it, and nothing naming a credential table may reach any
// replication stream.
//
// Stage 2, one node latched and its neighbour not yet — per-node markers make
// this window routine. The latched node copies the password into its
// credential row; then the operator rotates it through the UNLATCHED node,
// which writes the old column only. The latched coordinator must fence with
// the rotated password, not the older one its credential row still holds.
func TestFleet_CredentialsSplit_AnIPMIFenceReadsThePasswordMidRoll(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 268})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	insertVM(t, a, "vm-victim", victim.Name)

	// Stage 1: no node's gate is open.
	configureIPMI(t, c, a, victim.Name, "bmc-pass-1")
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM hosts WHERE name = ?`, victim.Name); got != "bmc-pass-1" {
			t.Fatalf("%s: hosts.ipmi_pass = %q; a previous-release fencer on this node would "+
				"authenticate with the wrong password", n.Name, got)
		}
		assertNoCredentialStatements(t, n)
	}

	// Stage 2: a latches; b has not yet.
	a.DB.SetCredentialsSplitGate(func() bool { return true })
	if rep, err := a.DB.SplitCredentials(ctx); err != nil || rep.Copied == 0 {
		t.Fatalf("the latched node copied nothing: %+v err=%v", rep, err)
	}
	c.WaitConverged(t, convergeTimeout)
	configureIPMI(t, c, b, victim.Name, "bmc-pass-2")
	c.WaitConverged(t, convergeTimeout)
	if got := oldColumn(t, a, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, victim.Name); got != "bmc-pass-1" {
		t.Fatalf("a's credential row holds %q; this scenario needs it to hold the OLDER password", got)
	}

	// The victim fails; a coordinates.
	c.Isolate(victim)
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, a)

	fences := cs.Fences()
	if len(fences) != 1 || fences[0].Target != victim.Name {
		t.Fatalf("expected one fence of %s, got %+v", victim.Name, fences)
	}
	if fences[0].IPMIPass != "bmc-pass-2" {
		t.Fatalf("%s fenced %s with IPMI password %q, want the rotated bmc-pass-2. Its credential "+
			"row predates a rotation an unlatched peer wrote to the old column; a reader that "+
			"trusts the credential row unconditionally fails the fence closed on a BMC that "+
			"has since changed its password", fences[0].By, victim.Name, fences[0].IPMIPass)
	}
}
