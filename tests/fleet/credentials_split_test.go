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
// credential row and clears the old column. Then the operator rotates the
// password through the UNLATCHED node, which writes the old column only. The
// latched node's next split pass must carry the rotation into its credential
// row; a pass that trusted its existing row would fence with the password the
// BMC no longer accepts.
//
// Stage 3, the roll completes: the second node latches too. No node's public
// hosts row carries the password any more, a further rotation writes the
// credential row alone, and the fence authenticates with it.
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
	if rep, err := a.DB.SplitCredentials(ctx); err != nil || rep.Copied == 0 || rep.Cleared == 0 {
		t.Fatalf("the latched node's pass did not copy and clear: %+v err=%v", rep, err)
	}
	c.WaitConverged(t, convergeTimeout)
	configureIPMI(t, c, b, victim.Name, "bmc-pass-2")
	c.WaitConverged(t, convergeTimeout)
	if got := oldColumn(t, a, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, victim.Name); got != "bmc-pass-1" {
		t.Fatalf("a's credential row holds %q; this scenario needs it to hold the OLDER password", got)
	}
	// a's periodic pass.
	if _, err := a.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}

	// Stage 3: b latches.
	b.DB.SetCredentialsSplitGate(func() bool { return true })
	if _, err := b.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM hosts WHERE name = ?`, victim.Name); got != "" {
			t.Errorf("%s: hosts.ipmi_pass = %q after both nodes latched; the public row still "+
				"carries the BMC password", n.Name, got)
		}
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, victim.Name); got != "bmc-pass-2" {
			t.Errorf("%s: host_fence_credentials holds %q, want the rotated bmc-pass-2", n.Name, got)
		}
	}

	// A rotation on a latched node never touches the public row.
	configureIPMI(t, c, a, victim.Name, "bmc-pass-3")
	if got := oldColumn(t, a, `SELECT ipmi_pass FROM hosts WHERE name = ?`, victim.Name); got != "" {
		t.Fatalf("a latched ConfigureHost wrote %q into hosts.ipmi_pass; after the latch the "+
			"password belongs in host_fence_credentials only", got)
	}
	c.WaitConverged(t, convergeTimeout, a, b)

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
	if fences[0].IPMIPass != "bmc-pass-3" {
		t.Fatalf("%s fenced %s with IPMI password %q, want the current bmc-pass-3 — a fence "+
			"that authenticates with anything else fails closed", fences[0].By, victim.Name, fences[0].IPMIPass)
	}
}

// TestFleet_CredentialsSplit_LoginAndTokenAuthAfterTheClear: once the split
// has cleared the old columns, a node holding the secrets ONLY in the
// credential tables still authenticates a password login and an API token —
// through the real Login RPC and a real bearer-authenticated call, on a node
// other than the one the credentials were created on.
func TestFleet_CredentialsSplit_LoginAndTokenAuthAfterTheClear(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 2682})
	a, b := c.Nodes[0], c.Nodes[1]
	admin := c.SelfClient(a)

	// Created before the latch: they live in the old columns only.
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "carol", Password: "c4rol-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "carol", Name: "ci"})
	if err != nil || tok.Token == "" {
		t.Fatalf("CreateToken: %+v %v", tok, err)
	}
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
		if _, err := n.DB.SplitCredentials(ctx); err != nil {
			t.Fatalf("%s split: %v", n.Name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)

	// b's public rows carry no secret; the credential tables carry both.
	if got := oldColumn(t, b, `SELECT password_hash FROM users WHERE username = 'carol'`); got != "" {
		t.Fatalf("users.password_hash on %s = %q after the clear", b.Name, got)
	}
	if got := oldColumn(t, b, `SELECT token_hash FROM tokens WHERE username = 'carol'`); got != "" {
		t.Fatalf("tokens.token_hash on %s = %q after the clear", b.Name, got)
	}
	if got := oldColumn(t, b, `SELECT password_hash FROM user_credentials WHERE username = 'carol'`); got == "" {
		t.Fatalf("%s holds no user_credentials row for carol; the scenario would prove nothing", b.Name)
	}

	login, err := c.SelfClient(b).Login(ctx, &pb.LoginRequest{Username: "carol", Password: "c4rol-pass"})
	if err != nil || login.Token == "" {
		t.Fatalf("password login on %s after the clear: %+v %v — a node holding the hash only in "+
			"user_credentials refused a valid password", b.Name, login, err)
	}
	if _, err := c.SelfClient(b).Login(ctx, &pb.LoginRequest{Username: "carol", Password: "wrong"}); err == nil {
		t.Fatal("a wrong password logged in; the login check is not reading a hash at all")
	}
	if _, err := c.bearerClient(b, tok.Token).ListHosts(ctx, &pb.ListHostsRequest{}); err != nil {
		t.Fatalf("API token on %s after the clear: %v — a node holding the hash only in "+
			"token_credentials refused a valid token", b.Name, err)
	}
}
