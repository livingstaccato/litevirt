// Fleet scenarios: clearing the old secret columns once credentials_clear_v1
// has latched (docs/design/credentials-clear.md, colonelpanik/litevirt#268).
//
// The hazards are multi-node: a clear that reaches a host still reading only
// the old columns, a host on the previous (dual-write) build authenticating
// against a peer that has cleared, and a maintenance host on that build that
// must hold the latch off. They are driven here over real replication between
// independent replicas.
package fleet

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// latchAndClear opens both credential gates on each node — the state of a
// node that has durably latched credentials_split_v1 and credentials_clear_v1
// — and runs its pass.
func latchAndClear(t *testing.T, nodes ...*Node) {
	t.Helper()
	for _, n := range nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
		n.DB.SetCredentialsClearGate(func() bool { return true })
		if _, err := n.DB.SplitCredentials(context.Background()); err != nil {
			t.Fatalf("%s clearing pass: %v", n.Name, err)
		}
	}
}

// publicDump is n's operator-safe state dump as plain JSON text.
func publicDump(t *testing.T, n *Node) string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(n.DB.DumpStateBytes()))
	if err != nil {
		t.Fatalf("%s dump: %v", n.Name, err)
	}
	defer gz.Close()
	b, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("%s dump: %v", n.Name, err)
	}
	return string(b)
}

// assertNoOldColumnSecret fails when any public row on n still carries a
// secret in its old column.
func assertNoOldColumnSecret(t *testing.T, n *Node, stage string) {
	t.Helper()
	for _, q := range []string{
		`SELECT username AS k, password_hash AS v FROM users WHERE password_hash != ''`,
		`SELECT id AS k, token_hash AS v FROM tokens WHERE token_hash != ''`,
		`SELECT name AS k, ipmi_pass AS v FROM hosts WHERE ipmi_pass IS NOT NULL AND ipmi_pass != ''`,
	} {
		rows, err := n.DB.Query(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %s: %v", n.Name, q, err)
		}
		for _, r := range rows {
			t.Errorf("%s %s: public row %s still carries a secret in its old column (%q)",
				n.Name, stage, r.String("k"), r.String("v"))
		}
	}
}

// assertAuthenticates logs in, uses the API token and reads the IPMI password
// the fencer would use, all on n.
func assertAuthenticates(t *testing.T, c *Cluster, n *Node, user, password, token, bmc, ipmi string) {
	t.Helper()
	ctx := context.Background()
	if login, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: user, Password: password}); err != nil || login.Token == "" {
		t.Errorf("%s: password login for %s: %+v %v", n.Name, user, login, err)
	}
	if _, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: user, Password: password + "-wrong"}); err == nil {
		t.Errorf("%s: a wrong password logged in; the check is not reading a hash at all", n.Name)
	}
	if _, err := c.bearerClient(n, token).ListHosts(ctx, &pb.ListHostsRequest{}); err != nil {
		t.Errorf("%s: API token: %v", n.Name, err)
	}
	if h, err := corrosion.GetHost(ctx, n.DB, bmc); err != nil || h == nil || h.IPMIPass != ipmi {
		t.Errorf("%s: the fencer reads IPMI password %+v (err %v), want %q", n.Name, h, err, ipmi)
	}
}

// TestFleet_CredentialsClear_AfterTheLatchNoPublicRowCarriesASecret: once every
// node has latched the clear and run its pass, no public row and no public dump
// on any node carries a secret, and a password login, an API token and the
// fencer's IPMI read all work from every node — for secrets set before the
// latch, and for secrets set or rotated after it through different nodes.
func TestFleet_CredentialsClear_AfterTheLatchNoPublicRowCarriesASecret(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2688})
	a, b, bmc := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "ivan", Password: "iv4n-before", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok1, err := c.SelfClient(a).CreateToken(ctx, &pb.CreateTokenRequest{Username: "ivan", Name: "before"})
	if err != nil || tok1.Token == "" {
		t.Fatalf("CreateToken: %+v %v", tok1, err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-before")
	c.WaitConverged(t, convergeTimeout)
	if got := oldColumn(t, b, `SELECT ipmi_pass FROM hosts WHERE name = ?`, bmc.Name); got != "bmc-before" {
		t.Fatalf("%s: hosts.ipmi_pass = %q before the latch; the scenario would prove nothing", b.Name, got)
	}

	latchAndClear(t, c.Nodes...)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		assertNoOldColumnSecret(t, n, "after the clearing pass")
		dump := publicDump(t, n)
		for _, secret := range []string{"bmc-before", oldColumn(t, n, `SELECT password_hash FROM user_credentials WHERE username = 'ivan'`)} {
			if secret == "" || strings.Contains(dump, secret) {
				t.Errorf("%s: the public dump carries %q after the clear", n.Name, secret)
			}
		}
		assertAuthenticates(t, c, n, "ivan", "iv4n-before", tok1.Token, bmc.Name, "bmc-before")
	}

	// Rotations and new secrets after the latch, through different nodes.
	if _, err := c.SelfClient(b).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "ivan", NewPassword: "iv4n-after",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	tok2, err := c.SelfClient(b).CreateToken(ctx, &pb.CreateTokenRequest{Username: "ivan", Name: "after"})
	if err != nil || tok2.Token == "" {
		t.Fatalf("CreateToken after the latch: %+v %v", tok2, err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-after")
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		assertNoOldColumnSecret(t, n, "after post-latch writes")
		if strings.Contains(publicDump(t, n), "bmc-after") {
			t.Errorf("%s: the public dump carries the IPMI password set after the latch", n.Name)
		}
		assertAuthenticates(t, c, n, "ivan", "iv4n-after", tok2.Token, bmc.Name, "bmc-after")
		if _, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: "ivan", Password: "iv4n-before"}); err == nil {
			t.Errorf("%s accepted the rotated-out password", n.Name)
		}
	}
}

// TestFleet_CredentialsClear_APreviousBuildNodeAuthenticatesAgainstAClearedPeer
// is the rollback half. b stands for a host on the build before the clear (or
// one rolled back to it): credentials_split_v1 latched, credentials_clear_v1
// not. a has latched the clear, so its clears empty b's old columns. b must
// still log users in, validate tokens and read the IPMI password — it reads the
// credential rows — including for secrets a writes after the clear and for its
// own dual-written ones, which a's next pass clears.
func TestFleet_CredentialsClear_APreviousBuildNodeAuthenticatesAgainstAClearedPeer(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2689})
	a, b, bmc := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "judy", Password: "jud7-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := c.SelfClient(a).CreateToken(ctx, &pb.CreateTokenRequest{Username: "judy", Name: "ci"})
	if err != nil || tok.Token == "" {
		t.Fatalf("CreateToken: %+v %v", tok, err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-one")
	c.WaitConverged(t, convergeTimeout)
	latchAndSplit(t, c.Nodes...)
	c.WaitConverged(t, convergeTimeout)

	latchAndClear(t, a) // b and bmc stay on the dual-write build
	c.WaitConverged(t, convergeTimeout)
	assertNoOldColumnSecret(t, b, "after a's clears replicated")
	assertAuthenticates(t, c, b, "judy", "jud7-pass", tok.Token, bmc.Name, "bmc-one")

	// A secret written through the cleared node: '' in the old column, the
	// value in the credential row only.
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "kim", Password: "k1m-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser on the cleared node: %v", err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-two")
	c.WaitConverged(t, convergeTimeout)
	assertNoOldColumnSecret(t, b, "after the cleared node's writes")
	assertAuthenticates(t, c, b, "kim", "k1m-pass", tok.Token, bmc.Name, "bmc-two")

	// A rotation through the previous-build node dual-writes; a reads it from
	// the credential row, and a's next pass clears the old column again.
	if _, err := c.SelfClient(b).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "judy", NewPassword: "jud7-rotated",
	}); err != nil {
		t.Fatalf("ChangePassword via %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{a, b} {
		assertAuthenticates(t, c, n, "judy", "jud7-rotated", tok.Token, bmc.Name, "bmc-two")
	}
	if _, err := a.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		assertNoOldColumnSecret(t, n, "after a's next pass")
		assertAuthenticates(t, c, n, "judy", "jud7-rotated", tok.Token, bmc.Name, "bmc-two")
	}
}

// TestFleet_CredentialsClear_AMaintenanceHostOnThePreviousBuildHoldsTheLatchOff:
// credentials_clear_v1 must not latch while any host this node replicates to
// runs a build without it — here one parked in maintenance, which does not
// vote, still receives every statement, and on the build before
// credentials_split_v1 would read only the old columns. Real health checkers
// drive the latch over real Ping; the maintenance host's pinger answer is the
// previous build's advertisement.
func TestFleet_CredentialsClear_AMaintenanceHostOnThePreviousBuildHoldsTheLatchOff(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2690})
	a, old := c.Nodes[0], c.Nodes[2]

	if err := corrosion.UpdateHostState(ctx, a.DB, old.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	// Every node has completed a credentials split pass: credentials_clear_v1
	// is advertised only by a node that has (corrosion.CredentialsLive).
	latchAndSplit(t, c.Nodes...)
	for _, n := range c.Nodes {
		if !n.DB.CredentialsLive() {
			t.Fatalf("%s is not credentials-live after its pass", n.Name)
		}
	}

	var held atomic.Bool
	held.Store(true)
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		node := n
		gates[node.Name].SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
			caps, wall, err := node.Server.PeerCapabilities(ctx, host)
			if held.Load() && host == old.Name {
				caps = withoutToken(caps, capabilities.CredentialsClearV1)
			}
			return caps, wall, err
		})
	}
	ga := gates[a.Name]
	a.DB.SetCredentialsSplitGate(func() bool { return ga.DurablyLatched(capabilities.CredentialsSplitV1) })
	a.DB.SetCredentialsClearGate(func() bool { return ga.DurablyLatched(capabilities.CredentialsClearV1) })

	if !ga.Enforced(ctx, capabilities.CredentialsSplitV1) {
		t.Fatal("credentials_split_v1 did not latch with every host advertising it; the rest is vacuous")
	}
	if ga.Enforced(ctx, capabilities.CredentialsClearV1) {
		t.Fatalf("credentials_clear_v1 latched on %s while %s — in maintenance, still receiving "+
			"replication — runs a build without it", a.Name, old.Name)
	}
	configureIPMI(t, c, a, old.Name, "bmc-held")
	if _, err := a.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if got := oldColumn(t, a, `SELECT ipmi_pass FROM hosts WHERE name = ?`, old.Name); got != "bmc-held" {
		t.Fatalf("%s emptied hosts.ipmi_pass (%q) with the clear held off", a.Name, got)
	}

	held.Store(false) // the maintenance host is upgraded
	eventually(t, 20*time.Second, "credentials_clear_v1 latches once every recipient has rolled", func() bool {
		return ga.Enforced(ctx, capabilities.CredentialsClearV1)
	})
	if _, err := a.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if got := oldColumn(t, a, `SELECT ipmi_pass FROM hosts WHERE name = ?`, old.Name); got != "" {
		t.Errorf("%s: hosts.ipmi_pass = %q after the latch formed and the pass ran", a.Name, got)
	}
}

func withoutToken(caps []string, tok string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if c != tok {
			out = append(out, c)
		}
	}
	return out
}

// TestFleet_CredentialsClear_AnExternalLoginNeverAdoptsALaggingLocalAccount:
// anti-entropy merges users and user_credentials separately. After the clear, a
// local account's users row carries an empty password_hash, so on a node that
// received it before its credential row an empty hash proves nothing. An
// external-realm login under that name must be refused there — never adopted —
// and refused again once the credential arrives (it is a local account). An
// external user that existed before the latch keeps logging in.
func TestFleet_CredentialsClear_AnExternalLoginNeverAdoptsALaggingLocalAccount(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 2691})
	a, n := c.Nodes[0], c.Nodes[1]
	if err := corrosion.InsertUser(ctx, a.DB, "ext", "viewer", ""); err != nil { // a pre-latch shadow
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	latchAndClear(t, a, n)
	c.WaitConverged(t, convergeTimeout)

	// n hears of bob only through its own anti-entropy, and only the public lane.
	c.SetLinkFault(a, n, LinkFault{Block: true})
	restore := a.DoNotImplement("GetSensitiveStateDigest")
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "bob", Password: "b0b-pass", Role: "admin",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	if u, err := corrosion.GetUser(ctx, n.DB, "bob"); err != nil || u == nil || u.PasswordHash != "" {
		t.Fatalf("%s holds bob as %+v (err %v); the scenario needs the cleared users row without its credential", n.Name, u, err)
	}
	ldap := func(subject string) error {
		return auth.EnsureUserShadow(ctx, n.DB, &auth.Principal{Subject: subject, Realm: "ldap:corp"}, "viewer")
	}
	if err := ldap("bob"); err == nil {
		t.Fatal("an LDAP principal named bob adopted the local admin bob while its credential row was in flight")
	}
	if err := ldap("ext"); err != nil {
		t.Errorf("a pre-latch external user was refused: %v", err)
	}

	restore()
	corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	if u, _ := corrosion.GetUser(ctx, n.DB, "bob"); u == nil || u.PasswordHash == "" {
		t.Fatalf("bob's credential did not arrive on %s; the rest is vacuous", n.Name)
	}
	if err := ldap("bob"); err == nil {
		t.Error("an LDAP principal named bob adopted the local admin bob after its credential arrived")
	}
}

// TestFleet_CredentialsClear_AnUnlatchedNeighboursRotationReachesAClearedNode
// backs keeping the absorb on a cleared node. Latches form per node, so a
// neighbour on this build whose credentials_split_v1 latch has not formed yet
// writes a password change to the old column only. A node that has latched the
// clear must take it into its credential row at once, and its next pass
// empties the old column again.
func TestFleet_CredentialsClear_AnUnlatchedNeighboursRotationReachesAClearedNode(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 2692})
	a, b := c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "lena", Password: "l3na-before", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	latchAndClear(t, a) // b has not latched credentials_split_v1
	c.WaitConverged(t, convergeTimeout)

	if _, err := c.SelfClient(b).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "lena", NewPassword: "l3na-after",
	}); err != nil {
		t.Fatalf("ChangePassword via %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	if login, err := c.SelfClient(a).Login(ctx, &pb.LoginRequest{Username: "lena", Password: "l3na-after"}); err != nil || login.Token == "" {
		t.Errorf("%s refuses the rotation an unlatched neighbour made: %+v %v", a.Name, login, err)
	}
	if _, err := c.SelfClient(a).Login(ctx, &pb.LoginRequest{Username: "lena", Password: "l3na-before"}); err == nil {
		t.Errorf("%s still accepts the rotated-out password", a.Name)
	}
	if _, err := a.DB.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if got := oldColumn(t, a, `SELECT password_hash FROM users WHERE username = 'lena'`); got != "" {
		t.Errorf("%s: users.password_hash = %q after its next pass; the cleared node must empty it again", a.Name, got)
	}
}
