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
		// As the daemon does at start (a no-op once recorded).
		if err := n.DB.NoteCredentialsBaseline(context.Background()); err != nil {
			t.Fatalf("%s baseline: %v", n.Name, err)
		}
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

// TestFleet_CredentialsClear_AJoinerNeverAdoptsAClearedLocalAccount
// (re-review I1): a host added after the clear starts with an empty database.
// Its public lane merges the cleared users rows; its sensitive lane has not
// merged, and the cluster has no API tokens and no IPMI-fenced hosts, so
// nothing on it shows a clear. An LDAP principal named after the local admin
// is refused there before and after the joiner's first credentials pass. A
// pre-split external user is refused too until its credential row (the floor
// row the founders' first passes wrote) arrives, and logs in after.
func TestFleet_CredentialsClear_AJoinerNeverAdoptsAClearedLocalAccount(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2693})
	a, b, j := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := j.DB.NoteCredentialsBaseline(ctx); err != nil { // j's first start: empty
		t.Fatal(err)
	}
	c.Isolate(j)
	if err := corrosion.InsertUser(ctx, a.DB, "ext", "viewer", ""); err != nil { // pre-split shadow
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, a.DB, "admin", "admin", "$2a$10$cluster-admin-hash"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	latchAndClear(t, a, b)
	c.WaitConverged(t, convergeTimeout, a, b)

	// j joins: no WAL pushes reach it, and neither source serves the
	// sensitive lane, so only the public rows arrive.
	c.ClearLinkFaults()
	c.SetLinkFault(a, j, LinkFault{Block: true})
	c.SetLinkFault(b, j, LinkFault{Block: true})
	restoreA := a.DoNotImplement("GetSensitiveStateDigest")
	restoreB := b.DoNotImplement("GetSensitiveStateDigest")
	corrosion.NewAntiEntropy(j.DB, j.PKIDir, 0).RunOnce(ctx)
	if u, _ := corrosion.GetUser(ctx, j.DB, "admin"); u == nil || u.PasswordHash != "" {
		t.Fatalf("%s holds admin as %+v; the scenario needs the cleared users row alone", j.Name, u)
	}
	ldap := func(subject string) error {
		return auth.EnsureUserShadow(ctx, j.DB, &auth.Principal{Subject: subject, Realm: "ldap:corp"}, "viewer")
	}
	if err := ldap("admin"); err == nil {
		t.Fatal("before its first pass, the joiner let an LDAP principal adopt the local admin")
	}
	latchAndSplit(t, j)
	if err := ldap("admin"); err == nil {
		t.Fatal("after its first pass, the joiner let an LDAP principal adopt the local admin")
	}
	if rows, err := j.DB.Query(ctx, `SELECT COUNT(*) AS n FROM user_credentials`); err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
		t.Errorf("the joiner wrote credential rows for accounts it cannot judge (err %v)", err)
	}
	if err := ldap("ext"); err == nil {
		t.Error("before its credential row arrived, the joiner judged ext external on no evidence")
	}

	restoreA()
	restoreB()
	corrosion.NewAntiEntropy(j.DB, j.PKIDir, 0).RunOnce(ctx)
	if err := ldap("ext"); err != nil {
		t.Errorf("the pre-split external user is refused after its credential row arrived: %v", err)
	}
	if err := ldap("admin"); err == nil {
		t.Error("an LDAP principal adopted the local admin after its credential arrived")
	}
}

// TestFleet_CredentialsClear_ASettledUsersTieDoesNotHoldBackCredentials
// (re-review m3): a users table whose only difference from a peer is a tie
// already tracked is deferred by scheduled anti-entropy. That deferral says
// nothing about re-mints (a refused re-mint is not a tie, so it never settles),
// so the peer's credentials are still repaired, as on main.
func TestFleet_CredentialsClear_ASettledUsersTieDoesNotHoldBackCredentials(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	latchAndClear(t, a, b)
	if err := corrosion.InsertUser(ctx, a.DB, "mia", "operator", "$2a$10$mia-before"); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, a, b)

	// An unresolved users tie, beneath the replicator on both sides.
	const ts = "2026-01-01T00:00:00.000000000Z"
	for _, n := range []*Node{a, b} {
		n.DB.Mu().Lock()
		_, err := n.DB.DB().Exec(`INSERT INTO users (username, role, password_hash, created_at, updated_at)
			VALUES ('tied', ?, '', '2026-01-01T00:00:00Z', ?)`, "role-"+n.Name, ts)
		n.DB.Mu().Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("catch-up pass did not run")
	}
	if b.DB.UnresolvedTieCount() == 0 {
		t.Fatal("precondition: the users tie is not tracked, so the table can never settle")
	}

	// A rotation reaches b's public lane only: its sensitive pull fails.
	if err := corrosion.UpdateUserPassword(ctx, a.DB, "mia", "$2a$10$mia-after"); err != nil {
		t.Fatal(err)
	}
	restore := a.DoNotImplement("GetSensitiveStateDigest")
	corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx)
	restore()
	if u, _ := corrosion.GetUser(ctx, b.DB, "mia"); u == nil || u.PasswordHash != "$2a$10$mia-before" {
		t.Fatalf("precondition: b serves %+v; the scenario needs the old credential still in place", u)
	}

	// Scheduled passes: users is settled (only the tracked tie differs) and
	// deferred; the credential must still be repaired.
	for i := 0; i < 2; i++ {
		corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx)
	}
	if u, _ := corrosion.GetUser(ctx, b.DB, "mia"); u == nil || u.PasswordHash != "$2a$10$mia-after" {
		t.Errorf("b serves %+v after scheduled passes, want the rotation: a settled users tie held "+
			"back the peer's credentials, and the rotated-out password keeps working", u)
	}
}

// TestFleet_CredentialsClear_AStaleNodesShadowNeverReplacesALocalAccount
// (re-review 2, Info; pre-existing on main): a node whose users table is behind
// — cut off while a local account was created — finds no row under that name
// and creates an external shadow for an LDAP login. That row is newer than the
// cluster's local account; before this, it replaced the account cluster-wide
// (role and password). Every node that holds the local account must refuse
// it: a different account under a live local account's name.
func TestFleet_CredentialsClear_AStaleNodesShadowNeverReplacesALocalAccount(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2694})
	a, b, j := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(j)
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "carol", Password: "c4rol-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)

	// j's replica caught up before it was cut off, so nothing tells it its
	// users table is behind: the shadow is created there. users.created_at
	// has one-second resolution; a real shadow comes later than this.
	time.Sleep(1100 * time.Millisecond)
	_ = auth.EnsureUserShadow(ctx, j.DB, &auth.Principal{Subject: "carol", Realm: "ldap:corp"}, "viewer")
	c.ClearLinkFaults()
	time.Sleep(2 * time.Second)
	for _, n := range []*Node{a, b} {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	for _, n := range []*Node{a, b} {
		u, gerr := corrosion.GetUser(ctx, n.DB, "carol")
		if gerr != nil || u == nil || u.Role != "operator" || u.PasswordHash == "" {
			t.Errorf("%s holds carol as %+v (err %v): a stale node's shadow replaced the local account", n.Name, u, gerr)
		}
		if _, lerr := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: "carol", Password: "c4rol-pass"}); lerr != nil {
			t.Errorf("%s: carol's local password no longer works: %v", n.Name, lerr)
		}
	}
}

// TestFleet_CredentialsClear_AHostBackFromOfflineNeverTakesACleardLocalAccountForExternal
// (re-review 2, N1): a host that was off across the clear and comes back with
// its old database records a baseline from that database — where admin still
// had a password. Its sensitive lane lags; the cleared admin row arrives. An
// LDAP principal named admin is refused there, and its first pass writes no
// floor row for admin.
func TestFleet_CredentialsClear_AHostBackFromOfflineNeverTakesACleardLocalAccountForExternal(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2695})
	a, b, s := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, a.DB, "admin", "admin", "$2a$10$cluster-admin-hash"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(s) // switched off with its database
	latchAndClear(t, a, b)
	c.WaitConverged(t, convergeTimeout, a, b)

	// s comes back on this build: the baseline is recorded from its old rows.
	if err := s.DB.NoteCredentialsBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	c.ClearLinkFaults()
	c.SetLinkFault(a, s, LinkFault{Block: true})
	c.SetLinkFault(b, s, LinkFault{Block: true})
	restoreA := a.DoNotImplement("GetSensitiveStateDigest")
	restoreB := b.DoNotImplement("GetSensitiveStateDigest")
	defer restoreA()
	defer restoreB()
	corrosion.NewAntiEntropy(s.DB, s.PKIDir, 0).RunOnce(ctx)
	if got := oldColumn(t, s, `SELECT password_hash FROM users WHERE username = 'admin'`); got != "" {
		t.Fatalf("precondition: %s still holds admin's old hash", s.Name)
	}
	ldap := func() error {
		return auth.EnsureUserShadow(ctx, s.DB, &auth.Principal{Subject: "admin", Realm: "ldap:corp"}, "viewer")
	}
	if err := ldap(); err == nil {
		t.Fatal("an LDAP principal adopted the cleared local admin on a host back from offline")
	}
	latchAndSplit(t, s)
	if err := ldap(); err == nil {
		t.Fatal("after its first pass, the host let an LDAP principal adopt the cleared local admin")
	}
	if rows, err := s.DB.Query(ctx, `SELECT COUNT(*) AS n FROM user_credentials WHERE username = 'admin'`); err != nil || rows[0].Int64("n") != 0 {
		t.Errorf("the host wrote a floor credential row for the cleared local admin (err %v)", err)
	}
}

// TestFleet_CredentialsClear_AReactivatedNameNeverMatchesItsOldEvidence
// (re-review 3, R1): users rows are never hard-deleted, so `lv user rm` and
// `lv user create` under the same name REACTIVATE the row and keep its
// created_at. A host that was off while that happened, and comes back with
// its old database, holds evidence — its baseline, and the shadow it made
// itself — that the name was an external user. The reactivated row arrives
// with its credential still in flight. That evidence describes the row as it
// was, not the local account it is now: an LDAP principal under the name is
// refused there before and after the host's first pass, and the pass writes no
// empty credential row for it. An external user whose row has not changed
// keeps logging in.
func TestFleet_CredentialsClear_AReactivatedNameNeverMatchesItsOldEvidence(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2696})
	a, b, s := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// Pre-split shadows: ops made on s itself, ext2 made on a.
	if err := corrosion.InsertUser(ctx, s.DB, "ops", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, a.DB, "ext2", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(s) // switched off with its database
	latchAndClear(t, a, b)
	c.WaitConverged(t, convergeTimeout, a, b)

	// ops becomes a local admin: the real delete, then the real create, which
	// reactivates the tombstoned row.
	if _, err := c.SelfClient(a).DeleteUser(ctx, &pb.DeleteUserRequest{Username: "ops"}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "ops", Password: "0ps-local", Role: "admin",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	createdAt := oldColumn(t, a, `SELECT created_at FROM users WHERE username = 'ops'`)

	// s comes back on this build with its old database.
	if err := s.DB.NoteCredentialsBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	c.ClearLinkFaults()
	c.SetLinkFault(a, s, LinkFault{Block: true})
	c.SetLinkFault(b, s, LinkFault{Block: true})
	restoreA := a.DoNotImplement("GetSensitiveStateDigest")
	restoreB := b.DoNotImplement("GetSensitiveStateDigest")
	defer restoreA()
	defer restoreB()
	corrosion.NewAntiEntropy(s.DB, s.PKIDir, 0).RunOnce(ctx)
	u, err := corrosion.GetUser(ctx, s.DB, "ops")
	if err != nil || u == nil || u.Role != "admin" || u.PasswordHash != "" || u.CreatedAt != createdAt {
		t.Fatalf("precondition: %s holds ops as %+v (err %v); the scenario needs the reactivated "+
			"admin row, created_at %s kept, without its credential", s.Name, u, err, createdAt)
	}
	ldap := func(subject string) error {
		return auth.EnsureUserShadow(ctx, s.DB, &auth.Principal{Subject: subject, Realm: "ldap:corp"}, "viewer")
	}
	if err := ldap("ops"); err == nil {
		t.Fatal("an LDAP principal adopted the reactivated local admin ops on evidence about the row it replaced")
	}
	if err := ldap("ext2"); err != nil {
		t.Errorf("an unchanged pre-split external user was refused: %v", err)
	}
	latchAndSplit(t, s)
	if err := ldap("ops"); err == nil {
		t.Fatal("after its first pass, the host let an LDAP principal adopt the reactivated local admin")
	}
	if rows, err := s.DB.Query(ctx, `SELECT COUNT(*) AS n FROM user_credentials WHERE username = 'ops'`); err != nil || rows[0].Int64("n") != 0 {
		t.Errorf("the host wrote an empty credential row for the reactivated local admin (err %v)", err)
	}
	if err := ldap("ext2"); err != nil {
		t.Errorf("after the first pass, an unchanged pre-split external user was refused: %v", err)
	}
}

// TestFleet_CredentialsClear_AShadowReactivationNeverWipesALocalPassword
// (re-review 3, R4; pre-existing on main): alice is deleted and created again
// as a local account on a. Inside the replication latency an LDAP alice logs
// in on b, which still holds only the tombstone, and b reactivates the row as
// an external shadow. That write comes later in real time, but it must not
// beat a's: it is a reactivation of the tombstone b saw, not of the account a
// created since. alice keeps her local password and role on every node.
func TestFleet_CredentialsClear_AShadowReactivationNeverWipesALocalPassword(t *testing.T) {
	for _, clear := range []bool{false, true} {
		name := "before the split"
		if clear {
			name = "after the clear"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 2697})
			a, b := c.Nodes[0], c.Nodes[1]
			if clear {
				latchAndClear(t, a, b)
			}
			if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
				Username: "alice", Password: "al1ce-first", Role: "operator",
			}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			c.WaitConverged(t, convergeTimeout)
			if _, err := c.SelfClient(a).DeleteUser(ctx, &pb.DeleteUserRequest{Username: "alice"}); err != nil {
				t.Fatalf("DeleteUser: %v", err)
			}
			c.WaitConverged(t, convergeTimeout)

			c.Isolate(b)
			if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
				Username: "alice", Password: "al1ce-again", Role: "operator",
			}); err != nil {
				t.Fatalf("CreateUser (reactivation): %v", err)
			}
			time.Sleep(50 * time.Millisecond) // b's write is later in real time
			if err := auth.EnsureUserShadow(ctx, b.DB, &auth.Principal{Subject: "alice", Realm: "ldap:corp"}, "viewer"); err != nil {
				t.Fatalf("precondition: b did not reactivate alice as a shadow: %v", err)
			}
			c.ClearLinkFaults()
			c.WaitConverged(t, convergeTimeout)
			for _, n := range []*Node{a, b} {
				corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
			}
			for _, n := range []*Node{a, b} {
				u, err := corrosion.GetUser(ctx, n.DB, "alice")
				if err != nil || u == nil || u.Role != "operator" || u.PasswordHash == "" {
					t.Errorf("%s holds alice as %+v (err %v): a stale shadow reactivation replaced the local account", n.Name, u, err)
				}
				if _, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: "alice", Password: "al1ce-again"}); err != nil {
					t.Errorf("%s: alice's local password no longer works: %v", n.Name, err)
				}
			}
		})
	}
}
