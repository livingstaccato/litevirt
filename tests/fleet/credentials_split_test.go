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

	"golang.org/x/crypto/bcrypt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
// credential row, and leaves the old column alone. Then the operator rotates
// the password through the UNLATCHED node, which writes the old column only.
// The latched node must serve the rotation at once, before any pass: its
// reader takes the newer of the two copies. A reader that trusted its existing
// credential row would fence with the password the BMC no longer accepts.
//
// Stage 3, the roll completes: the second node latches too. Every node's
// public hosts row still carries the password — dual-write, so a host rolled
// back one release still fences — and a further rotation on a latched node
// writes both copies.
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
		t.Fatalf("the latched node's pass did not copy: %+v err=%v", rep, err)
	}
	c.WaitConverged(t, convergeTimeout)
	configureIPMI(t, c, b, victim.Name, "bmc-pass-2")
	c.WaitConverged(t, convergeTimeout)
	// Before any pass: every node's credential row already holds the rotation.
	// a (latched) absorbed b's unlatched entry on apply; b updated the row it
	// held from a when it wrote. Neither waits for a pass.
	for _, n := range c.Nodes {
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, victim.Name); got != "bmc-pass-2" {
			t.Fatalf("%s: host_fence_credentials = %q before any pass, want the rotated bmc-pass-2 — "+
				"an unlatched rotation must be absorbed where it lands, not wait up to a minute", n.Name, got)
		}
	}
	if h, err := corrosion.GetHost(ctx, a.DB, victim.Name); err != nil || h == nil || h.IPMIPass != "bmc-pass-2" {
		t.Fatalf("%s serves IPMI password %+v (err %v) before its pass, want the rotated bmc-pass-2", a.Name, h, err)
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
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM hosts WHERE name = ?`, victim.Name); got != "bmc-pass-2" {
			t.Errorf("%s: hosts.ipmi_pass = %q after both nodes latched, want bmc-pass-2; a host "+
				"rolled back one release reads only this column", n.Name, got)
		}
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, victim.Name); got != "bmc-pass-2" {
			t.Errorf("%s: host_fence_credentials holds %q, want the rotated bmc-pass-2", n.Name, got)
		}
	}

	// A rotation on a latched node writes both copies.
	configureIPMI(t, c, a, victim.Name, "bmc-pass-3")
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		assertBothCopies(t, n, "hosts.ipmi_pass", "bmc-pass-3",
			`SELECT ipmi_pass FROM hosts WHERE name = ?`,
			`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, victim.Name)
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
	if fences[0].IPMIPass != "bmc-pass-3" {
		t.Fatalf("%s fenced %s with IPMI password %q, want the current bmc-pass-3 — a fence "+
			"that authenticates with anything else fails closed", fences[0].By, victim.Name, fences[0].IPMIPass)
	}
}

// assertBothCopies checks that a secret's two copies on n — the old column a
// previous-release reader uses and the credential row this release writes —
// both hold want.
func assertBothCopies(t *testing.T, n *Node, what, want, oldQuery, credQuery string, args ...interface{}) {
	t.Helper()
	if got := oldColumn(t, n, oldQuery, args...); got != want {
		t.Errorf("%s: %s (old column) = %q, want %q; a host rolled back one release reads only "+
			"this column", n.Name, what, got, want)
	}
	if got := oldColumn(t, n, credQuery, args...); got != want {
		t.Errorf("%s: %s (credential row) = %q, want %q", n.Name, what, got, want)
	}
}

// Previous-release readers. This harness runs one binary, so a host on the
// previous release is stood in for by the exact reads that release runs: the
// old column on the public row and nothing else.

func previousReleaseLogin(t *testing.T, n *Node, username, password string) bool {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT password_hash FROM users WHERE username = ? AND deleted_at IS NULL`, username)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%s: previous-release user read for %s: rows=%d err=%v", n.Name, username, len(rows), err)
	}
	return bcrypt.CompareHashAndPassword([]byte(rows[0].String("password_hash")), []byte(password)) == nil
}

func previousReleaseTokenValid(t *testing.T, n *Node, raw string) bool {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT t.token_hash FROM tokens t JOIN users u ON u.username = t.username
		  WHERE t.deleted_at IS NULL AND u.deleted_at IS NULL`)
	if err != nil {
		t.Fatalf("%s: previous-release token read: %v", n.Name, err)
	}
	for _, r := range rows {
		if bcrypt.CompareHashAndPassword([]byte(r.String("token_hash")), []byte(raw)) == nil {
			return true
		}
	}
	return false
}

func latchAndSplit(t *testing.T, nodes ...*Node) {
	t.Helper()
	for _, n := range nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
		if _, err := n.DB.SplitCredentials(context.Background()); err != nil {
			t.Fatalf("%s split: %v", n.Name, err)
		}
	}
}

// TestFleet_CredentialsSplit_DualWriteKeepsBothCopies: the latch starts
// writing the credential tables and stops writing nothing. After the split
// pass every node still holds every secret in its old column, equal to the
// credential row; and a password change, a new token and an IPMI rotation made
// after the latch leave the two copies equal on every node.
func TestFleet_CredentialsSplit_DualWriteKeepsBothCopies(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2683})
	a, b, bmc := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	admin := c.SelfClient(a)

	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "dave", Password: "d4ve-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok1, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "dave", Name: "before"})
	if err != nil || tok1.Id == "" {
		t.Fatalf("CreateToken: %+v %v", tok1, err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-before")
	c.WaitConverged(t, convergeTimeout)

	latchAndSplit(t, c.Nodes...)
	c.WaitConverged(t, convergeTimeout)

	userHash := func(n *Node) string {
		return oldColumn(t, n, `SELECT password_hash FROM user_credentials WHERE username = 'dave'`)
	}
	tokHash := func(n *Node, id string) string {
		return oldColumn(t, n, `SELECT token_hash FROM token_credentials WHERE token_id = ?`, id)
	}
	for _, n := range c.Nodes {
		if userHash(n) == "" || tokHash(n, tok1.Id) == "" {
			t.Fatalf("%s holds no credential rows after the split; the scenario would prove nothing", n.Name)
		}
		assertBothCopies(t, n, "users.password_hash", userHash(n),
			`SELECT password_hash FROM users WHERE username = ?`,
			`SELECT password_hash FROM user_credentials WHERE username = ?`, "dave")
		assertBothCopies(t, n, "tokens.token_hash", tokHash(n, tok1.Id),
			`SELECT token_hash FROM tokens WHERE id = ?`,
			`SELECT token_hash FROM token_credentials WHERE token_id = ?`, tok1.Id)
		assertBothCopies(t, n, "hosts.ipmi_pass", "bmc-before",
			`SELECT ipmi_pass FROM hosts WHERE name = ?`,
			`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, bmc.Name)
	}
	before := userHash(a)

	// Changes made after the latch, through different nodes.
	if _, err := c.SelfClient(b).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "dave", NewPassword: "d4ve-pass-2",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	tok2, err := c.SelfClient(b).CreateToken(ctx, &pb.CreateTokenRequest{Username: "dave", Name: "after"})
	if err != nil || tok2.Id == "" {
		t.Fatalf("CreateToken after the latch: %+v %v", tok2, err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-after")
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		if userHash(n) == before {
			t.Fatalf("%s: user_credentials still holds the pre-change hash", n.Name)
		}
		assertBothCopies(t, n, "users.password_hash", userHash(n),
			`SELECT password_hash FROM users WHERE username = ?`,
			`SELECT password_hash FROM user_credentials WHERE username = ?`, "dave")
		assertBothCopies(t, n, "tokens.token_hash", tokHash(n, tok2.Id),
			`SELECT token_hash FROM tokens WHERE id = ?`,
			`SELECT token_hash FROM token_credentials WHERE token_id = ?`, tok2.Id)
		assertBothCopies(t, n, "hosts.ipmi_pass", "bmc-after",
			`SELECT ipmi_pass FROM hosts WHERE name = ?`,
			`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, bmc.Name)
	}
}

// TestFleet_CredentialsSplit_AnUnlatchedWriteIsServedWithoutWaitingForAPass:
// latches form per node, so a neighbour that has not latched yet writes a
// password change to the old column only. A latched node must serve that
// change the moment it replicates — the new password logs in and the old one
// is refused — without waiting for its next split pass. A rotated leaked
// password that keeps working for up to a minute is the hazard.
func TestFleet_CredentialsSplit_AnUnlatchedWriteIsServedWithoutWaitingForAPass(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 2684})
	a, b := c.Nodes[0], c.Nodes[1]

	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "erin", Password: "leaked-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)

	latchAndSplit(t, a) // b has not latched
	c.WaitConverged(t, convergeTimeout)
	credBefore := oldColumn(t, a, `SELECT password_hash FROM user_credentials WHERE username = 'erin'`)
	if credBefore == "" {
		t.Fatalf("%s holds no user_credentials row for erin; the scenario would prove nothing", a.Name)
	}

	// The rotation, through the unlatched node: old column only.
	if _, err := c.SelfClient(b).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "erin", NewPassword: "rotated-pass",
	}); err != nil {
		t.Fatalf("ChangePassword via %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	// No pass has run since the rotation. Both nodes must already serve it:
	// a absorbed b's unlatched entry on apply, and b refreshed the credential
	// row it held (replicated from a) when it wrote.
	for _, n := range c.Nodes {
		if got := oldColumn(t, n, `SELECT password_hash FROM user_credentials WHERE username = 'erin'`); got == credBefore {
			t.Errorf("%s: user_credentials still holds the pre-rotation hash", n.Name)
		}
		if _, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: "erin", Password: "leaked-pass"}); err == nil {
			t.Errorf("%s accepted the rotated-out password", n.Name)
		}
		if login, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: "erin", Password: "rotated-pass"}); err != nil || login.Token == "" {
			t.Errorf("%s refused the rotated password: %+v %v", n.Name, login, err)
		}
	}
}

// TestFleet_CredentialsSplit_APreviousReleaseReaderAuthenticatesAfterTheLatch
// is the rollback half. After every node has latched and split, and after
// secrets were created and rotated on latched nodes, a host rolled back one
// release — which reads only the old columns — still logs a user in,
// validates an API token and fences with the current IPMI password.
func TestFleet_CredentialsSplit_APreviousReleaseReaderAuthenticatesAfterTheLatch(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2685})
	a, b, bmc := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "frank", Password: "fr4nk-before", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	configureIPMI(t, c, a, bmc.Name, "bmc-before")
	c.WaitConverged(t, convergeTimeout)
	latchAndSplit(t, c.Nodes...)
	c.WaitConverged(t, convergeTimeout)

	// Everything below is written by latched nodes.
	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "grace", Password: "gr4ce-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser after the latch: %v", err)
	}
	if _, err := c.SelfClient(b).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "frank", NewPassword: "fr4nk-after",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	tok, err := c.SelfClient(b).CreateToken(ctx, &pb.CreateTokenRequest{Username: "grace", Name: "ci"})
	if err != nil || tok.Token == "" {
		t.Fatalf("CreateToken: %+v %v", tok, err)
	}
	configureIPMI(t, c, b, bmc.Name, "bmc-after")
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		if !previousReleaseLogin(t, n, "frank", "fr4nk-after") {
			t.Errorf("%s: a previous-release reader refuses frank's current password; rolled back, "+
				"this host locks out a password changed after the latch", n.Name)
		}
		if previousReleaseLogin(t, n, "frank", "fr4nk-before") {
			t.Errorf("%s: a previous-release reader still accepts frank's OLD password", n.Name)
		}
		if !previousReleaseLogin(t, n, "grace", "gr4ce-pass") {
			t.Errorf("%s: a previous-release reader refuses a user created after the latch", n.Name)
		}
		if !previousReleaseTokenValid(t, n, tok.Token) {
			t.Errorf("%s: a previous-release reader refuses a token created after the latch", n.Name)
		}
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM hosts WHERE name = ?`, bmc.Name); got != "bmc-after" {
			t.Errorf("%s: a previous-release fencer would authenticate with %q, want bmc-after", n.Name, got)
		}
	}
}

// TestFleet_CredentialsSplit_LoginAndTokenAuthAfterTheSplit: once the split
// has run, a password login and an API token authenticate through the real
// Login RPC and a real bearer-authenticated call, on a node other than the one
// the credentials were created on.
func TestFleet_CredentialsSplit_LoginAndTokenAuthAfterTheSplit(t *testing.T) {
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

	latchAndSplit(t, c.Nodes...)
	c.WaitConverged(t, convergeTimeout)

	if got := oldColumn(t, b, `SELECT password_hash FROM user_credentials WHERE username = 'carol'`); got == "" {
		t.Fatalf("%s holds no user_credentials row for carol; the scenario would prove nothing", b.Name)
	}

	login, err := c.SelfClient(b).Login(ctx, &pb.LoginRequest{Username: "carol", Password: "c4rol-pass"})
	if err != nil || login.Token == "" {
		t.Fatalf("password login on %s after the split: %+v %v", b.Name, login, err)
	}
	if _, err := c.SelfClient(b).Login(ctx, &pb.LoginRequest{Username: "carol", Password: "wrong"}); err == nil {
		t.Fatal("a wrong password logged in; the login check is not reading a hash at all")
	}
	if _, err := c.bearerClient(b, tok.Token).ListHosts(ctx, &pb.ListHostsRequest{}); err != nil {
		t.Fatalf("API token on %s after the split: %v", b.Name, err)
	}
}

// TestFleet_CredentialsSplit_AConcurrentUnrelatedHostWriteDoesNotResurrectARotatedPassword
// is the #267 race on the secret column. A latched node rotates the IPMI
// password A→B, dual-written at T1. Before that reaches replica R, another
// node's unrelated hosts write (a version report, T2 > T1) lands on R first,
// so R's LWW gate then refuses the T1 hosts half: R holds hosts.ipmi_pass=A at
// T2 and host_fence_credentials=B at T1. The parent row's updated_at no longer
// dates the secret column, so neither R's reader nor any split pass may
// prefer A.
func TestFleet_CredentialsSplit_AConcurrentUnrelatedHostWriteDoesNotResurrectARotatedPassword(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2686})
	l, v, r := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	target := v.Name

	configureIPMI(t, c, l, target, "bmc-A")
	c.WaitConverged(t, convergeTimeout)
	latchAndSplit(t, c.Nodes...)
	c.WaitConverged(t, convergeTimeout)

	// Hold l's stream away from v and r, so v's write reaches r first.
	c.SetLinkFault(l, r, LinkFault{Block: true})
	c.SetLinkFault(l, v, LinkFault{Block: true})
	configureIPMI(t, c, l, target, "bmc-B")                                                // T1, dual-written on l
	if err := corrosion.UpdateHostVersion(ctx, v.DB, target, "v-concurrent"); err != nil { // T2 > T1
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "r applies v's version report", func() bool {
		return oldColumn(t, r, `SELECT version FROM hosts WHERE name = ?`, target) == "v-concurrent"
	})
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "r applies l's rotation to the credential row", func() bool {
		return oldColumn(t, r, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, target) == "bmc-B"
	})
	if got := oldColumn(t, r, `SELECT ipmi_pass FROM hosts WHERE name = ?`, target); got != "bmc-A" {
		t.Fatalf("r's hosts.ipmi_pass = %q; the scenario needs the LWW gate to have refused the T1 hosts half", got)
	}

	if h, err := corrosion.GetHost(ctx, r.DB, target); err != nil || h == nil || h.IPMIPass != "bmc-B" {
		t.Errorf("%s fences with %+v (err %v), want the rotated bmc-B: an unrelated write bumped the "+
			"parent row's updated_at, and the reader took that as the secret's age", r.Name, h, err)
	}
	for _, n := range c.Nodes {
		if _, err := n.DB.SplitCredentials(ctx); err != nil {
			t.Fatalf("%s split: %v", n.Name, err)
		}
	}
	time.Sleep(2 * time.Second) // let any copy a pass made replicate
	for _, n := range c.Nodes {
		if got := oldColumn(t, n, `SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, target); got != "bmc-B" {
			t.Errorf("%s: host_fence_credentials = %q after the passes, want bmc-B: a pass copied the "+
				"rotated-out password over the credential row", n.Name, got)
		}
	}
}

// TestFleet_CredentialsSplit_SensitiveAntiEntropyHealsAMissedAbsorb is gap (b):
// a latched node that never applied an unlatched neighbour's entry (it missed
// the WAL push and repaired the parent row some other way) holds the
// pre-rotation credential row. Every node that did apply the entry absorbed the
// same row under the entry's own updated_at, so sensitive-lane anti-entropy
// pulls it and LWW takes it.
func TestFleet_CredentialsSplit_SensitiveAntiEntropyHealsAMissedAbsorb(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2687})
	a, x, u := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	if _, err := c.SelfClient(a).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "hana", Password: "before-pass", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	latchAndSplit(t, a, x) // u has not latched
	c.WaitConverged(t, convergeTimeout)
	before := oldColumn(t, x, `SELECT password_hash FROM user_credentials WHERE username = 'hana'`)
	beforeTS := oldColumn(t, x, `SELECT updated_at FROM user_credentials WHERE username = 'hana'`)

	if _, err := c.SelfClient(u).ChangePassword(ctx, &pb.ChangePasswordRequest{
		Username: "hana", NewPassword: "after-pass",
	}); err != nil {
		t.Fatalf("ChangePassword via %s: %v", u.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)

	// x "missed" the entry: put its credential row back, locally only.
	x.DB.Mu().Lock()
	_, err := x.DB.DB().Exec(`UPDATE user_credentials SET password_hash = ?, updated_at = ? WHERE username = 'hana'`, before, beforeTS)
	x.DB.Mu().Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(x).Login(ctx, &pb.LoginRequest{Username: "hana", Password: "before-pass"}); err != nil {
		t.Fatalf("%s refuses the pre-rotation password with the stale row in place (%v); the "+
			"scenario would prove nothing", x.Name, err)
	}

	aeCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	corrosion.NewAntiEntropy(x.DB, x.PKIDir, 0).RunOnce(aeCtx)

	if _, err := c.SelfClient(x).Login(ctx, &pb.LoginRequest{Username: "hana", Password: "before-pass"}); err == nil {
		t.Errorf("%s still accepts the rotated-out password after sensitive anti-entropy", x.Name)
	}
	if login, err := c.SelfClient(x).Login(ctx, &pb.LoginRequest{Username: "hana", Password: "after-pass"}); err != nil || login.Token == "" {
		t.Errorf("%s refuses the rotated password after sensitive anti-entropy: %+v %v", x.Name, login, err)
	}
}
