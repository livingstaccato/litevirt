// Fleet scenarios: a re-minted admin must not replace the cluster's admin
// password (colonelpanik/litevirt#224) now that the hash lives in
// user_credentials (credentials_split_v1).
//
// The receiver refuses a replicated `users` row whose created_at differs from a
// live local admin's: it is a different account minted elsewhere under that
// name (users_admin_guard.go). Readers take the user_credentials row whenever
// one exists, so refusing only the users row protects nothing unless the
// credential that came with it is refused too. A minting node reaches a
// receiver three ways, and each is driven here over real replication:
//
//   - a latched sender's InsertUser: the users INSERT and a user_credentials
//     upsert in ONE entry;
//   - an unlatched sender's InsertUser: the users INSERT alone, which a
//     latched receiver would otherwise absorb into user_credentials;
//   - anti-entropy: the users row on the public lane and the credential row on
//     the sensitive lane, in separate pulls.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	clusterAdminHash = "cluster-admin-hash"
	remintedHash     = "reminted-admin-hash"
)

// remintAdminOn stands in for a state.db rebuild on n followed by the daemon's
// seed: n forgets the admin locally — nothing is logged or replicated — and
// mints a fresh one under the same name, which replicates the way InsertUser
// always does.
func remintAdminOn(t *testing.T, n *Node) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM users WHERE username = 'admin'`,
		`DELETE FROM user_credentials WHERE username = 'admin'`,
	} {
		if _, err := n.DB.DB().Exec(q); err != nil {
			t.Fatalf("%s: forget the admin locally: %v", n.Name, err)
		}
	}
	// users.created_at has one-second resolution; the re-mint must carry a
	// different one, as a real rebuild days later would.
	time.Sleep(1100 * time.Millisecond)
	if err := corrosion.InsertUser(context.Background(), n.DB, "admin", "admin", remintedHash); err != nil {
		t.Fatalf("%s: re-mint the admin: %v", n.Name, err)
	}
}

// waitApplied returns once `to` has applied everything `from` logged before
// the call: a sentinel written last on `from` arrives after it, because one
// origin's entries apply in order.
func waitApplied(t *testing.T, from, to *Node, sentinel string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, from.DB, sentinel, "viewer", "x"); err != nil {
		t.Fatalf("%s: write sentinel: %v", from.Name, err)
	}
	deadline := time.Now().Add(convergeTimeout)
	for time.Now().Before(deadline) {
		if u, err := corrosion.GetUser(ctx, to.DB, sentinel); err == nil && u != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never applied %s's sentinel %q", to.Name, from.Name, sentinel)
}

func assertAdminHash(t *testing.T, n *Node, stage string) {
	t.Helper()
	u, err := corrosion.GetUser(context.Background(), n.DB, "admin")
	if err != nil || u == nil {
		t.Fatalf("%s %s: read admin: %+v err=%v", n.Name, stage, u, err)
	}
	if u.PasswordHash != clusterAdminHash {
		t.Fatalf("%s %s: the admin password is now %q, want %q. A node that re-minted the admin "+
			"replaced the cluster's credential: the users row was refused, but readers take "+
			"user_credentials, and that row was not", n.Name, stage, u.PasswordHash, clusterAdminHash)
	}
}

func remintCluster(t *testing.T, senderLatched bool) (*Cluster, *Node, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 224})
	a, b := c.Nodes[0], c.Nodes[1]
	a.DB.SetCredentialsSplitGate(func() bool { return true })
	b.DB.SetCredentialsSplitGate(func() bool { return true })
	if err := corrosion.InsertUser(context.Background(), a.DB, "admin", "admin", clusterAdminHash); err != nil {
		t.Fatalf("seed the cluster admin: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	assertAdminHash(t, b, "before the re-mint")
	if !senderLatched {
		b.DB.SetCredentialsSplitGate(func() bool { return false })
	}
	return c, a, b
}

// Route (a): a latched sender's re-mint is one entry holding the users INSERT
// and the user_credentials upsert. Refusing the first and LWW-applying the
// second replaces the password.
func TestFleet_AdminRemint_LatchedSendersCredentialIsRefusedWithItsUsersRow(t *testing.T) {
	_, a, b := remintCluster(t, true)
	remintAdminOn(t, b)
	waitApplied(t, b, a, "sentinel-a")
	assertAdminHash(t, a, "after the WAL entry")
}

// Route (b): an unlatched sender's re-mint is the users INSERT alone. The
// receiver's absorb copies an unpaired old-column secret into user_credentials,
// and must not do so for a row it refused.
func TestFleet_AdminRemint_UnlatchedSendersRefusedRowIsNotAbsorbed(t *testing.T) {
	_, a, b := remintCluster(t, false)
	remintAdminOn(t, b)
	waitApplied(t, b, a, "sentinel-b")
	assertAdminHash(t, a, "after the WAL entry")
}

// Anti-entropy carries the users row and its credential in different pulls:
// public lane, then sensitive lane. The credential belongs to the account the
// peer holds under that name, so once the peer's users row is refused as a
// different account, its credential row is refused too. A legitimate rotation
// of the SAME account (equal created_at) keeps repairing.
func TestFleet_AdminRemint_AntiEntropyRefusesTheRemintedCredential(t *testing.T) {
	c, a, b := remintCluster(t, true)
	// Keep the WAL out of it: b's pushes to a are refused for the rest of the
	// test, so a hears of the re-mint only through its own anti-entropy pulls
	// (those run on the a->b link).
	c.SetLinkFault(b, a, LinkFault{Block: true})
	remintAdminOn(t, b)

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).RunOnce(ctx)
		assertAdminHash(t, a, "after anti-entropy from the re-minting peer")
	}
}

// The control: a rotation of the SAME account carries the same created_at and
// must keep repairing by anti-entropy alone, or the refusal has turned into a
// freeze on the admin password.
func TestFleet_AdminRemint_AntiEntropyStillRepairsARealRotation(t *testing.T) {
	c, a, b := remintCluster(t, true)
	c.SetLinkFault(b, a, LinkFault{Block: true})
	if err := corrosion.UpdateUserPassword(context.Background(), b.DB, "admin", "rotated-hash"); err != nil {
		t.Fatalf("rotate on %s: %v", b.Name, err)
	}
	corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).RunOnce(context.Background())
	u, err := corrosion.GetUser(context.Background(), a.DB, "admin")
	if err != nil || u == nil || u.PasswordHash != "rotated-hash" {
		t.Fatalf("%s serves %+v (err %v) after anti-entropy, want the rotated hash: a legitimate "+
			"rotation of the same account stopped repairing", a.Name, u, err)
	}
}

// The sensitive lane learns which credentials to refuse from the public lane's
// refusal, and that memory is per process. A pass in which the public pull
// fails — the first after a restart, say — has judged none of the peer's users
// rows, so it must not take the peer's user_credentials either.
func TestFleet_AdminRemint_AntiEntropyHoldsCredentialsWhileUsersAreUnjudged(t *testing.T) {
	c, a, b := remintCluster(t, true)
	c.SetLinkFault(b, a, LinkFault{Block: true})
	remintAdminOn(t, b)

	// b serves the sensitive lane but no public table pull, on any of the
	// paths a puller falls back through.
	var restore []func()
	for _, m := range []string{"StreamTableRows", "StreamTableDump", "StreamStateDump", "GetStateDump"} {
		restore = append(restore, b.DoNotImplement(m))
	}
	ctx := context.Background()
	corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).RunOnce(ctx)
	assertAdminHash(t, a, "after a pass whose public pull failed")

	for _, r := range restore {
		r()
	}
	corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).RunOnce(ctx)
	assertAdminHash(t, a, "after a pass that judged the peer's users rows")
}
