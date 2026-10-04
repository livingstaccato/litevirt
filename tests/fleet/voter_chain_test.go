// Fleet scenarios: a host that joins after `lv host rm --dead` adopting the
// voter chain from generation 1 (docs/design/recovery-claims.md §4.1
// "History and revocation"), and a revoked key still deciding nothing new.
//
// Every node adopts voter generations in order, each verified against the one
// before it. A node that was there all along verified each one as it was
// decided. A node that joins later walks the whole chain from genesis, so the
// signatures it checks are, by then, of hosts that may have been removed and
// revoked since — which is the ordinary end of a voter's life, not evidence
// against the generations it signed while it was one.
package fleet

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// reimage rebuilds n as a fresh machine under the same name, as the kvm003
// lab did after `lv host rm --dead` (drill 6, RESTORE.md steps 6 and 8): a new
// disk, so an empty state.db and a new voter incarnation; a new host
// certificate from the cluster CA; admission by via, which is what
// `lv host add` writes; and a replica filled from the live peers by
// anti-entropy. n's old daemon is stopped and its database closed first.
func reimage(t *testing.T, c *Cluster, n, via *Node, live ...*Node) {
	t.Helper()
	ctx := context.Background()
	if n.replStarted {
		n.repl.Stop()
		n.replStarted = false
	}
	if n.selfConn != nil {
		_ = n.selfConn.Close()
		n.selfConn = nil
	}
	n.GRPCSrv.Stop()
	_ = n.Listener.Close()
	n.DB.Close()

	if err := os.RemoveAll(n.PKIDir); err != nil {
		t.Fatal(err)
	}
	c.mintHostCert(n)
	l, err := net.Listen("tcp", net.JoinHostPort(n.Address, "0"))
	if err != nil {
		t.Fatalf("reserve a port for the rebuilt %s: %v", n.Name, err)
	}
	n.Port, n.Listener = l.Addr().(*net.TCPAddr).Port, l

	// A database of its own name: nothing of the old machine's survives.
	db, err := corrosion.NewSharedTestClient(fmt.Sprintf("fleet-%s-rebuilt-%s", n.Name, t.Name()), n.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.MarkReplicaCaughtUpForTests("fleet-reimage")
	n.DB = db
	c.seedGossipMembership()

	serial, err := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	rec := corrosion.HostRecord{Name: n.Name, Address: n.Address, SSHUser: "root", SSHPort: 22, GRPCPort: n.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort", CPUTotal: 64, MemTotal: 262144}
	if err := corrosion.AdmitHost(ctx, via.DB, rec); err != nil {
		t.Fatalf("admit the rebuilt %s on %s: %v", n.Name, via.Name, err)
	}
	for _, p := range live {
		h, err := corrosion.GetHost(ctx, via.DB, p.Name)
		if err != nil || h == nil {
			t.Fatalf("%s's hosts row on %s: %v", p.Name, via.Name, err)
		}
		if err := corrosion.InsertHost(ctx, n.DB, *h); err != nil {
			t.Fatalf("seed %s's hosts row on the rebuilt %s: %v", p.Name, n.Name, err)
		}
	}
	if err := corrosion.RegisterHost(ctx, n.DB, rec); err != nil {
		t.Fatal(err)
	}
	c.buildServer(n)
	n.repl.SetProofReplicaGate(func(context.Context, string) bool { return true })
	n.repl.Start(c.ctx)
	n.replStarted = true
	for _, p := range live {
		c.SetLinkFaultBoth(n, p, LinkFault{})
	}
	n.DB.SetVoterConfigGate(func() bool { return true })

	all := append(append([]*Node(nil), live...), n)
	eventually(t, convenientAETimeout, "the rebuilt "+n.Name+" to catch up by anti-entropy", func() bool {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		apart, err := divergence(all)
		return err == nil && len(apart) == 0
	})
	syncCRL(t, all...)
}

const convenientAETimeout = 3 * convergeTimeout

// adoptRebuilt runs n's adoption pass until it has adopted gen, failing with
// the pass's last error: where a rebuilt host stops in the chain, and why, is
// the finding.
func adoptRebuilt(t *testing.T, n *Node, gen int64) {
	t.Helper()
	deadline := time.Now().Add(convergeTimeout)
	for {
		got, err := n.Server.AdoptVoterConfigs(context.Background())
		if got >= gen {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rebuilt %s stopped at voter generation %d, want %d: %v", n.Name, got, gen, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func voterAdd(t *testing.T, c *Cluster, via, host *Node, wantGen int64) {
	t.Helper()
	resp, err := c.SelfClient(via).ChangeVoterConfig(context.Background(),
		&pb.ChangeVoterConfigRequest{Op: "add", Host: host.Name})
	if err != nil || resp.GetGeneration() != wantGen {
		t.Fatalf("lv cluster voter add %s: %+v %v", host.Name, resp, err)
	}
}

// TestFleet_VoterChain_AHostAddedAfterRmDeadAdoptsTheCurrentGeneration is the
// kvm003 drill-6 reproduction (B7), with the lab's history: genesis on five
// (1), `voter rm` node-4 (2) and `voter add` node-4 back (3), then node-2,3,4
// die for good — fence-confirmed, forced out (4 = {0,1}) and removed with
// `lv host rm --dead`, which revokes their certificates. All three are rebuilt
// under the same names, then voted back in one at a time (5 = +4, 6 = +3,
// 7 = +2). Each rebuilt host walks the chain from generation 1, whose
// certificate now carries three revoked signatures; generation 3 lists its own
// name under the old machine's incarnation; and generation 4 names its own
// name lost, and the other rebuilt hosts — alive again — lost as well. It must
// adopt the current generation and vote: a recovery claim at generation 6
// needs three of {0,1,3,4}, and node-1 is kept out of it.
//
// Mutations, each red: verify every generation against today's CRL (the old
// rule) — node-4 refuses generation 1; refuse a forced row naming this host's
// name whatever its incarnation — node-4 refuses generation 4; count a named
// lost host as reached whichever incarnation answers — node-4 refuses
// generation 4, node-2 and node-3 answering; treat a member entry under this
// host's name as this host whatever its incarnation — node-4 tries to import
// for generation 3 from a sealed majority of generation 2 that no longer
// exists, and never gets past 2.
func TestFleet_VoterChain_AHostAddedAfterRmDeadAdoptsTheCurrentGeneration(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2541})
	n0, n1, n2, n3, n4 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	if got := voterRow(t, n0, 1).Names(); len(got) != 5 {
		t.Fatalf("genesis members %v, want all five", got)
	}
	if resp, err := c.SelfClient(n0).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n4.Name}); err != nil || resp.GetGeneration() != 2 {
		t.Fatalf("lv cluster voter rm %s: %+v %v", n4.Name, resp, err)
	}
	adoptAll(t, c, 2)
	voterAdd(t, c, n0, n4, 3)
	adoptAll(t, c, 3)

	// Three die for good: fence-confirmed, forced out, removed and revoked.
	for _, n := range []*Node{n2, n3, n4} {
		c.Kill(n)
	}
	for _, n := range []*Node{n2, n3, n4} {
		fenceConfirm(t, c, n0, n)
	}
	c.WaitConverged(t, convergeTimeout, n0, n1)
	if resp, err := forceErr(t, c, n0, false, n2, n3, n4); err != nil || resp.GetGeneration() != 4 {
		t.Fatalf("force-reconfigure: %+v %v", resp, err)
	}
	adoptAll(t, c, 4, n0, n1)
	withOperatorPKI(t, n0)
	for _, n := range []*Node{n2, n3, n4} {
		if err := cli.HostRemoveDead(ctx, c.SelfClient(n0), n.Name, false); err != nil {
			t.Fatalf("lv host rm --dead %s: %v", n.Name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout, n0, n1)
	syncCRL(t, n0, n1)
	gen1, gen3 := voterRow(t, n0, 1), voterRow(t, n0, 3)

	// All three rebuilt under their old names before any is voted back in, as
	// on the lab: when node-4 adopts, node-2 and node-3 — named lost by
	// generation 4 — are live hosts again.
	reimage(t, c, n2, n0, n0, n1)
	reimage(t, c, n3, n0, n0, n1, n2)
	reimage(t, c, n4, n0, n0, n1, n2, n3)
	for _, n := range []*Node{n2, n3, n4} {
		old, _ := gen1.Member(n.Name)
		inc, err := n.DB.VoterIncarnation(ctx)
		if err != nil || inc == old.Incarnation {
			t.Fatalf("the rebuilt %s kept its old incarnation (%v)", n.Name, err)
		}
	}
	if _, ok := gen3.Member(n4.Name); !ok {
		t.Fatalf("generation 3 does not list %s under its old incarnation", n4.Name)
	}

	voterAdd(t, c, n0, n4, 5) // {0,1,4}, decided by {0,1}
	adoptRebuilt(t, n4, 5)
	adoptAll(t, c, 5, n0, n1, n4)
	voterAdd(t, c, n0, n3, 6) // {0,1,3,4}, decided by two of {0,1,4}
	adoptRebuilt(t, n3, 6)
	adoptAll(t, c, 6, n0, n1, n3, n4)

	// node-3 and node-4 vote: with node-1 out, only they can make three of four.
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "vm-after-rebuild", OwnerEpoch: 1}
	c.SetLinkFault(n0, n1, LinkFault{BlockClaims: true})
	out, err := n0.Server.DecideRecoveryClaim(ctx, key, workloadClaimValue(key, n0.Name, "proof-rebuilt"), 1, nil)
	if err != nil {
		t.Fatalf("no recovery claim can be decided at generation 6 without node-1: %v", err)
	}
	var signers []string
	for _, a := range out.Certificate.Accepts {
		signers = append(signers, a.Voter)
	}
	slices.Sort(signers)
	if !slices.Equal(signers, nodeNames(n0, n3, n4)) || out.Certificate.ConfigGeneration != 6 {
		t.Fatalf("the claim was certified by %v at generation %d, want %v at 6", signers,
			out.Certificate.ConfigGeneration, nodeNames(n0, n3, n4))
	}
	c.SetLinkFault(n0, n1, LinkFault{})

	// The last step back to five voters.
	voterAdd(t, c, n0, n2, 7)
	adoptAll(t, c, 7)
	for _, n := range c.Nodes {
		if got := voterNames(t, n); !slices.Equal(got, nodeNames(c.Nodes...)) {
			t.Fatalf("%s counts voters %v after the restore", n.Name, got)
		}
	}
}

// signedVoterRow forges a voter_configs row: value certified at key
// (voter_config, prev.Generation) by signers' own keys — what a holder of
// those private keys can write into any replica.
func signedVoterRow(t *testing.T, prev *corrosion.VoterConfig, value corrosion.VoterConfigValue, signers ...*Node) corrosion.ClaimCertificate {
	t.Helper()
	want, err := corrosion.ExpectedVoterConfigCertificate(prev, value)
	if err != nil {
		t.Fatal(err)
	}
	ballot := corrosion.Ballot{Round: 99, Coordinator: signers[0].Name, Nonce: []byte{7}}
	cert := corrosion.ClaimCertificate{Key: want.Key, ConfigGeneration: want.ConfigGeneration, Ballot: ballot,
		ValueDigest: want.ValueDigest}
	for _, n := range signers {
		s, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := prev.Member(n.Name)
		a, err := s.Sign(want.Key, want.ConfigGeneration, ballot, want.ValueDigest, m.Incarnation)
		if err != nil {
			t.Fatal(err)
		}
		cert.Accepts = append(cert.Accepts, a)
	}
	return cert
}

// TestFleet_VoterChain_ARevokedKeyDecidesNothingNew: revocation still stops a
// revoked key from signing anything new. Two of three voters' certificates are
// revoked while they are still members, and their holder writes generation 2
// (dropping the one honest voter) signed with those two keys — a majority of
// generation 1 — and a generation 3 on top of it, signed the same way, to try
// to give it a successor to stand on. The honest voter adopts neither: no
// generation in that chain verifies against its CRL, so there is nothing for
// the history to be judged from.
//
// Mutation: choose the anchor without the CRL (the historical verifier for
// the anchor's own certificate) — the honest node adopts both forged
// generations.
func TestFleet_VoterChain_ARevokedKeyDecidesNothingNew(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2542})
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	gen1 := voterRow(t, n0, 1)

	withOperatorPKI(t, n0)
	revokeOn(t, c, n0, hostSerial(t, n1))
	revokeOn(t, c, n0, hostSerial(t, n2))
	syncCRL(t, n0)

	m1, _ := gen1.Member(n1.Name)
	m2, _ := gen1.Member(n2.Name)
	g2 := corrosion.VoterConfigValue{Generation: 2, Members: corrosion.SortMembers([]corrosion.VoterMember{m1, m2}),
		Change: corrosion.VoterChangeRm(n0.Name), CreatedBy: "mallory", CreatedAt: "2026-10-03T00:00:00Z"}
	if err := corrosion.WriteVoterConfig(ctx, n0.DB, g2, signedVoterRow(t, gen1, g2, n1, n2)); err != nil {
		t.Fatal(err)
	}
	if _, err := n0.Server.AdoptVoterConfigs(ctx); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("adopting a generation signed only by revoked keys was not refused naming the revocation: %v", err)
	}
	if g := adoptedGen(t, n0); g != 1 {
		t.Fatalf("%s adopted generation %d, decided by revoked keys alone", n0.Name, g)
	}

	g2row := voterRow(t, n0, 2)
	m0, _ := gen1.Member(n0.Name)
	g3 := corrosion.VoterConfigValue{Generation: 3, Members: corrosion.SortMembers([]corrosion.VoterMember{m0, m1, m2}),
		Change: corrosion.VoterChangeAdd(n0.Name), CreatedBy: "mallory", CreatedAt: "2026-10-03T00:00:01Z"}
	if err := corrosion.WriteVoterConfig(ctx, n0.DB, g3, signedVoterRow(t, g2row, g3, n1, n2)); err != nil {
		t.Fatal(err)
	}
	_, _ = n0.Server.AdoptVoterConfigs(ctx)
	if g := adoptedGen(t, n0); g != 1 {
		t.Fatalf("%s adopted generation %d: a chain signed by revoked keys anchored itself", n0.Name, g)
	}
}
