package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// signedVoterRowWith is signedVoterRow with explicit signers' pki dirs, so a
// row can be signed with a certificate a node no longer holds.
func signedVoterRowWith(t *testing.T, prev *corrosion.VoterConfig, value corrosion.VoterConfigValue, signers map[string]string) corrosion.ClaimCertificate {
	t.Helper()
	want, err := corrosion.ExpectedVoterConfigCertificate(prev, value)
	if err != nil {
		t.Fatal(err)
	}
	var coord string
	for name := range signers {
		coord = name
		break
	}
	ballot := corrosion.Ballot{Round: 77, Coordinator: coord, Nonce: []byte{9}}
	cert := corrosion.ClaimCertificate{Key: want.Key, ConfigGeneration: want.ConfigGeneration, Ballot: ballot,
		ValueDigest: want.ValueDigest}
	for name, dir := range signers {
		s, err := corrosion.LoadClaimSigner(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := prev.Member(name)
		a, err := s.Sign(want.Key, want.ConfigGeneration, ballot, want.ValueDigest, m.Incarnation)
		if err != nil {
			t.Fatal(err)
		}
		cert.Accepts = append(cert.Accepts, a)
	}
	return cert
}

// TestFleet_VoterPin_AReplacedKeyDecidesNoNewGeneration is the re-review's N3
// attack. node-0 renews (its old key unrevoked — held, or kept with
// --keep-old). An honest change made afterwards — node-0 signing with its
// renewed key — is adopted everywhere (generation 2 = node-0..2). Then a
// forged generation 3 (remove node-2) is signed with node-0's OLD key and
// node-1's live key: a majority of generation 2. No node adopts it — checked
// on node-2 and node-3, which are not members of generation 3 and so would
// adopt it on verification alone (a member would also have to import claim
// state). Above the adopted generation, no accept signed with a certificate
// the CA has replaced counts.
//
// Mutation: drop the serial pin from voter-chain adoption (voterPinned) —
// node-2 and node-3 adopt the forged generation.
func TestFleet_VoterPin_AReplacedKeyDecidesNoNewGeneration(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 7714})
	n0, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)

	newSerial, oldDir := installRenewal(t, c, n0)
	if _, err := corrosion.RecordOwnCertSerial(ctx, n0.DB, n0.Name, newSerial); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "every node to record node-0's renewed serial", func() bool {
		for _, n := range c.Nodes {
			if _, rec, _, _ := hostRowOf(t, n, n0.Name); !strings.EqualFold(rec, newSerial) {
				return false
			}
		}
		return true
	})

	if resp, err := c.SelfClient(n1).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n3.Name}); err != nil ||
		resp.GetGeneration() != 2 {
		t.Fatalf("lv cluster voter rm %s after node-0 renewed: %+v %v", n3.Name, resp, err)
	}
	adoptAll(t, c, 2)
	gen2 := voterRow(t, n1, 2)
	m0, _ := gen2.Member(n0.Name)
	m1, _ := gen2.Member(n1.Name)

	forged := corrosion.VoterConfigValue{Generation: 3, Members: corrosion.SortMembers([]corrosion.VoterMember{m0, m1}),
		Change: corrosion.VoterChangeRm(n2.Name), CreatedBy: "mallory", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := corrosion.WriteVoterConfig(ctx, n1.DB, forged,
		signedVoterRowWith(t, gen2, forged, map[string]string{n0.Name: oldDir, n1.Name: n1.PKIDir})); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the forged row to replicate", func() bool {
		return voterRow(t, n2, 3) != nil && voterRow(t, n3, 3) != nil
	})
	for _, n := range []*Node{n2, n3} {
		_, err := n.Server.AdoptVoterConfigs(ctx)
		if g := adoptedGen(t, n); g != 2 {
			t.Fatalf("%s adopted generation %d, signed with a replaced key", n.Name, g)
		}
		if err == nil || !strings.Contains(err.Error(), "replaced") {
			t.Fatalf("%s did not refuse the forged generation for its replaced-key accept: %v", n.Name, err)
		}
	}
}

// TestFleet_VoterPin_ARewrittenSerialDoesNotReopenTheReplacedKey is re-review
// 2's R1 attack: the same forgery, by an attacker who ALSO controls a live
// host (node-1) and uses it to write node-0's hosts.cert_serial back to the
// replaced serial — a plain replicated column any peer can write. The pin's
// authority is the CA-signed successor each node collected (node-0's
// handshakes, its accepts in generation 2), not that column, so the rewrite
// changes nothing: node-2 and node-3 still refuse the forged generation.
//
// Mutation: make pki.SupersededError report nothing (the pin has no authority
// left) — node-2 and node-3 adopt the forged generation.
func TestFleet_VoterPin_ARewrittenSerialDoesNotReopenTheReplacedKey(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 7715})
	n0, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)

	_, oldSerial, _, _ := hostRowOf(t, n1, n0.Name)
	newSerial, oldDir := installRenewal(t, c, n0)
	if _, err := corrosion.RecordOwnCertSerial(ctx, n0.DB, n0.Name, newSerial); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "every node to record node-0's renewed serial", func() bool {
		for _, n := range c.Nodes {
			if _, rec, _, _ := hostRowOf(t, n, n0.Name); !strings.EqualFold(rec, newSerial) {
				return false
			}
		}
		return true
	})
	if resp, err := c.SelfClient(n1).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n3.Name}); err != nil ||
		resp.GetGeneration() != 2 {
		t.Fatalf("lv cluster voter rm %s after node-0 renewed: %+v %v", n3.Name, resp, err)
	}
	adoptAll(t, c, 2)
	gen2 := voterRow(t, n1, 2)
	m0, _ := gen2.Member(n0.Name)
	m1, _ := gen2.Member(n1.Name)

	// The compromised node-1 writes node-0's serial back to the replaced one,
	// and it replicates.
	if _, err := corrosion.RecordOwnCertSerial(ctx, n1.DB, n0.Name, oldSerial); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the rewritten serial to replicate", func() bool {
		for _, n := range []*Node{n2, n3} {
			if _, rec, _, _ := hostRowOf(t, n, n0.Name); !strings.EqualFold(rec, oldSerial) {
				return false
			}
		}
		return true
	})

	forged := corrosion.VoterConfigValue{Generation: 3, Members: corrosion.SortMembers([]corrosion.VoterMember{m0, m1}),
		Change: corrosion.VoterChangeRm(n2.Name), CreatedBy: "mallory", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := corrosion.WriteVoterConfig(ctx, n1.DB, forged,
		signedVoterRowWith(t, gen2, forged, map[string]string{n0.Name: oldDir, n1.Name: n1.PKIDir})); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the forged row to replicate", func() bool {
		return voterRow(t, n2, 3) != nil && voterRow(t, n3, 3) != nil
	})
	for _, n := range []*Node{n2, n3} {
		_, err := n.Server.AdoptVoterConfigs(ctx)
		if g := adoptedGen(t, n); g != 2 {
			t.Fatalf("%s adopted generation %d, signed with a replaced key whose serial a peer wrote back", n.Name, g)
		}
		if err == nil || !strings.Contains(err.Error(), "replaced") {
			t.Fatalf("%s did not refuse the forged generation for its replaced-key accept: %v", n.Name, err)
		}
	}
}

// renewThroughCLI runs `lv host renew-cert <target>` against via, on the
// default path (the replaced certificate revoked at once unless a hold
// applies), and waits for the replaced certificate to be revoked on every
// node. It returns the replaced serial. The caller has run withOperatorPKI
// on via and runs the certificate watches.
func renewThroughCLI(t *testing.T, c *Cluster, target, via *Node) string {
	t.Helper()
	ctx := context.Background()
	prevCert, err := pki.ServedHostCertificate(target.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	prev := strings.ToLower(prevCert.SerialNumber.Text(16))
	if err := cli.RenewHostCertOn(ctx, c.SelfClient(via), &cli.LocalRemotePKI{Dir: target.PKIDir},
		cli.GRPCProbe(target.Address, target.Port), target.Name, cli.RenewCertOptions{Wait: 20 * time.Second}); err != nil {
		t.Fatalf("renew-cert %s: %v", target.Name, err)
	}
	eventually(t, convergeTimeout, "the replaced certificate to be revoked on every node", func() bool {
		for _, n := range c.Nodes {
			_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
			if !revokedOn(n, prev) {
				return false
			}
		}
		return true
	})
	return prev
}

func stuckCondition(t *testing.T, n *Node) corrosion.HealthCondition {
	t.Helper()
	cnd, _, err := corrosion.GetHealthCondition(context.Background(), n.DB, "certificate", "voter_generation_stuck", "host", n.Name)
	if err != nil {
		t.Fatal(err)
	}
	return cnd
}

// TestFleet_VoterPin_AStuckGenerationIsReportedWithItsRemedy is re-review
// 2's R5, through the product path (re-review 3's I2). Generation 2 (rm
// node-3) is decided with exactly a majority of generation 1 — node-0's
// accept among them — while node-3, kept out of the claim, has not adopted
// it. Then `lv host renew-cert node-0` runs on its default path, which
// REVOKES node-0's replaced certificate at once. From then on node-3 cannot
// count node-0's pre-renewal accept — pinned and revoked — and generation 2
// stops one short of a majority for it.
//
// node-0 does not answer re-attestation here (as a host on an older build
// would not), so node-3 is stuck at generation 1. It says so, naming node-0
// and the voter change that cures it, as a health condition. That remedy —
// one more voter change from a node that adopted generation 2, signed with
// current certificates — becomes node-3's anchor, it adopts through it with
// node-0's replaced certificate revoked, and the condition clears.
//
// Mutations: drop the noteStuckByRenewal call from AdoptVoterConfigs —
// node-3 stays stuck and nothing says so; make RenewalBlind honour the
// revocation of a replaced certificate (the round-4 WithoutSerialPin check)
// — the revoked accept hides the renewal and nothing is raised.
func TestFleet_VoterPin_AStuckGenerationIsReportedWithItsRemedy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 7716})
	n0, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)

	blockClaimsInto(c, n3)
	if resp, err := c.SelfClient(n1).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n3.Name}); err != nil ||
		resp.GetGeneration() != 2 {
		t.Fatalf("lv cluster voter rm %s: %+v %v", n3.Name, resp, err)
	}
	c.ClearLinkFaults()
	adoptAll(t, c, 2, n0, n1, n2)
	eventually(t, convergeTimeout, "generation 2 to reach node-3", func() bool { return voterRow(t, n3, 2) != nil })
	if g := adoptedGen(t, n3); g != 1 {
		t.Fatalf("fixture: node-3 adopted generation %d before node-0 renewed", g)
	}

	withOperatorPKI(t, n1)
	stop := runCertWatches(c)
	defer stop()
	restore := n0.DoNotImplement("GetRecoveryClaim")
	defer restore()
	renewThroughCLI(t, c, n0, n1)

	_, err := n3.Server.AdoptVoterConfigs(ctx)
	if g := adoptedGen(t, n3); g != 1 || err == nil {
		t.Fatalf("fixture: node-3 at generation %d (%v); want it stuck below generation 2", g, err)
	}
	cnd := stuckCondition(t, n3)
	if cnd.Lifecycle == "" || cnd.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cnd.Evidence, "lv cluster voter") ||
		!strings.Contains(cnd.Evidence, n0.Name) {
		t.Fatalf("node-3 is stuck below generation 2 with node-0's replaced certificate revoked, and nothing says so, "+
			"names node-0, or says how to fix it: %+v", cnd)
	}

	// The remedy the condition names: one more voter change.
	if resp, err := c.SelfClient(n1).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n2.Name}); err != nil ||
		resp.GetGeneration() != 3 {
		t.Fatalf("lv cluster voter rm %s: %+v %v", n2.Name, resp, err)
	}
	adoptAll(t, c, 3)
	if cnd := stuckCondition(t, n3); cnd.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("node-3 adopted generation 3 but its stuck condition is %s", cnd.Lifecycle)
	}
}

// TestFleet_VoterPin_AMajorityStuckByARenewalAdoptsThroughReattestation is
// re-review 3's I2 majority case. Generation 2 (rm node-2) is decided by
// node-0 and node-1 — node-1 accepts it but has not adopted it, and neither
// has node-2 — when `lv host renew-cert node-0` revokes node-0's replaced
// certificate. Generation 2's members are node-0 and node-1, and node-1 is
// stuck at generation 1, so a MAJORITY of generation 2 cannot count it:
//
//   - no voter change can be decided (node-0 alone is not a majority of
//     generation 2, and node-1 answers only at generation 1);
//   - auth.trust_rotated_peer_certs, the round-4 remedy, does not help: it
//     relaxes the pin, not revocation.
//
// The cure is the renewed voter's re-attestation: node-0 re-signs its own
// recorded accept for generation 2 with its renewed certificate, and node-1
// and node-2 adopt it. Then the voter set moves again.
//
// A voter re-attests only what its own claim state accepted: asked about a
// generation it never voted on, node-0 gives nothing.
//
// Mutation: make reattestedAccept return nil — node-1 and node-2 stay stuck
// and no voter change can ever be decided.
func TestFleet_VoterPin_AMajorityStuckByARenewalAdoptsThroughReattestation(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7717})
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)

	blockClaimsInto(c, n2)
	if resp, err := c.SelfClient(n0).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n2.Name}); err != nil ||
		resp.GetGeneration() != 2 {
		t.Fatalf("lv cluster voter rm %s: %+v %v", n2.Name, resp, err)
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "generation 2 to reach node-1 and node-2", func() bool {
		return voterRow(t, n1, 2) != nil && voterRow(t, n2, 2) != nil
	})
	if adoptedGen(t, n0) != 2 || adoptedGen(t, n1) != 1 || adoptedGen(t, n2) != 1 {
		t.Fatalf("fixture: adopted generations %d/%d/%d, want 2/1/1", adoptedGen(t, n0), adoptedGen(t, n1), adoptedGen(t, n2))
	}

	withOperatorPKI(t, n1)
	stop := runCertWatches(c)
	defer stop()
	restore := n0.DoNotImplement("GetRecoveryClaim")
	renewThroughCLI(t, c, n0, n1)
	// node-0's cached self client was made with the certificate just
	// replaced and revoked, and is refused from here on: dial afresh.
	fresh0 := c.PeerClient(n0, n0)

	for _, n := range []*Node{n1, n2} {
		if _, err := n.Server.AdoptVoterConfigs(ctx); err == nil || adoptedGen(t, n) != 1 {
			t.Fatalf("fixture: %s adopted generation %d (%v); want it stuck at 1", n.Name, adoptedGen(t, n), err)
		}
		if cnd := stuckCondition(t, n); cnd.Lifecycle == "" || cnd.Lifecycle == corrosion.ConditionResolved {
			t.Fatalf("%s is stuck by a renewal and nothing says so: %+v", n.Name, cnd)
		}
	}
	// The deadlock is real: no change can be decided, and the round-4
	// remedy does not adopt.
	if _, err := fresh0.ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "add", Host: n2.Name}); err == nil ||
		!strings.Contains(err.Error(), "not decided") {
		t.Fatalf("fixture: a voter change with a majority of generation 2 stuck below it: %v, want it not decided", err)
	}
	n1.Server.SetTrustRotatedPeerCerts(true)
	if _, err := n1.Server.AdoptVoterConfigs(ctx); err == nil || adoptedGen(t, n1) != 1 {
		t.Fatalf("fixture: trust_rotated_peer_certs adopted generation %d (%v) with the replaced certificate revoked",
			adoptedGen(t, n1), err)
	}
	n1.Server.SetTrustRotatedPeerCerts(false)

	// node-0 answers re-attestation: the stuck nodes adopt.
	restore()
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig, OwnerEpoch: 7}
	if resp, err := fresh0.GetRecoveryClaim(ctx, &pb.GetRecoveryClaimRequest{Key: &pb.RecoveryClaimKey{
		TargetKind: key.TargetKind, OwnerEpoch: key.OwnerEpoch}, Reattest: true}); err != nil || resp.GetReattested() != nil {
		t.Fatalf("node-0 re-attested an accept for a generation it never voted on: %+v %v", resp.GetReattested(), err)
	}
	adoptAll(t, c, 2)
	for _, n := range []*Node{n1, n2} {
		if cnd := stuckCondition(t, n); cnd.Lifecycle != corrosion.ConditionResolved {
			t.Fatalf("%s adopted generation 2 but its stuck condition is %s", n.Name, cnd.Lifecycle)
		}
	}
	if resp, err := fresh0.ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "add", Host: n2.Name}); err != nil ||
		resp.GetGeneration() != 3 {
		t.Fatalf("lv cluster voter add %s once the stuck nodes adopted: %+v %v", n2.Name, resp, err)
	}
	adoptAll(t, c, 3)
}
