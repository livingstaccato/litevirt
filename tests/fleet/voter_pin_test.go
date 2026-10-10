package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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

// TestFleet_VoterPin_AStuckGenerationIsReportedWithItsRemedy is re-review 2's
// R5. Generation 2 (rm node-3) is decided with exactly a majority of
// generation 1 — node-0's accept among them — while node-3, kept out of the
// claim, has not adopted it. node-0 then renews and node-3 learns of it from
// node-0's handshake. From then on node-3 cannot count node-0's pre-renewal
// accept, and generation 2 stops one short of a majority for it: it is stuck
// at generation 1. It says so, with the remedy, as a health condition. The
// remedy — one more voter change from a node that adopted generation 2,
// signed with current certificates — becomes node-3's anchor, it adopts
// through it, and the condition clears.
//
// Mutation: drop noteAdoptionRefusedByPin from AdoptVoterConfigs — node-3
// stays stuck and nothing says so.
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

	newSerial, _ := installRenewal(t, c, n0)
	if _, err := corrosion.RecordOwnCertSerial(ctx, n0.DB, n0.Name, newSerial); err != nil {
		t.Fatal(err)
	}
	if got := servedSerial(t, n3, n0); !strings.EqualFold(got, newSerial) {
		t.Fatalf("node-0 serves %s, want %s", got, newSerial)
	}

	_, err := n3.Server.AdoptVoterConfigs(ctx)
	if g := adoptedGen(t, n3); g != 1 || err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("fixture: node-3 at generation %d (%v); want it stuck below generation 2 by the pin", g, err)
	}
	cnd, ok, gerr := corrosion.GetHealthCondition(ctx, n3.DB, "certificate", "voter_generation_stuck", "host", n3.Name)
	if gerr != nil || !ok || cnd.Lifecycle == corrosion.ConditionResolved || !strings.Contains(cnd.Evidence, "lv cluster voter") {
		t.Fatalf("node-3 is stuck below generation 2 and nothing says so, or not how to fix it: %+v %v", cnd, gerr)
	}

	// The remedy the condition names: one more voter change.
	if resp, err := c.SelfClient(n1).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n2.Name}); err != nil ||
		resp.GetGeneration() != 3 {
		t.Fatalf("lv cluster voter rm %s: %+v %v", n2.Name, resp, err)
	}
	adoptAll(t, c, 3)
	cnd, _, _ = corrosion.GetHealthCondition(ctx, n3.DB, "certificate", "voter_generation_stuck", "host", n3.Name)
	if cnd.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("node-3 adopted generation 3 but its stuck condition is %s", cnd.Lifecycle)
	}
}
