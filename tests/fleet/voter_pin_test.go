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
// attack. node-0 renews (its old key is owed revocation, so still CA-valid and
// unrevoked). An honest change made afterwards — node-0 signing with its
// renewed key — is adopted everywhere (generation 2 = node-0..2). Then a
// forged generation 3 (remove node-2) is signed with node-0's OLD key and
// node-1's live key: a majority of generation 2. No node adopts it — checked
// on node-2 and node-3, which are not members of generation 3 and so would
// adopt it on verification alone (a member would also have to import claim
// state). Above the adopted generation, every accept must be signed with the
// certificate recorded for its voter, or that certificate's CA-attested
// successor.
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
		if err == nil || !strings.Contains(err.Error(), "recorded") {
			t.Fatalf("%s did not refuse the forged generation for its replaced-key accept: %v", n.Name, err)
		}
	}
}
