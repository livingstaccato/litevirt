package health

import (
	"context"
	"fmt"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The explicit voter set (colonelpanik/litevirt#251 step 2) reaches #262's
// probe plan and #265's region quorum through corrosion.VoterSet alone. These
// pin that combination: each case is one where the explicit set and the
// derived set give different answers, so a VoterSet that fell back to host
// state would be caught here.

// adoptVoters writes generation 1 with members and adopts it, as the adoption
// loop does once the certificate verifies (not what these tests are about).
func adoptVoters(t *testing.T, db *corrosion.Client, members ...string) {
	t.Helper()
	ctx := context.Background()
	db.SetVoterConfigGate(func() bool { return true })
	var ms []corrosion.VoterMember
	for _, m := range members {
		ms = append(ms, corrosion.VoterMember{Name: m, Incarnation: "inc-" + m})
	}
	val := corrosion.VoterConfigValue{Generation: 1, Members: corrosion.SortMembers(ms),
		Change: corrosion.VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
	if err := corrosion.WriteVoterConfig(ctx, db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, db, 1); err != nil {
		t.Fatal(err)
	}
}

func insertActiveHosts(t *testing.T, db *corrosion.Client, names []string, region func(i int) string) {
	t.Helper()
	ctx := context.Background()
	for i, name := range names {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: fmt.Sprintf("10.9.0.%d", i+1), SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
		if region != nil {
			if err := corrosion.UpdateHostRegion(ctx, db, name, region(i)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestProbePlan_ReadsTheAdoptedVoterSet: an active host that is not a member
// of the adopted generation is a non-voter to the probe plan — it probes the
// members and a bounded sample of the other non-voters, not the full mesh the
// derived set (every active host a voter) would give it.
//
// Mutation: make VoterSet ignore the adopted config — every host is active, so
// the derived set holds all ten and this node probes all nine peers.
func TestProbePlan_ReadsTheAdoptedVoterSet(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	names, _ := planCluster(10, 0)
	insertActiveHosts(t, db, names, nil)
	adoptVoters(t, db, names[0], names[1], names[2])

	self := names[9] // active, but not a member
	probes := &countingProbes{calls: map[string]map[string]int{}}
	c := NewChecker(self, t.TempDir(), db)
	c.writeFn = func(context.Context, string, ...interface{}) error { return nil }
	c.SetPeerReadiness(probes.forObserver(self))
	c.checkAllPeers(ctx)
	if got, want := probes.total(), 3+nonVoterProbeSample; got != want {
		t.Fatalf("%s probed %d peers; as a non-member it probes the 3 members and %d non-voters (%d)",
			self, got, nonVoterProbeSample, want)
	}
	for _, m := range names[:3] {
		if probes.calls[self][m] == 0 {
			t.Errorf("%s did not probe member %s; every target must keep every voter as an observer", self, m)
		}
	}
}

// TestRegionQuorumProof_CountsAFencedMember: under region-scoped failover a
// region's quorum is a majority of its members of the voter set. Once a
// generation is adopted a fenced member stays one, so four east members with
// one fenced still need three, where the derived set (three) would need two.
//
// Mutation: make VoterSet ignore the adopted config — needed drops to 2.
func TestRegionQuorumProof_CountsAFencedMember(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	names := []string{"east-0", "east-1", "east-2", "east-3", "west-0"}
	insertActiveHosts(t, db, names, func(i int) string {
		if i < 4 {
			return "east"
		}
		return "west"
	})
	adoptVoters(t, db, names...)
	if err := corrosion.UpdateHostState(ctx, db, "east-3", "fenced"); err != nil {
		t.Fatal(err)
	}
	c := NewChecker("east-0", t.TempDir(), db)
	_, _, needed := c.RegionQuorumProof(ctx, "east")
	if needed != 3 {
		t.Fatalf("east needs %d for quorum; the fenced member east-3 must stay in the denominator (want 3)", needed)
	}
	if _, _, needed := c.RegionQuorumProof(ctx, "west"); needed != 1 {
		t.Fatalf("west needs %d, want 1", needed)
	}
}
