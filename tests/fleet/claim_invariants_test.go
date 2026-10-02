package fleet

// The safety properties every claim-fault scenario asserts
// (docs/design/recovery-claims.md §2 G1, §3.5, §3.16), checked over what
// actually happened rather than over the end state alone:
//
//   - no voter accepts two different values at one ballot;
//   - no voter accepts a ballot below one it has already promised;
//   - at most one value is ever CHOSEN per claim key — accepted by a majority
//     of one generation at one ballot — whether or not anyone saw it chosen;
//   - at most one value digest is certified per claim key, across every
//     certificate in every replica;
//   - at most one ownership-transfer proof is minted per workload epoch;
//   - exactly one running domain of the workload, across every node's libvirt.
//
// The first three read a ledger of every promise and accept every voter
// committed, its own proposer's included (grpcapi.SetClaimVoteObserverForTest),
// which is how "chosen but never certified" — a coordinator that crashed after
// a majority accepted — is visible at all.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// claimLedger records every vote on every node of a cluster.
type claimLedger struct {
	mu    sync.Mutex
	votes []grpcapi.ClaimVote
}

// watchClaims starts recording every node's votes.
func watchClaims(t *testing.T, c *Cluster) *claimLedger {
	t.Helper()
	l := &claimLedger{}
	for _, n := range c.Nodes {
		n.Server.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
			l.mu.Lock()
			l.votes = append(l.votes, v)
			l.mu.Unlock()
		})
	}
	t.Cleanup(func() {
		for _, n := range c.Nodes {
			n.Server.SetClaimVoteObserverForTest(nil)
		}
	})
	return l
}

func (l *claimLedger) snapshot() []grpcapi.ClaimVote {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]grpcapi.ClaimVote(nil), l.votes...)
}

// accepts returns the accepts recorded for key.
func (l *claimLedger) accepts(key corrosion.ClaimKey) []grpcapi.ClaimVote {
	var out []grpcapi.ClaimVote
	for _, v := range l.snapshot() {
		if v.Phase == "accept" && v.Key == key {
			out = append(out, v)
		}
	}
	return out
}

func ballotID(b corrosion.Ballot) string {
	return fmt.Sprintf("%d/%s/%x", b.Round, b.Coordinator, b.Nonce)
}

// chosen returns, per claim key, every value digest a majority of one
// generation accepted at one ballot. majority answers a generation's quorum.
func (l *claimLedger) chosen(majority func(gen int64) int) map[corrosion.ClaimKey]map[string]bool {
	type slot struct {
		key    corrosion.ClaimKey
		gen    int64
		ballot string
		digest string
	}
	voters := map[slot]map[string]bool{}
	for _, v := range l.snapshot() {
		if v.Phase != "accept" {
			continue
		}
		s := slot{v.Key, v.Generation, ballotID(v.Ballot), v.Digest}
		if voters[s] == nil {
			voters[s] = map[string]bool{}
		}
		voters[s][v.Voter] = true
	}
	out := map[corrosion.ClaimKey]map[string]bool{}
	for s, vs := range voters {
		if len(vs) >= majority(s.gen) {
			if out[s.key] == nil {
				out[s.key] = map[string]bool{}
			}
			out[s.key][s.digest] = true
		}
	}
	return out
}

// checkVoters asserts the acceptor-side invariants: one value per ballot per
// voter, and no accept below a promise the voter had already made.
func (l *claimLedger) checkVoters(t *testing.T) {
	t.Helper()
	type vk struct {
		voter string
		key   corrosion.ClaimKey
	}
	type vkb struct {
		vk
		ballot string
	}
	promised := map[vk]corrosion.Ballot{}
	valueAt := map[vkb]string{}
	for i, v := range l.snapshot() {
		k := vk{v.Voter, v.Key}
		switch v.Phase {
		case "prepare":
			if corrosion.CompareBallots(v.Ballot, promised[k]) > 0 {
				promised[k] = v.Ballot
			}
		case "accept":
			if p := promised[k]; corrosion.CompareBallots(p, v.Ballot) > 0 {
				t.Errorf("vote %d: %s accepted %s at %s after promising %s", i, v.Voter, v.Key, v.Ballot, p)
			}
			if corrosion.CompareBallots(v.Ballot, promised[k]) > 0 {
				promised[k] = v.Ballot
			}
			slot := vkb{k, ballotID(v.Ballot)}
			if d, ok := valueAt[slot]; ok && d != v.Digest {
				t.Errorf("vote %d: %s accepted two values for %s at one ballot %s: %s and %s",
					i, v.Voter, v.Key, v.Ballot, short8(d), short8(v.Digest))
			}
			valueAt[slot] = v.Digest
		}
	}
}

func short8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// generationMajority reads a generation's quorum from n's replica.
func generationMajority(t *testing.T, n *Node) func(int64) int {
	return func(gen int64) int {
		row, err := corrosion.GetVoterConfig(context.Background(), n.DB, gen)
		if err != nil || row == nil {
			t.Fatalf("%s: voter generation %d: %v", n.Name, gen, err)
		}
		return corrosion.MajorityOf(len(row.Names()))
	}
}

// claimOutcome is what checkClaimSafety found, for a scenario's own
// assertions on top.
type claimOutcome struct {
	// Chosen is every digest a majority accepted at one ballot, per key.
	Chosen map[corrosion.ClaimKey]map[string]bool
	// Certified is every certified digest found in any replica, per key.
	Certified map[corrosion.ClaimKey]map[string]bool
	// Proofs is every ownership-transfer proof ID minted for the workload, per
	// owner epoch, across every replica.
	Proofs map[string]map[string]bool
	// Running names the nodes on which the workload's domain runs.
	Running []string
}

// checkClaimSafety asserts every property above for workload vm, over the
// ledger and over every given node's replica and libvirt. alive are the nodes
// whose libvirt can run anything (a dead node's fake has nothing).
func checkClaimSafety(t *testing.T, l *claimLedger, majorityFrom *Node, vm string, nodes []*Node) claimOutcome {
	t.Helper()
	ctx := context.Background()
	l.checkVoters(t)
	out := claimOutcome{Chosen: l.chosen(generationMajority(t, majorityFrom)),
		Certified: map[corrosion.ClaimKey]map[string]bool{}, Proofs: map[string]map[string]bool{}}
	for k, ds := range out.Chosen {
		if k.TargetName == vm && len(ds) > 1 {
			t.Errorf("%d values were chosen for %s (accepted by a majority at one ballot): %v", len(ds), k, keys(ds))
		}
	}
	for _, n := range nodes {
		rows, err := n.DB.Query(ctx, `SELECT id, action, owner_epoch, claim_certificate FROM runtime_action_proofs
			WHERE target_name = ? AND action IN ('reschedule', 'promote', 'relocate')`, vm)
		if err != nil {
			t.Fatalf("%s: read proofs: %v", n.Name, err)
		}
		for _, r := range rows {
			ep := r.String("owner_epoch")
			if out.Proofs[ep] == nil {
				out.Proofs[ep] = map[string]bool{}
			}
			out.Proofs[ep][r.String("id")] = true
			if s := r.String("claim_certificate"); s != "" {
				cert, err := corrosion.DecodeClaimCertificate(s)
				if err != nil {
					t.Errorf("%s: proof %s carries a certificate that does not parse: %v", n.Name, r.String("id"), err)
					continue
				}
				if out.Certified[cert.Key] == nil {
					out.Certified[cert.Key] = map[string]bool{}
				}
				out.Certified[cert.Key][cert.ValueDigest] = true
			}
		}
		if st, _ := n.Virt.DomainState(vm); st == string(libvirtfake.StateRunning) {
			out.Running = append(out.Running, n.Name)
		}
	}
	for k, ds := range out.Certified {
		if len(ds) > 1 {
			t.Errorf("%d different values are certified for %s: %v", len(ds), k, keys(ds))
		}
	}
	for ep, ids := range out.Proofs {
		if len(ids) > 1 {
			t.Errorf("%d ownership-transfer proofs were minted for %s at owner epoch %s: %v", len(ids), vm, ep, keys(ids))
		}
	}
	if len(out.Running) != 1 {
		t.Errorf("%d running domains of %s (%s), want exactly one", len(out.Running), vm, strings.Join(out.Running, ", "))
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, short8(k))
	}
	sort.Strings(out)
	return out
}
