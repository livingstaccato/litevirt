package corrosion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The currency pull's candidates (re-review 1, m-1): the target is never
// asked; with nobody else to ask it proceeds, but a skipped voter is named and
// refuses.
func TestPullTableNow_Candidates(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	for _, h := range []string{c.hostName, "target", "voter-x"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	ae := NewAntiEntropy(c, "", 0)

	// Only the target besides this node: nobody to confirm with, proceed.
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "target"}} })
	if peer, _, err := ae.PullTableNow(ctx, "hosts", "target"); err != nil || peer != "" {
		t.Fatalf("alone with the target: (%q, %v), want to proceed", peer, err)
	}

	// Another voter, isolated: refused, and named.
	if _, err := c.DB().Exec(`UPDATE hosts SET isolation_epoch = 3, isolation_reason = 'manual' WHERE name = 'voter-x'`); err != nil {
		t.Fatal(err)
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "target"}, {Name: "voter-x"}} })
	_, skipped, err := ae.PullTableNow(ctx, "hosts", "target")
	if !errors.Is(err, ErrNoPeerConfirmed) || !strings.Contains(err.Error(), "voter-x (isolated)") {
		t.Errorf("every other voter skipped: %v, want the refusal naming voter-x", err)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped = %v", skipped)
	}
}

// Re-review 2, m-3: a coordinator in release probation names itself.
func TestPullTableNow_InProbationNamesThisNode(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.EnterReleaseProbation([]string{"release_9999_01_v1"})
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "peer"}} })
	_, _, err := NewAntiEntropy(c, "", 0).PullTableNow(ctx, "hosts", "target")
	if !errors.Is(err, ErrNoPeerConfirmed) || !strings.Contains(err.Error(), "this node is in release probation") {
		t.Errorf("in probation: %v", err)
	}
}

// Re-review 3, m-5: a voter set that cannot be read fails closed. Without it a
// skipped voter cannot be told from a skipped non-voter, so the "nobody to
// confirm with" answer that lets a lone coordinator proceed is not given.
func TestPullTableNow_AnUnreadableVoterSetRefuses(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	for _, h := range []string{c.hostName, "target"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "target"}} })
	ae := NewAntiEntropy(c, "", 0)
	// Precondition: alone with the target, the pull proceeds.
	if peer, _, err := ae.PullTableNow(ctx, "hosts", "target"); err != nil || peer != "" {
		t.Fatalf("precondition, alone with the target: (%q, %v), want to proceed", peer, err)
	}
	// An adopted generation with no voter_configs row: VoterSet errors.
	if err := RecordVoterAdoption(ctx, c, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := VoterSet(ctx, c); err == nil {
		t.Fatal("precondition: VoterSet read an adopted generation that has no row")
	}
	_, _, err := ae.PullTableNow(ctx, "hosts", "target")
	if !errors.Is(err, ErrNoPeerConfirmed) || !strings.Contains(err.Error(), "read the voter set") {
		t.Errorf("unreadable voter set: %v, want ErrNoPeerConfirmed naming the voter set", err)
	}
}

// Lab test 26, F4: a voter that does not answer gets only its share of the
// pull's budget, so the reachable voter behind it is still asked.
func TestPullTableNow_AnUnreachableVoterDoesNotStarveTheRest(t *testing.T) {
	c := newTestDB(t)
	for _, h := range []string{c.hostName, "target", "voter-a", "voter-b"} {
		if err := InsertHost(context.Background(), c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "voter-a"}, {Name: "voter-b"}, {Name: "target"}} })
	ae := NewAntiEntropy(c, "", 0)
	var asked []string
	ae.tablePull = func(ctx context.Context, peer, _ string) error {
		asked = append(asked, peer)
		if peer == "voter-a" {
			<-ctx.Done() // dropped packets: no answer until the deadline
			return ctx.Err()
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	peer, _, err := ae.PullTableNow(ctx, "hosts", "target")
	if err != nil || peer != "voter-b" {
		t.Errorf("PullTableNow = (%q, %v) after asking %v; want voter-b to confirm", peer, err, asked)
	}
}

// Re-review m-2: the budget is shared among the voters still left, not every
// candidate, so non-voters (asked only once every voter has failed) do not
// shrink it; and no candidate's share falls below the per-peer floor while
// the budget lasts.
//
// Mutations: divide by every candidate left again — "many non-voters" fails;
// drop the floor — "many voters" fails.
func TestPullTableNow_TheBudgetIsSharedAmongTheVoters(t *testing.T) {
	run := func(t *testing.T, voters, nonVoters int, budget, slow time.Duration) (string, error) {
		c := newTestDB(t)
		var members []PeerInfo
		add := func(name, state string) {
			if err := InsertHost(context.Background(), c, HostRecord{Name: name, Address: "10.0.0.1", State: state, CertSerial: "s-" + name}); err != nil {
				t.Fatal(err)
			}
			if name != c.hostName {
				members = append(members, PeerInfo{Name: name})
			}
		}
		add(c.hostName, "active")
		add("target", "active")
		for i := 0; i < voters; i++ {
			add(fmt.Sprintf("voter-%02d", i), "active")
		}
		for i := 0; i < nonVoters; i++ {
			add(fmt.Sprintf("nonvoter-%02d", i), "maintenance")
		}
		c.SetMembersForTests(func() []PeerInfo { return members })
		ae := NewAntiEntropy(c, "", 0)
		ae.tablePull = func(ctx context.Context, peer, _ string) error {
			if peer == "voter-00" {
				<-ctx.Done() // no answer until its deadline
				return ctx.Err()
			}
			select { // a healthy voter whose merge takes slow
			case <-time.After(slow):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		peer, _, err := ae.PullTableNow(ctx, "hosts", "target")
		return peer, err
	}
	t.Run("many non-voters", func(t *testing.T) {
		old := pullPeerFloor
		pullPeerFloor = 100 * time.Millisecond
		t.Cleanup(func() { pullPeerFloor = old })
		if peer, err := run(t, 2, 20, 2*time.Second, 300*time.Millisecond); err != nil || peer != "voter-01" {
			t.Errorf("PullTableNow = (%q, %v); want voter-01 to confirm", peer, err)
		}
	})
	t.Run("many voters", func(t *testing.T) {
		old := pullPeerFloor
		pullPeerFloor = 500 * time.Millisecond
		t.Cleanup(func() { pullPeerFloor = old })
		if peer, err := run(t, 10, 0, 2*time.Second, 300*time.Millisecond); err != nil || peer != "voter-01" {
			t.Errorf("PullTableNow = (%q, %v); want voter-01 to confirm", peer, err)
		}
	})
}
