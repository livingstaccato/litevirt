package corrosion

import (
	"errors"
	"slices"
	"testing"
)

// An isolated node has to be able to find the cluster again.
//
// list.Join runs ONCE, at startup; a failure is logged and the daemon carries
// on. Peer discovery for both replication and anti-entropy derives from
// Members(), so a node whose seeds were down at boot, or whose membership aged
// out across a long partition, has an empty peer set forever. Anti-entropy
// cannot repair against a peer it never discovers.
//
// This is the lab wedge: after a host suspend or a NIC flap, memberlist
// declares every peer departed and the only known cure is a rolling daemon
// restart, because a restart is the only thing that ever calls Join.
func TestRejoinTargets_UsesSeedsAndAdmittedHosts(t *testing.T) {
	seeds := []string{"10.0.0.1:7946"}
	hosts := []HostRecord{
		{Name: "node-a", Address: "10.0.0.1"},
		{Name: "node-b", Address: "10.0.0.2"},
		{Name: "node-c", Address: "10.0.0.3"},
	}

	got := rejoinTargets(seeds, hosts, "node-a", "10.0.0.1")

	// Self's HOSTS-TABLE address is excluded: dialling our own gossip port
	// rediscovers nothing, and on a cluster where every node has the same seed
	// list it is the majority of the dial set. The configured seed
	// "10.0.0.1:7946" may legitimately name us -- an operator's seed list is not
	// ours to second-guess -- so only the bare address derived from the hosts
	// row is checked here.
	if slices.Contains(got, "10.0.0.1") {
		t.Errorf("targets = %v; our own hosts-table address must not be dialled", got)
	}
	if !slices.Contains(got, "10.0.0.2") || !slices.Contains(got, "10.0.0.3") {
		t.Fatalf("targets = %v; the admitted hosts table is the only record of peers that "+
			"survives a membership wipe, so a node with stale seeds can never come back", got)
	}
	if slices.Contains(got, "node-a") {
		t.Errorf("targets = %v; must not contain our own name", got)
	}
}

// A removed host must never be dialled back in. ListHosts already filters
// tombstones, so the contract here is that the caller passes that filtered set
// and rejoinTargets does not reintroduce anything from elsewhere.
func TestRejoinTargets_SkipsBlankAddresses(t *testing.T) {
	hosts := []HostRecord{{Name: "node-b", Address: ""}, {Name: "node-c", Address: "10.0.0.3"}}
	got := rejoinTargets(nil, hosts, "node-a", "10.0.0.1")
	if slices.Contains(got, "") {
		t.Fatalf("targets = %v; a blank address makes memberlist dial nothing and log noise", got)
	}
	if len(got) != 1 || got[0] != "10.0.0.3" {
		t.Errorf("targets = %v, want [10.0.0.3]", got)
	}
}

// The loop must not dial on every tick while the cluster is healthy: a node
// that already sees peers has nothing to rediscover, and re-joining N nodes on
// a timer is exactly the O(N) chatter the sizing work is trying to remove.
func TestRejoiner_DoesNothingWhilePeersAreVisible(t *testing.T) {
	called := 0
	r := &rejoiner{
		peerCount: func() int { return 2 },
		targets:   func() []string { return []string{"10.0.0.2"} },
		join:      func([]string) (int, error) { called++; return 1, nil },
	}
	attempted, _, _ := r.tick()
	if attempted || called != 0 {
		t.Fatalf("re-joined while %d peers were already visible (attempted=%v calls=%d)", 2, attempted, called)
	}
}

// And it MUST dial when the peer set is empty — that is the whole point.
func TestRejoiner_RejoinsWhenIsolated(t *testing.T) {
	var got []string
	r := &rejoiner{
		peerCount: func() int { return 0 },
		targets:   func() []string { return []string{"10.0.0.2", "10.0.0.3"} },
		join:      func(ts []string) (int, error) { got = ts; return 2, nil },
	}
	attempted, joined, err := r.tick()
	if !attempted {
		t.Fatal("an isolated node did not attempt to re-join; it stays isolated until a " +
			"daemon restart, which is the manual step this removes")
	}
	if err != nil || joined != 2 {
		t.Errorf("joined=%d err=%v, want 2/nil", joined, err)
	}
	if len(got) != 2 {
		t.Errorf("join targets = %v, want both", got)
	}
}

// A failed re-join is reported, not swallowed: "joined 0 of N" is the signal an
// operator needs, and the startup path's habit of logging and carrying on is
// what made this invisible for a whole partition.
func TestRejoiner_ReportsAFailedAttempt(t *testing.T) {
	r := &rejoiner{
		peerCount: func() int { return 0 },
		targets:   func() []string { return []string{"10.0.0.2"} },
		join:      func([]string) (int, error) { return 0, errors.New("no route to host") },
	}
	attempted, joined, err := r.tick()
	if !attempted {
		t.Fatal("no attempt made")
	}
	if err == nil {
		t.Fatal("a re-join that reached nobody must report the error, or an isolated node " +
			"looks identical to a healthy one")
	}
	if joined != 0 {
		t.Errorf("joined = %d, want 0", joined)
	}
}

// Nothing to dial is not an error, and must not be reported as an attempt:
// a single-node cluster with no seeds is a legitimate configuration.
func TestRejoiner_NoTargetsIsNotAnAttempt(t *testing.T) {
	r := &rejoiner{
		peerCount: func() int { return 0 },
		targets:   func() []string { return nil },
		join:      func([]string) (int, error) { t.Fatal("dialled with no targets"); return 0, nil },
	}
	if attempted, _, err := r.tick(); attempted || err != nil {
		t.Errorf("attempted=%v err=%v; a single-node cluster is not a fault", attempted, err)
	}
}
