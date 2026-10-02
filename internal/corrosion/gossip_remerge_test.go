package corrosion

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Two halves of a healed partition must find each other again.
//
// The re-join loop used to dial only when this node saw NOBODY. A 2|3
// partition leaves neither side empty, and memberlist does not re-merge two
// live clusters by itself: each side declares the other dead, reaps it after
// GossipToTheDeadTime, and nobody ever dials it again. The kvm003 drill of
// 2026-10-02 healed a partition and the halves were still apart eight minutes
// later — the minority never received the majority's fence row, its moved VM
// or its claim proof — until a daemon restart called Join.
//
// The trigger is a host the cluster still LISTS as a member that gossip does
// not show.

func names(ts []remergeTarget) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	slices.Sort(out)
	return out
}

func addrOf(ts []remergeTarget, name string) string {
	for _, t := range ts {
		if t.Name == name {
			return t.Addr
		}
	}
	return ""
}

// Only the hosts missing from gossip are targets — not every listed host and
// not the seeds. Dialling every seed each interval while peers are visible is
// the O(N) periodic chatter the sizing argument rules out; dialling the
// missing ones is O(missing), which is zero on a healthy cluster.
func TestRemergeTargets_OnlyListedHostsMissingFromGossip(t *testing.T) {
	hosts := []HostRecord{
		{Name: "node-1", Address: "10.0.0.1"},
		{Name: "node-2", Address: "10.0.0.2"},
		{Name: "node-3", Address: "10.0.0.3"},
		{Name: "node-4", Address: "10.0.0.4"},
		{Name: "node-5", Address: "10.0.0.5"},
	}
	visible := []PeerInfo{{Name: "node-2", Addr: "10.0.0.2:7946"}}

	got := remergeTargets(hosts, visible, nil, "node-1", "10.0.0.1")

	if want := []string{"node-3", "node-4", "node-5"}; !slices.Equal(names(got), want) {
		t.Fatalf("targets = %v, want %v: the hosts the cluster lists that gossip does not show", names(got), want)
	}
	if a := addrOf(got, "node-4"); a != "10.0.0.4" {
		t.Errorf("node-4 dialled at %q, want its recorded address 10.0.0.4", a)
	}
}

// A healthy cluster dials nobody.
func TestRemergeTargets_NothingMissingDialsNothing(t *testing.T) {
	hosts := []HostRecord{{Name: "node-1", Address: "10.0.0.1"}, {Name: "node-2", Address: "10.0.0.2"}}
	visible := []PeerInfo{{Name: "node-2", Addr: "10.0.0.2:7946"}}
	if got := remergeTargets(hosts, visible, nil, "node-1", "10.0.0.1"); len(got) != 0 {
		t.Fatalf("targets = %v; a node that sees every listed host has nothing to re-merge", names(got))
	}
}

// Self is never a target — by name, and not by a row that would make
// memberlist dial our own gossip port.
func TestRemergeTargets_ExcludesSelf(t *testing.T) {
	hosts := []HostRecord{
		{Name: "node-1", Address: "10.0.0.1"},
		{Name: "node-2", Address: ""}, // blank: dials nothing and logs noise
		{Name: "node-3", Address: "10.0.0.3"},
	}
	// selfAddr is empty when advertise_address is unset and memberlist
	// auto-detects, so the name is the only thing that identifies our row.
	for _, selfAddr := range []string{"10.0.0.1", ""} {
		got := remergeTargets(hosts, nil, nil, "node-1", selfAddr)
		if want := []string{"node-3"}; !slices.Equal(names(got), want) {
			t.Fatalf("selfAddr %q: targets = %v, want %v", selfAddr, names(got), want)
		}
	}
}

// The address memberlist last reported for a host carries its gossip port, so
// it is preferred — a host on a non-default gossip_port is unreachable at the
// bare recorded address. It is used only while it still names the recorded
// IP: a host since re-admitted at another address is dialled where its row
// says it lives (and admission would refuse the old one anyway).
func TestRemergeTargets_PrefersTheLastGossipAddressForTheRecordedIP(t *testing.T) {
	hosts := []HostRecord{
		{Name: "node-2", Address: "10.0.0.2"},
		{Name: "node-3", Address: "10.0.0.33"},
	}
	last := map[string]string{
		"node-2": "10.0.0.2:17946",
		"node-3": "10.0.0.3:7946", // re-addressed since
	}
	got := remergeTargets(hosts, nil, last, "node-1", "10.0.0.1")
	if a := addrOf(got, "node-2"); a != "10.0.0.2:17946" {
		t.Errorf("node-2 dialled at %q, want its last gossip address 10.0.0.2:17946", a)
	}
	if a := addrOf(got, "node-3"); a != "10.0.0.33" {
		t.Errorf("node-3 dialled at %q, want its recorded address 10.0.0.33 — the remembered one is stale", a)
	}
}

// A shared address with a remembered port is NOT self: an in-process fleet, or
// two daemons on one test host, gossip on one IP and different ports.
func TestRemergeTargets_SameIPOtherPortIsNotSelf(t *testing.T) {
	hosts := []HostRecord{{Name: "node-1", Address: "127.0.0.1"}, {Name: "node-2", Address: "127.0.0.1"}}
	last := map[string]string{"node-2": "127.0.0.1:20002"}
	got := remergeTargets(hosts, nil, last, "node-1", "127.0.0.1")
	if a := addrOf(got, "node-2"); a != "127.0.0.1:20002" {
		t.Fatalf("node-2 dialled at %q, want 127.0.0.1:20002", a)
	}
	// Without a remembered port the bare address is our own gossip port.
	if got := remergeTargets(hosts, nil, nil, "node-1", "127.0.0.1"); len(got) != 0 {
		t.Fatalf("targets = %v; the bare shared address would dial ourselves", names(got))
	}
}

func remergeHost(name, addr string) HostRecord {
	return HostRecord{
		Name: name, Address: addr, SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "ab" + name, FenceStrategy: "best-effort",
	}
}

// A removed host is never dialled back in — the membership read is the
// replicated hosts table with tombstones filtered, the same set gossip
// admission admits from. Host state is deliberately NOT a filter: the majority
// of a partition fences or marks offline exactly the hosts on the other side,
// so a state filter would exclude the very hosts that need re-merging.
func TestMissingMembers_ReadsTheHostsTableWithoutRemovedHosts(t *testing.T) {
	c := newPruneTestClient(t)
	c.hostName = "node-1"
	ctx := context.Background()
	for _, h := range []HostRecord{
		remergeHost("node-1", "10.0.0.1"),
		remergeHost("node-2", "10.0.0.2"),
		remergeHost("node-3", "10.0.0.3"),
		remergeHost("node-4", "10.0.0.4"),
		remergeHost("node-5", "10.0.0.5"),
	} {
		if err := InsertHost(ctx, c, h); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteHost(ctx, c, "node-3"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostState(ctx, c, "node-4", "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostState(ctx, c, "node-5", "maintenance"); err != nil {
		t.Fatal(err)
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "node-2", Addr: "10.0.0.2:7946"}} })

	got := c.missingMembers(ctx, "10.0.0.1")

	if slices.Contains(names(got), "node-3") {
		t.Fatalf("targets = %v; a removed host must never be dialled back into the cluster", names(got))
	}
	if want := []string{"node-4", "node-5"}; !slices.Equal(names(got), want) {
		t.Fatalf("targets = %v, want %v: a fenced or maintenance host is still a member the partition hid", names(got), want)
	}
}

// What gossip showed is remembered, so a host that later drops out is dialled
// at the address — port included — memberlist last had for it.
func TestMissingMembers_RemembersGossipAddresses(t *testing.T) {
	c := newPruneTestClient(t)
	c.hostName = "node-1"
	ctx := context.Background()
	for _, h := range []HostRecord{remergeHost("node-1", "127.0.0.1"), remergeHost("node-2", "127.0.0.1")} {
		if err := InsertHost(ctx, c, h); err != nil {
			t.Fatal(err)
		}
	}
	visible := []PeerInfo{{Name: "node-2", Addr: "127.0.0.1:20002"}}
	c.SetMembersForTests(func() []PeerInfo { return visible })
	if got := c.missingMembers(ctx, "127.0.0.1"); len(got) != 0 {
		t.Fatalf("targets = %v while node-2 is visible", names(got))
	}
	visible = nil
	got := c.missingMembers(ctx, "127.0.0.1")
	if a := addrOf(got, "node-2"); a != "127.0.0.1:20002" {
		t.Fatalf("node-2 dialled at %q, want the address gossip last showed (127.0.0.1:20002)", a)
	}
}

// remergeFixture is a rejoiner over a scripted view: `missing` is what the
// hosts table lists that gossip does not show, and a join of a host listed in
// `answers` makes it visible.
type remergeFixture struct {
	missing map[string]bool
	answers map[string]bool
	dials   [][]string
}

func (f *remergeFixture) rejoiner() *rejoiner {
	addr := map[string]string{"node-3": "10.0.0.3", "node-4": "10.0.0.4", "node-5": "10.0.0.5", "node-6": "10.0.0.6"}
	name := map[string]string{}
	for n, a := range addr {
		name[a] = n
	}
	return &rejoiner{
		peerCount: func() int { return 1 },
		targets:   func() []string { return []string{"seed-1:7946", "seed-2:7946"} },
		missing: func() []remergeTarget {
			var out []remergeTarget
			for n := range f.missing {
				out = append(out, remergeTarget{Name: n, Addr: addr[n]})
			}
			slices.SortFunc(out, func(a, b remergeTarget) int {
				if a.Name < b.Name {
					return -1
				}
				return 1
			})
			return out
		},
		join: func(ts []string) (int, error) {
			f.dials = append(f.dials, slices.Clone(ts))
			n := 0
			for _, a := range ts {
				if f.answers[name[a]] {
					delete(f.missing, name[a])
					n++
				}
			}
			if n < len(ts) {
				return n, errors.New("i/o timeout")
			}
			return n, nil
		},
	}
}

// With peers visible, the loop dials the missing hosts — and only them, never
// the seeds.
func TestRejoiner_RemergeDialsOnlyTheMissingHosts(t *testing.T) {
	f := &remergeFixture{missing: map[string]bool{"node-3": true, "node-4": true}, answers: map[string]bool{"node-3": true, "node-4": true}}
	r := f.rejoiner()

	if attempted, _, _ := r.tick(); attempted {
		t.Fatal("the isolated path dialled while peers were visible")
	}
	res := r.remerge()

	if len(f.dials) != 1 {
		t.Fatalf("dial calls = %v, want one pass", f.dials)
	}
	if want := []string{"10.0.0.3", "10.0.0.4"}; !slices.Equal(f.dials[0], want) {
		t.Fatalf("dialled %v, want only the missing hosts %v — not the seeds", f.dials[0], want)
	}
	if want := []string{"node-3", "node-4"}; !slices.Equal(res.recovered, want) {
		t.Errorf("recovered = %v, want %v", res.recovered, want)
	}
	if len(res.missing) != 0 {
		t.Errorf("still missing = %v, want none", res.missing)
	}
}

// Nothing missing, nothing dialled: the steady state costs zero dials.
func TestRejoiner_RemergeDialsNothingWhenNothingIsMissing(t *testing.T) {
	f := &remergeFixture{missing: map[string]bool{}}
	r := f.rejoiner()
	for i := 0; i < 10; i++ {
		r.remerge()
	}
	if len(f.dials) != 0 {
		t.Fatalf("dialled %v on a cluster where every listed host is visible", f.dials)
	}
}

// A host that is dead but not removed is dialled on a backoff, capped, so it
// costs at most one dial every remergeMaxSkip+1 passes — while a host that goes
// missing later is dialled at once, not held behind the dead one's backoff.
func TestRejoiner_RemergeBacksOffAPermanentlyMissingHost(t *testing.T) {
	f := &remergeFixture{missing: map[string]bool{"node-5": true}, answers: map[string]bool{}}
	r := f.rejoiner()

	var dialledAt []int
	const passes = 40
	for i := 0; i < passes; i++ {
		before := len(f.dials)
		r.remerge()
		if len(f.dials) > before {
			dialledAt = append(dialledAt, i)
		}
	}
	if len(dialledAt) == 0 || dialledAt[0] != 0 {
		t.Fatalf("dialled at passes %v; a newly missing host must be dialled on the first pass", dialledAt)
	}
	if len(dialledAt) < 2 || dialledAt[1] != 2 {
		t.Errorf("dialled at passes %v; the first retry should come after one skipped pass", dialledAt)
	}
	for i := 1; i < len(dialledAt); i++ {
		if gap := dialledAt[i] - dialledAt[i-1]; gap > remergeMaxSkip+1 {
			t.Fatalf("dialled at passes %v; gap %d exceeds the cap of %d — a healed partition must not wait longer",
				dialledAt, gap, remergeMaxSkip+1)
		}
	}
	if max := passes/(remergeMaxSkip+1) + 2; len(dialledAt) > max {
		t.Fatalf("dialled %d times in %d passes (at %v); a dead host must back off to one dial per %d passes",
			len(dialledAt), passes, dialledAt, remergeMaxSkip+1)
	}

	// node-6 drops out while node-5 is backed off: it is dialled on the very
	// next pass, alone if node-5 is not due.
	f.missing["node-6"] = true
	f.answers["node-6"] = true
	before := len(f.dials)
	res := r.remerge()
	if len(f.dials) != before+1 || !slices.Contains(f.dials[len(f.dials)-1], "10.0.0.6") {
		t.Fatalf("a newly missing host was not dialled on the next pass: dials %v", f.dials[before:])
	}
	if !slices.Contains(res.recovered, "node-6") {
		t.Errorf("recovered = %v, want node-6", res.recovered)
	}
}

// A host that comes back is forgotten: if it drops out again it is dialled at
// once, not from where its old backoff left off.
func TestRejoiner_RemergeBackoffResetsWhenAHostReturns(t *testing.T) {
	f := &remergeFixture{missing: map[string]bool{"node-5": true}, answers: map[string]bool{}}
	r := f.rejoiner()
	for i := 0; i < 12; i++ {
		r.remerge() // deep into node-5's backoff
	}
	// It comes back on its own (the other side dialled us).
	delete(f.missing, "node-5")
	r.remerge()
	if len(r.backoff) != 0 {
		t.Fatalf("backoff = %v after node-5 returned; a visible host keeps no backoff", r.backoff)
	}
	f.missing["node-5"] = true
	before := len(f.dials)
	r.remerge()
	if len(f.dials) != before+1 {
		t.Fatal("a host that dropped out again was held behind its previous episode's backoff")
	}
}

// Re-merging is not isolation. A node that sees peers but misses some of the
// listed hosts must not mark its replica stale or raise gossip_isolated on
// every pass: a permanently dead, unremoved host would hold every node of the
// cluster stale forever.
func TestMembershipTick_RemergeIsNotIsolation(t *testing.T) {
	c := isolationClient(t)
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	f := &remergeFixture{missing: map[string]bool{"node-5": true}, answers: map[string]bool{}}
	r := f.rejoiner()

	c.membershipTick(context.Background(), r, reporter(c))
	c.membershipTick(context.Background(), r, reporter(c))

	if len(f.dials) == 0 {
		t.Fatal("membershipTick never re-merged a missing host while peers were visible")
	}
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		t.Fatal("a re-merge pass marked the replica stale; only seeing NO peers does that")
	}
	if _, ok := isolationRow(t, c); ok {
		t.Fatal("a re-merge pass raised gossip_isolated; the node sees peers")
	}
}

// The isolated path is unchanged: with nobody visible it dials the seeds and
// the hosts table, and does not ALSO run a re-merge pass on top.
func TestMembershipTick_IsolatedPathDoesNotAlsoRemerge(t *testing.T) {
	c := isolationClient(t)
	r := isolatedRejoiner()
	remerged := 0
	r.missing = func() []remergeTarget { remerged++; return []remergeTarget{{Name: "node-9", Addr: "10.0.0.9"}} }
	c.membershipTick(context.Background(), r, reporter(c))
	if remerged != 0 {
		t.Fatal("an isolated pass also ran the re-merge pass; the isolated path already dials every target")
	}
}
