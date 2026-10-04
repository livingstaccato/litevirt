package corrosion

import (
	"context"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/litevirt/litevirt/internal/hlc"
)

// admissionClient is a gossip-less client named self whose hosts table holds
// the given rows (name → address). It stands in for one node's replica.
func admissionClient(t *testing.T, self string, rows map[string]string) *Client {
	t.Helper()
	c := NewTestClientT(t)
	c.hostName = self
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for name, addr := range rows {
		admitRow(t, c, name, addr)
	}
	return c
}

func admitRow(t *testing.T, c *Client, name, addr string) {
	t.Helper()
	if err := InsertHost(context.Background(), c, HostRecord{
		Name: name, Address: addr, SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "ab" + name, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("insert host %s: %v", name, err)
	}
}

func tombstone(t *testing.T, c *Client, name string) {
	t.Helper()
	if err := c.Execute(context.Background(),
		`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		"2026-09-01T00:00:00Z", c.NowTS(), name); err != nil {
		t.Fatalf("tombstone %s: %v", name, err)
	}
}

func node(name, ip string) *memberlist.Node {
	return &memberlist.Node{Name: name, Addr: net.ParseIP(ip), Port: 7946}
}

func memberNames(ps []PeerInfo) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

// TestGossipAdmission_Delegates pins the four verdicts of the one predicate, as
// memberlist's AliveDelegate sees them. Every alive message — a join, a
// push/pull merge, a refutation — reaches the node map through NotifyAlive, so
// this is the gate a phantom has to get past.
func TestGossipAdmission_Delegates(t *testing.T) {
	c := admissionClient(t, "node-a", map[string]string{
		"node-a":  "10.0.0.1",
		"node-b":  "10.0.0.2",
		"witness": "10.0.0.9",
		"gone":    "10.0.0.7",
	})
	tombstone(t, c, "gone")
	// A witness in maintenance is still a host of this cluster: admission is
	// "known and not removed", not "votes".
	if err := c.Execute(context.Background(),
		`UPDATE hosts SET role = 'witness', state = 'maintenance' WHERE name = 'witness'`); err != nil {
		t.Fatal(err)
	}
	d := &admissionDelegate{client: c}

	cases := []struct {
		name, ip string
		admit    bool
		why      string
	}{
		{"node-a", "10.0.0.1", true, "self"},
		{"node-b", "10.0.0.2", true, "known host at its recorded address"},
		{"witness", "10.0.0.9", true, "known witness in maintenance"},
		{"phantom", "10.0.0.66", false, "a name with no hosts row"},
		{"node-b", "10.0.0.66", false, "a known name at an address that is not its own"},
		{"gone", "10.0.0.7", false, "a removed host, even at its old address"},
	}
	for _, tc := range cases {
		err := d.NotifyAlive(node(tc.name, tc.ip))
		if (err == nil) != tc.admit {
			t.Errorf("%s (%s@%s): admitted=%v, want %v (err %v)", tc.why, tc.name, tc.ip, err == nil, tc.admit, err)
		}
	}
}

// TestGossipAdmission_MergeRefusesAJoinThatBringsNobody: a join whose state
// names no admissible member is someone else's cluster (or a phantom joining
// this one) and is refused whole. One that names any admissible member merges,
// and NotifyAlive then drops the rest one by one.
func TestGossipAdmission_MergeRefusesAJoinThatBringsNobody(t *testing.T) {
	c := admissionClient(t, "node-a", map[string]string{"node-a": "10.0.0.1", "node-b": "10.0.0.2"})
	d := &admissionDelegate{client: c}

	if err := d.NotifyMerge([]*memberlist.Node{node("phantom", "10.0.0.66"), node("node-b", "10.0.0.99")}); err == nil {
		t.Error("a join offering only a phantom and an impersonator was merged")
	} else if !strings.Contains(err.Error(), "phantom") {
		t.Errorf("refusal should name the refused members, got %v", err)
	}
	if err := d.NotifyMerge([]*memberlist.Node{node("node-b", "10.0.0.2"), node("phantom", "10.0.0.66")}); err != nil {
		t.Errorf("a join from a known host was refused: %v", err)
	}
}

// TestGossipAdmission_BootstrapTrustsSeedsOnlyUntilTheClusterIsKnown is the
// bootstrap case. A node `lv host add` just started holds nothing but its own
// row — often not even that, since the first join runs before registration —
// so it can learn the cluster only from what its seeds introduce. Once it holds
// any other host's row, that trust ends. A node with no seeds (a founder) never
// had it.
func TestGossipAdmission_BootstrapTrustsSeedsOnlyUntilTheClusterIsKnown(t *testing.T) {
	joiner := admissionClient(t, "node-new", map[string]string{"node-new": "10.0.0.5"})
	joiner.gossipSeeded = true
	d := &admissionDelegate{client: joiner}
	if err := d.NotifyAlive(node("node-a", "10.0.0.1")); err != nil {
		t.Fatalf("a seeded node that knows no other host refused the cluster it is joining: %v", err)
	}

	admitRow(t, joiner, "node-a", "10.0.0.1")
	if err := d.NotifyAlive(node("phantom", "10.0.0.66")); err == nil {
		t.Error("a node that has learned the cluster still admits unknown names")
	}

	// A tombstone is knowledge of the cluster too: the last survivor of a
	// removal is not a fresh node.
	survivor := admissionClient(t, "node-a", map[string]string{"node-a": "10.0.0.1", "node-b": "10.0.0.2"})
	survivor.gossipSeeded = true
	tombstone(t, survivor, "node-b")
	if err := (&admissionDelegate{client: survivor}).NotifyAlive(node("phantom", "10.0.0.66")); err == nil {
		t.Error("a node whose only peer was removed admits unknown names as if it were new")
	}

	founder := admissionClient(t, "node-a", map[string]string{"node-a": "10.0.0.1"})
	if err := (&admissionDelegate{client: founder}).NotifyAlive(node("phantom", "10.0.0.66")); err == nil {
		t.Error("a single-node founder with no seeds admits an unknown name")
	}
}

// TestGossipAdmission_SeedTrustLastsUntilItsAddressIsLearned: kvm003 drill 6.
// A newcomer whose first foreign row came from ANOTHER newcomer still admits
// the hosts at its seeds' addresses, because nothing else can ever bring their
// rows: their history is pruned from every push backlog, and anti-entropy
// dials admitted members only. That trust is per address, and ends for an
// address the moment any row here records it.
func TestGossipAdmission_SeedTrustLastsUntilItsAddressIsLearned(t *testing.T) {
	joiner := admissionClient(t, "node-5", map[string]string{
		"node-5": "10.0.0.5",
		"node-4": "10.0.0.4", // the other newcomer's boot row, pushed first
	})
	joiner.gossipSeeded = true
	joiner.gossipSeedIPs = seedIPs([]string{"10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.7:7946"})
	d := &admissionDelegate{client: joiner}

	if err := d.NotifyAlive(node("node-1", "10.0.0.1")); err != nil {
		t.Fatalf("the newcomer refused the established host at its seed's address: %v", err)
	}
	if err := d.NotifyAlive(node("phantom", "10.0.0.66")); err == nil {
		t.Error("a newcomer that knows a host admits an unknown name at an address that is not a seed")
	}

	// node-1's row arrives (anti-entropy from node-1 itself): from now on the
	// row is the authority for 10.0.0.1, and another name there is a phantom.
	admitRow(t, joiner, "node-1", "10.0.0.1")
	if err := d.NotifyAlive(node("node-1", "10.0.0.1")); err != nil {
		t.Fatalf("node-1 was refused once its row arrived: %v", err)
	}
	if err := d.NotifyAlive(node("aa-phantom", "10.0.0.1")); err == nil {
		t.Error("an unknown name at a seed address this node has learned was admitted")
	}

	// A tombstone records its address too: a seed that was removed is known,
	// and is not trusted again under some other name.
	admitRow(t, joiner, "gone", "10.0.0.7")
	tombstone(t, joiner, "gone")
	if err := d.NotifyAlive(node("other", "10.0.0.7")); err == nil {
		t.Error("an unknown name at a removed seed's address was admitted")
	}

	// A node with no seeds has no seed trust, whatever it was handed.
	unseeded := admissionClient(t, "node-5", map[string]string{"node-5": "10.0.0.5", "node-4": "10.0.0.4"})
	unseeded.gossipSeedIPs = seedIPs([]string{"10.0.0.1:7946"})
	if err := (&admissionDelegate{client: unseeded}).NotifyAlive(node("node-1", "10.0.0.1")); err == nil {
		t.Error("an unseeded node admitted an unknown name")
	}
}

func TestSeedIPs_ParsesAddressForms(t *testing.T) {
	got := seedIPs([]string{"10.0.0.1:7946", "10.0.0.2", "not a host name at all:7946"})
	if !got["10.0.0.1"] || !got["10.0.0.2"] || len(got) != 2 {
		t.Fatalf("seedIPs = %v, want exactly 10.0.0.1 and 10.0.0.2", got)
	}
}

// TestGossipAdmission_RefusalIsPerAttempt: the join race. A host whose row has
// not replicated here yet is refused, and nothing about that refusal sticks —
// the first exchange after its row lands admits it.
func TestGossipAdmission_RefusalIsPerAttempt(t *testing.T) {
	c := admissionClient(t, "node-a", map[string]string{"node-a": "10.0.0.1", "node-b": "10.0.0.2"})
	d := &admissionDelegate{client: c}
	if err := d.NotifyAlive(node("node-new", "10.0.0.5")); err == nil {
		t.Fatal("a host with no row was admitted")
	}
	admitRow(t, c, "node-new", "10.0.0.5")
	if err := d.NotifyAlive(node("node-new", "10.0.0.5")); err != nil {
		t.Fatalf("the host was still refused after its row arrived: %v", err)
	}
}

// TestMembers_FiltersOnTheAdmissionPredicate: Members() is what replication,
// anti-entropy, relay election and capability activation count, and a member
// admitted before its row went away (bootstrap trust, or a later removal) must
// drop out of all of them at once.
func TestMembers_FiltersOnTheAdmissionPredicate(t *testing.T) {
	c := admissionClient(t, "node-a", map[string]string{
		"node-a": "10.0.0.1", "node-b": "10.0.0.2", "node-c": "10.0.0.3", "gone": "10.0.0.7",
	})
	tombstone(t, c, "gone")
	c.SetGossipForTests(func() []PeerInfo {
		return []PeerInfo{
			{Name: "node-b", Addr: "10.0.0.2:7946"},
			{Name: "node-c", Addr: "10.0.0.3:7946"},
			{Name: "aaa-phantom", Addr: "10.0.0.66:7946"},
			{Name: "node-c", Addr: "10.0.0.99:7946"},
			{Name: "gone", Addr: "10.0.0.7:7946"},
		}
	})
	got := memberNames(c.Members())
	if strings.Join(got, ",") != "node-b,node-c" {
		t.Fatalf("Members() = %v, want only the admitted [node-b node-c]", got)
	}
}

// TestRelays_PhantomsDoNotInflateNOrR: relay election is name-ordered, so a
// phantom named to sort first would otherwise both raise R and take a relay
// slot. It must not change the election at all.
func TestRelays_PhantomsDoNotInflateNOrR(t *testing.T) {
	c := admissionClient(t, "node-a", map[string]string{
		"node-a": "10.0.0.1", "node-b": "10.0.0.2", "node-c": "10.0.0.3",
	})
	honest := []PeerInfo{{Name: "node-b", Addr: "10.0.0.2:7946"}, {Name: "node-c", Addr: "10.0.0.3:7946"}}
	phantoms := append([]PeerInfo{}, honest...)
	for _, n := range []string{"aa-1", "aa-2", "aa-3", "aa-4", "aa-5", "aa-6"} {
		phantoms = append(phantoms, PeerInfo{Name: n, Addr: "10.0.0.66:7946"})
	}
	c.SetGossipForTests(func() []PeerInfo { return phantoms })

	want := ComputeRelays(honest, "node-a", RelayConfig{}, nil)
	got := ComputeRelays(c.Members(), "node-a", RelayConfig{}, nil)
	if strings.Join(got.Relays(), ",") != strings.Join(want.Relays(), ",") {
		t.Fatalf("phantoms changed the relay set: got %v, want %v", got.Relays(), want.Relays())
	}
	if len(got.Relays()) != len(want.Relays()) {
		t.Fatalf("phantoms changed R: got %d, want %d", len(got.Relays()), len(want.Relays()))
	}
}

// TestGossip_SingleNodeFounderAdmitsItself: the AliveDelegate also sees the
// node's OWN alive message, at memberlist.Create, before the schema exists. A
// fresh single-node cluster must come up as a member of itself.
func TestGossip_SingleNodeFounderAdmitsItself(t *testing.T) {
	a := newGossipClient(t, "node-a", "127.0.0.1", "127.0.0.1", freePort(t), nil)
	if n := a.list.NumMembers(); n != 1 {
		t.Fatalf("founder memberlist has %d members, want exactly itself", n)
	}
	if a.list.LocalNode().Name != "node-a" {
		t.Fatalf("local node is %q", a.list.LocalNode().Name)
	}
}

// TestGossip_JoinRaceIsAdmittedOnTheNextExchange drives the real memberlist.
// node-a already knows its cluster; node-new joins before its row has
// replicated to node-a, and is refused. Its row then arrives, and the next
// periodic push/pull — no re-join, no restart — admits it.
func TestGossip_JoinRaceIsAdmittedOnTheNextExchange(t *testing.T) {
	portA, portN := freePort(t), freePort(t)
	a := newGossipClientWith(t, Config{
		HostName: "node-a", BindAddr: "127.0.0.1", AdvertiseAddr: "127.0.0.1", BindPort: portA,
		pushPullInterval: 200 * time.Millisecond,
	})
	if err := InitSchema(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	admitRow(t, a, "node-a", "127.0.0.1")
	admitRow(t, a, "node-b", "127.0.0.2") // node-a knows its cluster: no bootstrap trust

	n := newGossipClientWith(t, Config{
		HostName: "node-new", BindAddr: "127.0.0.1", AdvertiseAddr: "127.0.0.1", BindPort: portN,
		JoinPeers:        []string{net.JoinHostPort("127.0.0.1", itoa(portA))},
		pushPullInterval: 200 * time.Millisecond,
	})

	// The joiner, knowing nobody, trusted its seed.
	waitFor(t, 5*time.Second, "node-new to see node-a", func() bool { return len(n.Members()) == 1 })

	// node-a refused it, and keeps refusing it while the row is absent.
	time.Sleep(time.Second)
	if a.list.NumMembers() != 1 {
		t.Fatalf("node-a admitted a host with no hosts row: %d members", a.list.NumMembers())
	}

	admitRow(t, a, "node-new", "127.0.0.1")
	waitFor(t, 5*time.Second, "node-a to admit node-new once its row arrived", func() bool {
		return strings.Join(memberNames(a.Members()), ",") == "node-new"
	})
}

func newGossipClientWith(t *testing.T, cfg Config) *Client {
	t.Helper()
	cfg.DataDir = t.TempDir()
	c, err := NewClient(cfg, hlc.NewClock(cfg.HostName))
	if err != nil {
		t.Fatalf("NewClient %s: %v", cfg.HostName, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
