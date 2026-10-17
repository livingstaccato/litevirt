// Fleet scenarios for the host incarnation counter (corrosion/host_incarnation.go):
// a host removed while it was down and re-added while its data directory still
// held its old database converges on the re-admission, whatever order its
// writes and anti-entropy take and however close its first admission was.
// Test numbers are the design's (eqts-report.md, section 7).
package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// incFleet is a latched three-node fleet whose gates see every peer healthy,
// so a re-admission can count its voter majority.
func incFleet(t *testing.T, seed int64) (*Cluster, map[string]*health.Checker) {
	t.Helper()
	c, gates := latchedFleet(t, 3, seed)
	latchReleaseToken(t, c, gates)
	seedIncPeers(c, gates)
	return c, gates
}

func seedIncPeers(c *Cluster, gates map[string]*health.Checker) {
	for _, n := range c.Nodes {
		peers := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
}

// setIncMembers is every node's gossip membership with absent left out: a
// crashed node leaves memberlist, and a node that cannot be reached is no
// replication recipient.
func setIncMembers(c *Cluster, absent ...*Node) {
	out := map[string]bool{}
	for _, n := range absent {
		out[n.Name] = true
	}
	nodes := append([]*Node(nil), c.Nodes...)
	for _, target := range nodes {
		self := target.Name
		target.DB.SetMembersForTests(func() []corrosion.PeerInfo {
			var peers []corrosion.PeerInfo
			for _, n := range nodes {
				if n.Name == self || out[n.Name] {
					continue
				}
				peers = append(peers, corrosion.PeerInfo{Name: n.Name, Addr: n.Address + ":7946"})
			}
			return peers
		})
	}
}

// others is c's nodes without d.
func others(c *Cluster, d *Node) []*Node {
	var out []*Node
	for _, n := range c.Nodes {
		if n != d {
			out = append(out, n)
		}
	}
	return out
}

// rewireIncNode re-installs n's release gate and checker on the server a
// restart rebuilt.
func rewireIncNode(c *Cluster, gates map[string]*health.Checker, n *Node) {
	g := gates[n.Name]
	g.SetPeerPinger(n.Server.PeerCapabilities)
	g.SetReleaseUseConfirmer(n.Server.PeerHoldsReleaseFeatureUse)
	n.Server.SetReleaseFeatureGate(g)
	n.Server.SetGate(g)
	n.DB.SetReplicationSourceGate(n.Server.ReleaseSourceAllowed)
}

// convergeAll runs anti-entropy everywhere until no table is apart.
func convergeAll(t *testing.T, c *Cluster, what string, d *Node) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(2 * convergeTimeout)
	for {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		apart, err := divergence(c.Nodes)
		if err != nil {
			t.Fatalf("divergence: %v", err)
		}
		if len(apart) == 0 {
			return
		}
		if time.Now().After(deadline) {
			for _, n := range c.Nodes {
				t.Logf("%s holds %s as %v", n.Name, d.Name, hostsRowOf(t, n, d.Name))
			}
			t.Fatalf("%s: tables still apart: %v", what, apart)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ownRowBoot is d's daemon starting on its database, as daemon.go does: the
// own-row hold first, then registration and the boot report. Returns the
// hold's state.
func ownRowBoot(t *testing.T, d *Node, serial string) corrosion.OwnRowHoldStatus {
	t.Helper()
	ctx := context.Background()
	st, err := d.DB.ConfigureOwnRowHold(ctx, serial)
	if err != nil {
		t.Fatal(err)
	}
	rerr := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort",
	})
	berr := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-boot", 24, 48, 96, true)
	if st.Held {
		if !errors.Is(rerr, corrosion.ErrOwnRowHeld) || !errors.Is(berr, corrosion.ErrOwnRowHeld) {
			t.Fatalf("%s wrote its own row while held: register %v, boot %v", d.Name, rerr, berr)
		}
	} else if rerr != nil || berr != nil {
		t.Fatalf("%s boot: register %v, boot %v", d.Name, rerr, berr)
	}
	return st
}

// ownRowReconcile is the daemon's reconcile once the hold opens (own_row.go):
// registration, the address and port at a counted incarnation, the boot report.
func ownRowReconcile(t *testing.T, d *Node, serial string) {
	t.Helper()
	ctx := context.Background()
	eventually(t, convergeTimeout, d.Name+"'s own-row hold to open", func() bool {
		corrosion.NewAntiEntropy(d.DB, d.PKIDir, 0).RunOnce(ctx)
		st, err := d.DB.EvaluateOwnRowHold(ctx, corrosion.OwnRowHeldSuperseded)
		return err == nil && !st.Held
	})
	if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
		Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
		State: "active", CertSerial: serial, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("reconcile: register: %v", err)
	}
	if n, _, _, _, _, err := corrosion.HostIncarnationOf(ctx, d.DB, d.Name); err == nil && n >= 1 {
		if err := corrosion.WriteOwnEndpoint(ctx, d.DB, d.Name, d.Address, d.Port,
			capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
			t.Fatalf("reconcile: endpoint: %v", err)
		}
	}
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-boot", 24, 48, 96, true); err != nil {
		t.Fatalf("reconcile: boot report: %v", err)
	}
}

// Test 19: no created_at backdate — the stale database's row is inside the old
// rule's five minutes, where it used to tie (WAL first) or come back on every
// node (anti-entropy first). Both orders, with and without the split copies.
func TestFleet_HostIncarnation_StaleDBReadd(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		retired, aeFirst, noHold bool
		seed                     int64
	}{
		{name: "dual-write", seed: 3671},
		{name: "both copies retired", retired: true, seed: 3672},
		{name: "dual-write, anti-entropy first", aeFirst: true, seed: 3673},
		{name: "both copies retired, anti-entropy first", retired: true, aeFirst: true, seed: 3674},
		// d without the own-row hold (a daemon whose hold timed out, or an
		// older one): it writes on its stale base, and only the counter keeps
		// those writes, and its stale row, off the survivors.
		{name: "no hold", noHold: true, seed: 3675},
		{name: "no hold, anti-entropy first", noHold: true, aeFirst: true, seed: 3676},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, gates := incFleet(t, tc.seed)
			d := c.Nodes[2]
			incStaleCycle(t, c, gates, d, c.Nodes[0], tc.retired, tc.aeFirst, tc.noHold, 1)
			// Test 20: a second cycle, removed at incarnation 1 and re-added on
			// another node, with d back on its database from the first cycle.
			incStaleCycle(t, c, gates, d, c.Nodes[1], false, tc.aeFirst, tc.noHold, 2)
		})
	}
}

// incStaleCycle configures d, crashes it, removes it and re-adds it on
// admitter while it hears nothing, boots it on its old database, and checks
// that every node converges on the re-admission at incarnation want.
func incStaleCycle(t *testing.T, c *Cluster, gates map[string]*health.Checker, d, admitter *Node, retired, aeFirst, noHold bool, want int64) {
	t.Helper()
	ctx := context.Background()
	var survivors []*Node
	for _, n := range c.Nodes {
		if n != d {
			survivors = append(survivors, n)
		}
	}
	if retired {
		for _, n := range c.Nodes {
			retireMembership(t, n)
			retireRuntime(t, n)
		}
		c.WaitConverged(t, convergeTimeout)
	}
	// The old machine's per-host settings, which the re-admission resets.
	if err := corrosion.SetHostLabel(ctx, admitter.DB, d.Name, "gpu", "a100"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostRegion(ctx, admitter.DB, d.Name, "rack-a"); err != nil {
		t.Fatal(err)
	}
	ratio := 4.0
	if _, err := c.SelfClient(admitter).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: d.Name, CpuOvercommit: &ratio, WatchdogDev: "/dev/watchdog0",
	}); err != nil {
		t.Fatalf("configure %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)

	c.Crash(d)
	setIncMembers(c, d)
	if _, err := c.SelfClient(admitter).RemoveHost(ctx, &pb.RemoveHostRequest{Name: d.Name, Force: true}); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the removal on every survivor", func() bool {
		for _, n := range survivors {
			if h, err := corrosion.GetHost(ctx, n.DB, d.Name); err != nil || h != nil {
				return false
			}
		}
		return true
	})
	serial := restartWithNewCert(t, c, d)
	rewireIncNode(c, gates, d)
	if aeFirst {
		// Admitted at the port d serves on, so the survivors can dial it.
		if _, _, err := corrosion.AdmitHostV2(ctx, admitter.DB, corrosion.HostRecord{
			Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
			State: corrosion.HostStateJoining, CertSerial: serial,
		}, capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
			t.Fatalf("admit %s again: %v", d.Name, err)
		}
	} else if _, err := c.SelfClient(admitter).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: serial,
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the admission on every survivor", func() bool {
		for _, n := range survivors {
			h, err := corrosion.GetHost(ctx, n.DB, d.Name)
			if err != nil || h == nil || h.CertSerial != serial {
				return false
			}
		}
		return true
	})
	if n, _, _, _, _, _ := corrosion.HostIncarnationOf(ctx, admitter.DB, d.Name); n != want {
		t.Fatalf("the re-admission issued incarnation %d, want %d", n, want)
	}

	// d's daemon starts on its old database, before it has heard anything.
	if noHold {
		if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{
			Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
			State: "active", CertSerial: serial, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("register %s: %v", d.Name, err)
		}
		if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v-stale-db", 24, 48, 96, true); err != nil {
			t.Fatalf("boot report of %s: %v", d.Name, err)
		}
	} else if st := ownRowBoot(t, d, serial); !st.Held {
		t.Fatalf("%s booted on its old database without the own-row hold: %+v", d.Name, st)
	}
	setIncMembers(c)
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	if aeFirst {
		// The survivors pull d's whole row before anything else moves.
		for _, n := range survivors {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		for _, n := range survivors {
			if got := hostsRowOf(t, n, d.Name); got["region"] != "default" || got["watchdog_dev"] != "NULL" {
				t.Errorf("%s took %s's stale row over the re-admission: %v", n.Name, d.Name, got)
			}
		}
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	if noHold {
		// The daemon's own-row hook re-runs its writes once its row moves
		// to the re-admission's incarnation (own_row.go).
		eventually(t, convergeTimeout, d.Name+" to adopt the re-admission", func() bool {
			corrosion.NewAntiEntropy(d.DB, d.PKIDir, 0).RunOnce(ctx)
			n, _, _, _, _, err := corrosion.HostIncarnationOf(ctx, d.DB, d.Name)
			return err == nil && n == want
		})
	}
	ownRowReconcile(t, d, serial)
	convergeAll(t, c, d.Name+" booted on its old database", d)

	ref := hostsRowOf(t, admitter, d.Name)
	for _, n := range c.Nodes {
		got := hostsRowOf(t, n, d.Name)
		if fmt.Sprint(got) != fmt.Sprint(ref) {
			t.Errorf("%s's hosts row for %s differs from %s's:\n %v\n %v", n.Name, d.Name, admitter.Name, got, ref)
		}
		if got["labels"] != "NULL" || got["region"] != "default" || got["grpc_port"] != fmt.Sprint(d.Port) ||
			got["cpu_overcommit"] != "0" || got["watchdog_dev"] != "NULL" || got["cert_serial"] != serial ||
			got["deleted_at"] != "NULL" || got["incarnation"] != fmt.Sprint(want) {
			t.Errorf("%s holds %s's row as %v; want the re-admission's at incarnation %d with %s's own port %d",
				n.Name, d.Name, got, want, d.Name, d.Port)
		}
		h, err := corrosion.GetHost(ctx, n.DB, d.Name)
		if err != nil || h == nil {
			t.Fatalf("%s: %s is not a member: %+v %v", n.Name, d.Name, h, err)
		}
		if h.State != "active" || h.FenceStrategy != "best-effort" || h.IPMIPass != "" || h.WatchdogDev != "" {
			t.Errorf("%s reads %s as state %q fence %q watchdog %q", n.Name, d.Name, h.State, h.FenceStrategy, h.WatchdogDev)
		}
		if k := n.DB.UnresolvedTieCount(); k != 0 {
			t.Errorf("%s tracks %d unresolved tie(s)", n.Name, k)
		}
	}
}

// Test 22 (I4, R-M4): a host re-added on an EMPTY database, its clock behind
// the admitter's, serving on a non-default port. Its insert at incarnation 0
// is refused; it adopts the re-admission and records its own port.
func TestFleet_HostIncarnation_EmptyDBReadd(t *testing.T) {
	ctx := context.Background()
	c, gates := incFleet(t, 3680)
	a, d := c.Nodes[0], c.Nodes[2]
	c.Crash(d)
	setIncMembers(c, d)
	if _, err := c.SelfClient(a).RemoveHost(ctx, &pb.RemoveHostRequest{Name: d.Name, Force: true}); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, others(c, d)...)
	serial := restartWithNewCert(t, c, d)
	rewireIncNode(c, gates, d)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{Name: d.Name, Address: d.Address, CertSerial: serial}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	// An empty database, as far as d's own row goes.
	if _, err := d.DB.DB().Exec(`DELETE FROM hosts WHERE name = ?`, d.Name); err != nil {
		t.Fatal(err)
	}
	if st := ownRowBoot(t, d, serial); st.Held {
		t.Fatalf("an empty database held: %+v", st)
	}
	setIncMembers(c)
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	eventually(t, convergeTimeout, d.Name+" to adopt the re-admission", func() bool {
		corrosion.NewAntiEntropy(d.DB, d.PKIDir, 0).RunOnce(ctx)
		n, _, _, _, _, err := corrosion.HostIncarnationOf(ctx, d.DB, d.Name)
		return err == nil && n == 1
	})
	ownRowReconcile(t, d, serial)
	convergeAll(t, c, "an empty-database re-add", d)
	for _, n := range c.Nodes {
		got := hostsRowOf(t, n, d.Name)
		if got["grpc_port"] != fmt.Sprint(d.Port) || got["incarnation"] != "1" || got["deleted_at"] != "NULL" {
			t.Errorf("%s holds %s as %v; want incarnation 1 at its own port %d", n.Name, d.Name, got, d.Port)
		}
		if h, _ := corrosion.GetHost(ctx, n.DB, d.Name); h == nil || h.State == "fenced" || h.State == "offline" {
			t.Errorf("%s reads %s as %+v", n.Name, d.Name, h)
		}
	}
}

// Test 23 (I1, R-I1) and 29: duplicate admissions. In a partition only the
// majority side can re-add; inside one connected majority two admissions at
// the same number converge on the later stamp, and the loser's machine, whose
// hold had already opened, is held again.
func TestFleet_HostIncarnation_DuplicateAdmissions(t *testing.T) {
	ctx := context.Background()
	c, gates := latchedFleet(t, 5, 3690)
	latchReleaseToken(t, c, gates)
	seedIncPeers(c, gates)
	a, b, x, y, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	c.Crash(d)
	setIncMembers(c, d)
	if _, err := c.SelfClient(a).RemoveHost(ctx, &pb.RemoveHostRequest{Name: d.Name, Force: true}); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, others(c, d)...)

	// Partitioned: y alone is a minority. Its gate sees no peer.
	cutOff := map[string]bool{}
	for _, o := range c.Nodes {
		if o != y {
			cutOff[o.Name] = false
		}
	}
	gates[y.Name].SeedPeersForTests(cutOff)
	_, err := c.SelfClient(y).AdmitHost(ctx, &pb.AdmitHostRequest{Name: d.Name, Address: d.Address, CertSerial: "77aa"})
	if err == nil || !containsAll(err.Error(), "voter") {
		t.Errorf("a minority-side re-add = %v, want the quorum refusal", err)
	}
	seedIncPeers(c, gates)

	// Connected race: two admissions at 1, delivered in opposite orders.
	serial := restartWithNewCert(t, c, d)
	rewireIncNode(c, gates, d)
	h := func(s string) corrosion.HostRecord {
		return corrosion.HostRecord{Name: d.Name, Address: d.Address, SSHUser: "root", SSHPort: 22, GRPCPort: d.Port,
			State: corrosion.HostStateJoining, CertSerial: s}
	}
	for _, o := range []*Node{a, x} {
		c.Partition(b, o)
	}
	if _, _, err := corrosion.AdmitHostV2(ctx, b.DB, h("88bb"), capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, _, err := corrosion.AdmitHostV2(ctx, a.DB, h(serial), capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
		t.Fatal(err)
	}
	// d's daemon starts on its old database.
	if st := ownRowBoot(t, d, serial); !st.Held {
		t.Fatalf("not held: %+v", st)
	}
	setIncMembers(c)
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	for _, o := range []*Node{a, x} {
		c.Heal(b, o)
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	ownRowReconcile(t, d, serial)
	convergeAll(t, c, "two admissions at one number", d)
	for _, n := range c.Nodes {
		got := hostsRowOf(t, n, d.Name)
		if got["cert_serial"] != serial || got["incarnation"] != "1" {
			t.Errorf("%s holds %s as %v; want the later admission (serial %s) at 1", n.Name, d.Name, got, serial)
		}
		if k := n.DB.UnresolvedTieCount(); k != 0 {
			t.Errorf("%s tracks %d unresolved tie(s)", n.Name, k)
		}
	}

	// Test 29: an admission at 2 under another serial supersedes d's while
	// d runs with its hold open; d re-holds and its writes stop.
	if st := d.DB.OwnRowHold(); st.Held {
		t.Fatalf("d held before the supersession: %+v", st)
	}
	fired := make(chan struct{}, 8)
	d.DB.SetOwnRowChangeHook(func() {
		d.DB.EvaluateOwnRowHold(ctx, corrosion.OwnRowHeldSuperseded)
		select {
		case fired <- struct{}{}:
		default:
		}
	})
	if err := corrosion.DeleteHost(ctx, a.DB, d.Name); err != nil {
		t.Fatal(err)
	}
	if _, _, err := corrosion.AdmitHostV2(ctx, a.DB, h("99cc"), capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, d.Name+" to be held as superseded", func() bool {
		st := d.DB.OwnRowHold()
		return st.Held && st.Reason == corrosion.OwnRowHeldSuperseded
	})
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "v", 1, 2, 3, true); !errors.Is(err, corrosion.ErrOwnRowHeld) {
		t.Errorf("a superseded host's own-row write = %v, want ErrOwnRowHeld", err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// Test 24 (I5): a hold whose admission never reaches the host times out,
// reports so, and the host's fallback is refused by a cluster that holds a
// later incarnation; once the admission arrives the host converges.
func TestFleet_HostIncarnation_HoldTimesOut(t *testing.T) {
	ctx := context.Background()
	old := corrosion.OwnRowHoldTimeout
	corrosion.OwnRowHoldTimeout = 300 * time.Millisecond
	t.Cleanup(func() { corrosion.OwnRowHoldTimeout = old })
	c, gates := incFleet(t, 3700)
	a, d := c.Nodes[0], c.Nodes[2]
	c.Crash(d)
	setIncMembers(c, d)
	if _, err := c.SelfClient(a).RemoveHost(ctx, &pb.RemoveHostRequest{Name: d.Name, Force: true}); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, others(c, d)...)
	serial := restartWithNewCert(t, c, d)
	rewireIncNode(c, gates, d)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{Name: d.Name, Address: d.Address, CertSerial: serial}); err != nil {
		t.Fatal(err)
	}
	if st := ownRowBoot(t, d, serial); !st.Held {
		t.Fatalf("not held: %+v", st)
	}
	time.Sleep(400 * time.Millisecond)
	if st := d.DB.OwnRowHold(); !st.Held || !st.TimedOut {
		t.Fatalf("hold = %+v, want timed out", st)
	}
	// The fallback writes on the stale base; the cluster refuses them.
	if err := corrosion.RegisterHost(ctx, d.DB, corrosion.HostRecord{Name: d.Name, Address: d.Address, SSHUser: "root",
		SSHPort: 22, GRPCPort: d.Port, State: "active", CertSerial: serial}); err != nil {
		t.Fatalf("fallback register: %v", err)
	}
	setIncMembers(c)
	for _, o := range c.Nodes {
		if o != d {
			c.SetLinkFaultBoth(d, o, LinkFault{})
		}
	}
	d.repl.Start(c.ctx)
	d.replStarted = true
	ownRowReconcile(t, d, serial)
	convergeAll(t, c, "after a timed-out hold", d)
	for _, n := range c.Nodes {
		if got := hostsRowOf(t, n, d.Name); got["incarnation"] != "1" || got["cert_serial"] != serial {
			t.Errorf("%s holds %s as %v", n.Name, d.Name, got)
		}
	}
}

// Test 25: before the latch, the legacy statements only, and the token-free
// hold closes both orders with no created_at backdate when d runs this build.
func TestFleet_HostIncarnation_BeforeTheLatch(t *testing.T) {
	for _, aeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("anti-entropy first=", aeFirst), func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 3710})
			a, d := c.Nodes[0], c.Nodes[2]
			c.WaitConverged(t, convergeTimeout)
			if err := corrosion.UpdateHostRegion(ctx, a.DB, d.Name, "rack-a"); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout)
			c.Crash(d)
			setIncMembers(c, d)
			if err := corrosion.DeleteHost(ctx, a.DB, d.Name); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout, others(c, d)...)
			serial := restartWithNewCert(t, c, d)
			port := 7443
			if aeFirst {
				port = d.Port
			}
			if err := corrosion.AdmitHost(ctx, a.DB, corrosion.HostRecord{Name: d.Name, Address: d.Address, SSHUser: "root",
				SSHPort: 22, GRPCPort: port, State: corrosion.HostStateJoining, CertSerial: serial}); err != nil {
				t.Fatal(err)
			}
			for _, n := range c.Nodes {
				if j := incMutationLog(t, n); strings.Contains(j, "incarnation = ?") || strings.Contains(j, "HostIncarnation") {
					t.Errorf("%s logged an incarnation statement before the latch", n.Name)
				}
			}
			c.WaitConverged(t, convergeTimeout, others(c, d)...)
			if st := ownRowBoot(t, d, serial); !st.Held {
				t.Fatalf("not held: %+v", st)
			}
			setIncMembers(c)
			for _, o := range c.Nodes {
				if o != d {
					c.SetLinkFaultBoth(d, o, LinkFault{})
				}
			}
			if aeFirst {
				for _, n := range c.Nodes[:2] {
					corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
					if got := hostsRowOf(t, n, d.Name); got["region"] != "default" {
						t.Errorf("%s took %s's stale row before the latch: %v", n.Name, d.Name, got)
					}
				}
			}
			d.repl.Start(c.ctx)
			d.replStarted = true
			ownRowReconcile(t, d, serial)
			convergeAll(t, c, "before the latch", d)
			for _, n := range c.Nodes {
				got := hostsRowOf(t, n, d.Name)
				if got["region"] != "default" || got["cert_serial"] != serial || got["incarnation"] != "0" {
					t.Errorf("%s holds %s as %v", n.Name, d.Name, got)
				}
				if k := n.DB.UnresolvedTieCount(); k != 0 {
					t.Errorf("%s tracks %d unresolved tie(s)", n.Name, k)
				}
			}
		})
	}
}

func incMutationLog(t *testing.T, n *Node) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	var s string
	for _, r := range rows {
		s += r.String("stmts") + "\n"
	}
	return s
}
