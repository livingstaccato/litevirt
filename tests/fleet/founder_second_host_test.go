// Fleet scenario: the first host of a cluster adds its second.
//
// Found on a real lab bootstrap (integrate/fixes-2026-10-10 = 2bddcdee7). A
// founder never completes an anti-entropy exchange: it has nobody to exchange
// with, so its replica is never "caught up", and every gate that needs one lets
// it through only because it is alone. `lv host add` asks AdmitHost twice: once
// before it installs anything, and again right before the install (6c258cb4e).
// The first ask writes the new host's joining row, and on the second the
// founder no longer counted as alone. The re-ask was refused Unavailable
// ("cannot vouch for node-1's audit history"), and so was `lv host rm` of the
// half-admitted host: the founder could neither finish the add nor undo it.
//
// Nothing here marks a replica caught up (Options.RealCatchUp). The founder
// is wired as the daemon wires it: the operator's hosts-write currency check
// is on, and it has an anti-entropy puller.
package fleet

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// newFounder is a one-node cluster founded the real way: its replica is not
// caught up, its daemon's write-currency check is on, and its anti-entropy
// loop runs (RealCatchUp).
func newFounder(t *testing.T, seed int64) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 1, IndependentReplicas: true, RealCatchUp: true, FaultSeed: seed})
	f := c.Nodes[0]
	f.Server.SetHostWriteCurrencyCheck(true)
	if ok, _ := f.DB.ReplicaCaughtUp(); ok {
		t.Fatal("fixture: the founder's replica starts caught up; nothing a real founder does marks it so")
	}
	if len(f.DB.Members()) != 0 {
		t.Fatalf("fixture: the founder has gossip peers: %v", f.DB.Members())
	}
	return c, f
}

// newMachine is a machine `lv host add` has not reached yet: an address of
// its own, a port reserved for its daemon, and an empty pki directory.
func newMachine(t *testing.T, c *Cluster, name, addr string) *Node {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Skipf("needs %s bound on loopback: %v", addr, err)
	}
	m := &Node{
		Name:          name,
		Region:        "default",
		Address:       addr,
		PKIDir:        filepath.Join(c.tmpRoot, name, "pki"),
		Listener:      l,
		Port:          l.Addr().(*net.TCPAddr).Port,
		blockedFrom:   make(map[string]bool),
		unimplemented: make(map[string]bool),
		streamWatches: make(map[string][]*StreamWatch),
		unaryHooks:    make(map[string][]UnaryHook),
		streamHooks:   make(map[string][]StreamHook),
		cluster:       c,
	}
	if err := mkdirAll(m.PKIDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if m.DB == nil {
			_ = m.Listener.Close()
		}
	})
	return m
}

// bootAdded starts the daemon `lv host add` set up on m: an empty database
// that knows the founder's row (its join_peers), gossip between the two, its
// registration and boot write.
func bootAdded(t *testing.T, c *Cluster, m, founder *Node, serial string) {
	t.Helper()
	ctx := context.Background()
	db, err := corrosion.NewSharedTestClient(c.dbName("added-"+m.Name), m.Name)
	if err != nil {
		t.Fatalf("open %s's database: %v", m.Name, err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema for %s: %v", m.Name, err)
	}
	m.DB = db
	rows, err := founder.DB.Query(ctx, `SELECT * FROM hosts WHERE name != ?`, m.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(r.Columns)), ", ")
		if _, err := db.DB().Exec(`INSERT INTO hosts (`+strings.Join(r.Columns, ", ")+`) VALUES (`+marks+`)`,
			r.Values...); err != nil {
			t.Fatalf("seed the founder's row on %s: %v", m.Name, err)
		}
	}
	peer := func(n *Node) func() []corrosion.PeerInfo {
		return func() []corrosion.PeerInfo {
			return []corrosion.PeerInfo{{Name: n.Name, Addr: net.JoinHostPort(n.Address, "7946")}}
		}
	}
	// In the cluster before anything can dial it: nothing reaches the
	// founder until it sees m, so c.Nodes is not read concurrently here.
	c.Nodes = append(c.Nodes, m)
	db.SetMembersForTests(peer(founder))
	founder.DB.SetMembersForTests(peer(m))
	c.buildServer(m)
	m.repl.SetProofReplicaGate(func(context.Context, string) bool { return true })
	m.repl.Start(c.ctx)
	m.replStarted = true
	bootRebuiltNode(t, m, serial)
}

func fakeBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := os.WriteFile(bin, []byte("build"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestFleet_FounderAddsItsSecondHost: `lv host add` against a founder that
// has never had a peer admits the new host, asks again before the install,
// installs it, and the new host's daemon comes up active on both nodes.
//
// Mutation: drop the joining-subject exception from the alone test
// (grpcapi.clusterOfOneBut), and the re-ask is refused "cannot vouch".
func TestFleet_FounderAddsItsSecondHost(t *testing.T) {
	ctx := context.Background()
	c, founder := newFounder(t, 5101)
	operatorPKICopy(t, founder)
	m := newMachine(t, c, "node-1", "127.0.0.2")

	target := &cli.LocalAddTarget{Root: t.TempDir(), PKIDir: m.PKIDir, Binary: fakeBinary(t)}
	t.Cleanup(cli.UseMachinesForTests(filepath.Join(t.TempDir(), "no-daemon-config.yaml"),
		map[string]*cli.LocalAddTarget{m.Address: target}))
	if err := cli.HostAddOn(ctx, c.SelfClient(founder), target, m.Name, m.Address); err != nil {
		t.Fatalf("lv host add %s against the founder: %v", m.Name, err)
	}
	serial, err := pki.CertSerial(filepath.Join(m.PKIDir, "host.crt"))
	if err != nil {
		t.Fatalf("the add installed no certificate on %s: %v", m.Name, err)
	}
	h, err := corrosion.GetHost(ctx, founder.DB, m.Name)
	if err != nil || h == nil || h.State != corrosion.HostStateJoining || !strings.EqualFold(h.CertSerial, serial) {
		t.Fatalf("the founder's row of %s = %+v (%v), want joining with %s", m.Name, h, err, serial)
	}

	fleetAdmittedPort(t, m, serial, founder)
	bootAdded(t, c, m, founder, serial)
	for _, n := range []*Node{founder, m} {
		eventually(t, convergeTimeout, n.Name+" to read "+m.Name+" active", func() bool {
			h, err := corrosion.GetHost(ctx, n.DB, m.Name)
			return err == nil && h != nil && h.State == "active" && strings.EqualFold(h.CertSerial, serial)
		})
	}
	// Each replica catches up by its own anti-entropy loop, which the
	// harness runs as the daemon does (Options.RealCatchUp), and with it the
	// founder's lease mint, which held while node-1 was joining, may ask.
	for _, n := range []*Node{founder, m} {
		eventually(t, convergeTimeout, n.Name+"'s replica to catch up with its peer", func() bool {
			ok, _ := n.DB.ReplicaCaughtUp()
			return ok
		})
	}
	if ok, why := founder.Server.LeaseMintClearance(ctx, corrosion.LeaseMintRequest{
		Key: "failover", Term: 1 << 40, Holder: founder.Name, Takeover: true}); !ok &&
		strings.Contains(why, "not caught up") {
		t.Errorf("the founder's lease mint still waits for a catch-up once %s has booted: %s", m.Name, why)
	}
}

// TestFleet_FounderRemovesAHalfAdmittedHost: an add whose setup fails leaves
// the host admitted (joining) on a founder that has never had a peer. The
// exception that lets the founder vouch for its own joiner covers that joiner
// and its admission only; `lv host rm` then removes it.
func TestFleet_FounderRemovesAHalfAdmittedHost(t *testing.T) {
	ctx := context.Background()
	c, founder := newFounder(t, 5102)
	operatorPKICopy(t, founder)
	m := newMachine(t, c, "node-1", "127.0.0.2")
	cl := c.SelfClient(founder)

	setupFailed := errors.New("setup failed (fleet)")
	target := &cli.LocalAddTarget{Root: t.TempDir(), PKIDir: m.PKIDir, Binary: fakeBinary(t), FailSetup: setupFailed}
	t.Cleanup(cli.UseMachinesForTests(filepath.Join(t.TempDir(), "no-daemon-config.yaml"),
		map[string]*cli.LocalAddTarget{m.Address: target}))
	if err := cli.HostAddOn(ctx, cl, target, m.Name, m.Address); err == nil {
		t.Fatal("an add whose setup fails succeeded")
	}
	h, err := corrosion.GetHost(ctx, founder.DB, m.Name)
	if err != nil || h == nil || h.State != corrosion.HostStateJoining {
		t.Fatalf("the founder's row of %s = %+v (%v), want joining", m.Name, h, err)
	}
	serial := h.CertSerial

	refused := func(t *testing.T, what string, req *pb.AdmitHostRequest) {
		t.Helper()
		_, err := cl.AdmitHost(ctx, req)
		if err == nil || !strings.Contains(err.Error(), "cannot vouch") {
			t.Fatalf("%s = %v, want refused: the founder cannot vouch for it", what, err)
		}
	}
	t.Run("another name is not vouched for", func(t *testing.T) {
		refused(t, "AdmitHost of node-2 beside the joining "+m.Name,
			&pb.AdmitHostRequest{Name: "node-2", Address: "127.0.0.3", CertSerial: "0a0b0c0d0e"})
	})
	t.Run("another name with this admission's serial is not vouched for", func(t *testing.T) {
		refused(t, "AdmitHost of node-2 with "+m.Name+"'s serial",
			&pb.AdmitHostRequest{Name: "node-2", Address: "127.0.0.3", CertSerial: serial})
	})
	t.Run("another admission of the name is not vouched for", func(t *testing.T) {
		refused(t, "AdmitHost of "+m.Name+" with another serial",
			&pb.AdmitHostRequest{Name: m.Name, Address: m.Address, CertSerial: "0a0b0c0d0e"})
	})
	t.Run("a gossip peer ends the exception", func(t *testing.T) {
		founder.DB.SetMembersForTests(func() []corrosion.PeerInfo {
			return []corrosion.PeerInfo{{Name: "node-9", Addr: "127.0.0.9:7946"}}
		})
		defer founder.DB.SetMembersForTests(func() []corrosion.PeerInfo { return nil })
		refused(t, "the re-ask of "+m.Name+"'s own admission with a gossip peer",
			&pb.AdmitHostRequest{Name: m.Name, Address: m.Address, CertSerial: serial})
	})
	t.Run("a host whose daemon has booted is not vouched for", func(t *testing.T) {
		// Its boot write has reached the founder and its daemon is gone from
		// gossip: it may have written what the founder lacks.
		if err := corrosion.UpdateHostState(ctx, founder.DB, m.Name, "active"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := corrosion.UpdateHostState(ctx, founder.DB, m.Name, corrosion.HostStateJoining); err != nil {
				t.Fatal(err)
			}
		}()
		refused(t, "AdmitHost of the booted "+m.Name+" with its own serial",
			&pb.AdmitHostRequest{Name: m.Name, Address: m.Address, CertSerial: serial})
	})
	// The hosts-write side: the exception covers writes to the joining host
	// itself and nothing else.
	notCaughtUp := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "has not caught up") {
			t.Fatalf("%s = %v, want refused: the founder has not caught up", what, err)
		}
		if h, gerr := corrosion.GetHost(ctx, founder.DB, m.Name); gerr != nil || h == nil {
			t.Fatalf("a refused %s removed %s's row: %+v, %v", what, m.Name, h, gerr)
		}
	}
	t.Run("a write to the founder's own row is not let through", func(t *testing.T) {
		_, err := cl.SetHostLabels(ctx, &pb.SetHostLabelsRequest{Name: founder.Name, Labels: map[string]string{"rack": "r1"}})
		notCaughtUp(t, "label "+founder.Name, err)
	})
	t.Run("rm with a gossip peer is not let through", func(t *testing.T) {
		founder.DB.SetMembersForTests(func() []corrosion.PeerInfo {
			return []corrosion.PeerInfo{{Name: "node-9", Addr: "127.0.0.9:7946"}}
		})
		defer founder.DB.SetMembersForTests(func() []corrosion.PeerInfo { return nil })
		notCaughtUp(t, "lv host rm "+m.Name+" with a gossip peer", cli.HostRemove(ctx, cl, m.Name, false))
	})
	t.Run("rm of a host whose daemon has booted is not let through", func(t *testing.T) {
		if err := corrosion.UpdateHostState(ctx, founder.DB, m.Name, "active"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := corrosion.UpdateHostState(ctx, founder.DB, m.Name, corrosion.HostStateJoining); err != nil {
				t.Fatal(err)
			}
		}()
		notCaughtUp(t, "lv host rm of the booted "+m.Name, cli.HostRemove(ctx, cl, m.Name, false))
	})
	t.Run("the re-ask of the standing admission is vouched for", func(t *testing.T) {
		if _, err := cl.AdmitHost(ctx, &pb.AdmitHostRequest{Name: m.Name, Address: m.Address, CertSerial: serial}); err != nil {
			t.Fatalf("the re-ask of %s's own admission: %v", m.Name, err)
		}
	})

	if err := cli.HostRemove(ctx, cl, m.Name, false); err != nil {
		t.Fatalf("lv host rm of the half-admitted %s: %v", m.Name, err)
	}
	if h, err := corrosion.GetHost(ctx, founder.DB, m.Name); err != nil || h != nil {
		t.Fatalf("after lv host rm, the founder's row of %s = %+v (%v), want none", m.Name, h, err)
	}
}
