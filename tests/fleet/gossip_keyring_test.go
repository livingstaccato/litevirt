// Fleet scenarios: gossip encryption rolled on, rotated, and enforced across a
// real multi-node memberlist (colonelpanik/litevirt#259, step 2).
//
// The shared harness (cluster.go) SEEDS membership rather than gossiping it, so
// it structurally cannot reach memberlist's encryption. These scenarios run
// their own small fleet instead: one real corrosion client per node, each with
// its own data dir and PKI dir, binding 0.0.0.0 and advertising 127.0.0.1 — so
// memberlist auto-detection cannot produce the configured answer by accident —
// with each node's daemon-side key watcher running. A "restart" is what the
// daemon does: close the client and open a new one on the same port and data
// dir with the new stage, reading the key from the PKI dir.
//
// The failure mode is multi-node by construction: a stage change or a key
// change is only safe relative to what every OTHER node is doing at that
// moment, so a single-node test cannot see it.
package fleet

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/pki"
)

type gossipNode struct {
	name, dataDir, pkiDir string
	port                  int
	reload                time.Duration

	mu         sync.Mutex
	c          *corrosion.Client
	stopWatch  context.CancelFunc
	restarting atomic.Bool
}

func (n *gossipNode) client() *corrosion.Client {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.c
}

type gossipFleet struct {
	t     *testing.T
	nodes []*gossipNode
	names []string // every name with a hosts row, intruders included
}

func freeGossipPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenPacket("udp", "0.0.0.0:"+strconv.Itoa(port))
		l.Close()
		if err == nil {
			u.Close()
			return port
		}
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

func newGossipFleet(t *testing.T, n int, extraNames ...string) *gossipFleet {
	t.Helper()
	f := &gossipFleet{t: t}
	for i := 0; i < n; i++ {
		f.nodes = append(f.nodes, &gossipNode{
			name: fmt.Sprintf("gk-%d", i+1), dataDir: t.TempDir(), pkiDir: t.TempDir(),
			port: freeGossipPort(t), reload: 50 * time.Millisecond,
		})
		f.names = append(f.names, f.nodes[i].name)
	}
	f.names = append(f.names, extraNames...)
	t.Cleanup(func() {
		for _, nd := range f.nodes {
			f.stop(nd)
		}
	})
	return f
}

func (f *gossipFleet) seeds(except *gossipNode) []string {
	var out []string
	for _, nd := range f.nodes {
		if nd != except {
			out = append(out, net.JoinHostPort("127.0.0.1", strconv.Itoa(nd.port)))
		}
	}
	return out
}

// start opens nd at stage mode, loading its key file the way the daemon does
// (gossipKeysFor): not at all when off, and a hard failure when a keyed stage
// has no usable key.
func (f *gossipFleet) start(nd *gossipNode, mode corrosion.GossipEncryption) {
	t := f.t
	t.Helper()
	var keys corrosion.GossipKeys
	if mode != corrosion.GossipEncryptionOff {
		ring, err := pki.LoadGossipKeyring(filepath.Join(nd.pkiDir, pki.GossipKeyName))
		if err != nil {
			t.Fatalf("%s: stage %v with no usable key: %v", nd.name, mode, err)
		}
		keys = ring
	}
	var c *corrosion.Client
	var err error
	// A just-closed node's port can linger for a moment; the daemon would be
	// restarted by systemd into the same port, so retry rather than move.
	for i := 0; i < 50; i++ {
		c, err = corrosion.NewClient(corrosion.Config{
			HostName: nd.name, DataDir: nd.dataDir, BindAddr: "0.0.0.0", AdvertiseAddr: "127.0.0.1",
			BindPort: nd.port, JoinPeers: f.seeds(nd), GossipEncryption: mode, GossipKeys: keys,
		}, hlc.NewClock(nd.name))
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("start %s at %v: %v", nd.name, mode, err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, name := range f.names {
		if h, _ := corrosion.GetHost(ctx, c, name); h != nil {
			continue
		}
		if err := corrosion.InsertHost(ctx, c, corrosion.HostRecord{
			Name: name, Address: "127.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
			State: "active", CertSerial: "ab" + name, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("%s: insert host %s: %v", nd.name, name, err)
		}
	}
	wctx, cancel := context.WithCancel(context.Background())
	go c.WatchGossipKeyFile(wctx,
		filepath.Join(nd.pkiDir, pki.GossipKeyName),
		filepath.Join(nd.pkiDir, pki.GossipKeyringStateName), nd.reload)
	nd.mu.Lock()
	nd.c, nd.stopWatch = c, cancel
	nd.mu.Unlock()
}

func (f *gossipFleet) stop(nd *gossipNode) {
	nd.mu.Lock()
	c, cancel := nd.c, nd.stopWatch
	nd.c, nd.stopWatch = nil, nil
	nd.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c != nil {
		c.Close()
	}
}

// restart is one step of a rolling restart: nd leaves, comes back at mode, and
// must be back in every peer's membership — and every peer in its — within the
// bound. A stage its peers cannot talk to never gets there.
func (f *gossipFleet) restart(nd *gossipNode, mode corrosion.GossipEncryption) {
	f.t.Helper()
	nd.restarting.Store(true)
	f.stop(nd)
	f.start(nd, mode)
	f.waitConverged(15*time.Second, fmt.Sprintf("%s to rejoin at stage %v", nd.name, mode))
	nd.restarting.Store(false)
}

func sees(c *corrosion.Client, name string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.Members() {
		if p.Name == name {
			return true
		}
	}
	return false
}

// converged: every node sees every other node.
func (f *gossipFleet) converged() bool {
	for _, a := range f.nodes {
		for _, b := range f.nodes {
			if a != b && !sees(a.client(), b.name) {
				return false
			}
		}
	}
	return true
}

func (f *gossipFleet) waitConverged(d time.Duration, what string) {
	f.t.Helper()
	deadline := time.Now().Add(d)
	for !f.converged() {
		if time.Now().After(deadline) {
			var views []string
			for _, nd := range f.nodes {
				var ms []string
				if c := nd.client(); c != nil {
					for _, p := range c.Members() {
						ms = append(ms, p.Name)
					}
				}
				views = append(views, fmt.Sprintf("%s sees %v", nd.name, ms))
			}
			f.t.Fatalf("timed out waiting for %s:\n  %s", what, strings.Join(views, "\n  "))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// watchMembership samples, until the returned stop is called, whether every
// pair of nodes that are both up (neither mid-restart) still see each other,
// and records every loss. "Membership never lost" is this list staying empty.
func (f *gossipFleet) watchMembership() (stop func() []string) {
	var mu sync.Mutex
	var lost []string
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case <-time.After(25 * time.Millisecond):
			}
			for _, a := range f.nodes {
				for _, b := range f.nodes {
					if a == b || a.restarting.Load() || b.restarting.Load() {
						continue
					}
					if c := a.client(); c != nil && !sees(c, b.name) && !a.restarting.Load() && !b.restarting.Load() {
						mu.Lock()
						lost = append(lost, fmt.Sprintf("%s lost %s", a.name, b.name))
						mu.Unlock()
					}
				}
			}
		}
	}()
	return func() []string {
		close(done)
		<-finished
		mu.Lock()
		defer mu.Unlock()
		return lost
	}
}

func (f *gossipFleet) rejections() map[string]uint64 {
	out := map[string]uint64{}
	for _, nd := range f.nodes {
		if c := nd.client(); c != nil {
			out[nd.name] = c.GossipAuthRejections()
		}
	}
	return out
}

func (f *gossipFleet) installKey(ring [][]byte) {
	for _, nd := range f.nodes {
		if err := pki.WriteGossipKeyring(filepath.Join(nd.pkiDir, pki.GossipKeyName), ring); err != nil {
			f.t.Fatal(err)
		}
	}
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// rolloutStages is the documented operator sequence for an existing cluster:
// one rolling restart per stage, each finished on every node before the next.
var rolloutStages = []corrosion.GossipEncryption{
	corrosion.GossipEncryptionInstall,
	corrosion.GossipEncryptionStaged,
	corrosion.GossipEncryptionEnforced,
}

// TestGossipKeyring_RollingEnableNeverLosesMembership walks a live 4-node
// plaintext cluster through the documented sequence — install the key, then
// one rolling restart per stage — and requires that no two running nodes ever
// lose each other, that every restarted node rejoins, and that no node drops a
// single gossip message on encryption grounds along the way. It then checks the
// point of the exercise: a node holding a hosts row but not the key cannot join.
func TestGossipKeyring_RollingEnableNeverLosesMembership(t *testing.T) {
	f := newGossipFleet(t, 4, "gk-intruder")
	for _, nd := range f.nodes {
		f.start(nd, corrosion.GossipEncryptionOff)
	}
	f.waitConverged(10*time.Second, "the plaintext cluster to form")

	key, err := pki.NewGossipKey()
	if err != nil {
		t.Fatal(err)
	}
	f.installKey([][]byte{key}) // lv host install-gossip-key: nothing changes on the wire

	stop := f.watchMembership()
	for _, stage := range rolloutStages {
		for _, nd := range f.nodes {
			f.restart(nd, stage)
		}
	}
	if lost := stop(); len(lost) > 0 {
		t.Fatalf("membership was lost during the rolling enable:\n  %s", strings.Join(dedupe(lost), "\n  "))
	}
	for name, n := range f.rejections() {
		if n != 0 {
			t.Errorf("%s dropped %d gossip messages on encryption grounds during a correct rollout", name, n)
		}
	}
	for _, nd := range f.nodes {
		waitGossipState(t, nd, func(s pki.GossipKeyringState) bool {
			return s.Mode == "enforced" && s.Primary == pki.GossipKeyID(key)
		})
	}

	// Enforced: an intruder with a hosts row on every node, but no key, is
	// refused — at every sample, not just eventually.
	intruder := &gossipNode{name: "gk-intruder", dataDir: t.TempDir(), pkiDir: t.TempDir(),
		port: freeGossipPort(t), reload: time.Second}
	f.start(intruder, corrosion.GossipEncryptionOff)
	defer f.stop(intruder)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		for _, nd := range f.nodes {
			if sees(nd.client(), "gk-intruder") {
				t.Fatalf("%s admitted a node without the gossip key into an enforced cluster", nd.name)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !f.converged() {
		t.Fatal("the enforced cluster lost membership while refusing the intruder")
	}
}

func waitGossipState(t *testing.T, nd *gossipNode, ok func(pki.GossipKeyringState) bool) {
	t.Helper()
	path := filepath.Join(nd.pkiDir, pki.GossipKeyringStateName)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(path); err == nil {
			if s, err := pki.ParseGossipKeyringState(b); err == nil && ok(s) {
				return
			}
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(path)
			t.Fatalf("%s: state file never matched; last:\n%s", nd.name, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fleetKeyHost is cli.GossipKeyHost over a fleet node's PKI dir: what
// `lv host rotate-gossip-key` does over SSH, minus the SSH.
type fleetKeyHost struct{ nd *gossipNode }

func (h fleetKeyHost) Name() string { return h.nd.name }

func (h fleetKeyHost) ReadKeyFile(context.Context) ([]byte, bool, error) {
	b, err := os.ReadFile(filepath.Join(h.nd.pkiDir, pki.GossipKeyName))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (h fleetKeyHost) WriteKeyFile(_ context.Context, data []byte) error {
	ring, err := pki.ParseGossipKeyring(data)
	if err != nil {
		return err
	}
	return pki.WriteGossipKeyring(filepath.Join(h.nd.pkiDir, pki.GossipKeyName), ring)
}

func (h fleetKeyHost) LiveKeyring(context.Context) (pki.GossipKeyringState, bool, error) {
	b, err := os.ReadFile(filepath.Join(h.nd.pkiDir, pki.GossipKeyringStateName))
	if os.IsNotExist(err) {
		return pki.GossipKeyringState{}, false, nil
	}
	if err != nil {
		return pki.GossipKeyringState{}, false, err
	}
	s, err := pki.ParseGossipKeyringState(b)
	return s, err == nil, err
}

// TestGossipKeyring_RotationKeepsMembership runs the real rotate command's
// logic against a live enforced 4-node cluster whose key watchers reload at
// very different rates — one node takes over a second to notice a new file —
// and requires that no pair ever loses the other and no node ever drops a
// message for want of a key. Collapsing the phases (new key primary before
// every node holds it) drops messages at the slow node, and fails this.
func TestGossipKeyring_RotationKeepsMembership(t *testing.T) {
	f := newGossipFleet(t, 4)
	f.nodes[2].reload = 1200 * time.Millisecond
	key, err := pki.NewGossipKey()
	if err != nil {
		t.Fatal(err)
	}
	f.installKey([][]byte{key})
	for _, nd := range f.nodes {
		f.start(nd, corrosion.GossipEncryptionEnforced)
	}
	f.waitConverged(10*time.Second, "the enforced cluster to form")

	local := filepath.Join(t.TempDir(), pki.GossipKeyName)
	if err := pki.WriteGossipKeyring(local, [][]byte{key}); err != nil {
		t.Fatal(err)
	}
	var hosts []cli.GossipKeyHost
	for _, nd := range f.nodes {
		hosts = append(hosts, fleetKeyHost{nd})
	}

	stop := f.watchMembership()
	var out strings.Builder
	err = cli.RotateGossipKey(context.Background(), local, hosts, cli.GossipKeyOptions{
		Out: &out, Grace: 500 * time.Millisecond, Timeout: 20 * time.Second, Poll: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, out.String())
	}
	// Past the slowest reload, so anything a late node dropped is counted.
	time.Sleep(2 * time.Second)
	if lost := stop(); len(lost) > 0 {
		t.Fatalf("membership was lost during rotation:\n  %s", strings.Join(dedupe(lost), "\n  "))
	}
	for name, n := range f.rejections() {
		if n != 0 {
			t.Errorf("%s dropped %d gossip messages under a key it did not hold during rotation", name, n)
		}
	}
	ring, err := pki.LoadGossipKeyring(local)
	if err != nil || len(ring) != 1 || pki.GossipKeyID(ring[0]) == pki.GossipKeyID(key) {
		t.Fatalf("local key after rotation: %v, %v", pki.GossipKeyIDs(ring), err)
	}
	for _, nd := range f.nodes {
		if s := nd.client().GossipKeyring(); s.Primary != pki.GossipKeyID(ring[0]) || len(s.Keys) != 1 {
			t.Fatalf("%s ended on %+v, want only %s", nd.name, s, pki.GossipKeyID(ring[0]))
		}
	}
	if !f.converged() {
		t.Fatal("not converged after rotation")
	}
}
