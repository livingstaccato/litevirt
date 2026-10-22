// Fleet scenarios for managed fence SSH (internal/fencessh): real daemons'
// release gates latching release_2026_12_v1 over real Pings, each host's
// signed host_fence_ssh row travelling over real replication, and every
// host's agent verifying its peers' rows against the cluster CA and the CRL
// and rendering them into its authorized_keys and known_hosts.
package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/health"
)

// fenceSSHNode is one node's agent and the files it renders.
type fenceSSHNode struct {
	n     *Node
	agent *fencessh.Agent
	dir   string
	ip    string
}

// fenceSSHIP is node i's certificate address.
func fenceSSHIP(i int) string { return fmt.Sprintf("10.77.0.%d", i+1) }

// fenceSSHFleet is a latched fleet whose hosts' certificates name
// 10.77.0.<i+1>, with a fence ssh agent per node over its real database,
// PKI dir and release gate. Each node's sshd is modelled by one host key file
// and an sshd evaluation that accepts.
func fenceSSHFleet(t *testing.T, nodes int, seed int64) (*Cluster, map[string]*fenceSSHNode) {
	c, fs, _ := fenceSSHFleetGates(t, nodes, seed)
	return c, fs
}

// seedQuorum gives every node's checker a fresh view of every other node as
// live, as the HA monitor's probes would (nothing probes in the fleet).
func seedQuorum(c *Cluster, gates map[string]*health.Checker, live ...*Node) {
	for _, n := range live {
		gates[n.Name].QuorumProof(context.Background())
		peers := map[string]bool{}
		for _, o := range live {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
}

func fenceSSHFleetGates(t *testing.T, nodes int, seed int64) (*Cluster, map[string]*fenceSSHNode, map[string]*health.Checker) {
	return fenceSSHFleetFull(t, nodes, seed, func(string) bool { return true }, func(string) string { return fencessh.ModeAuto })
}

// fenceSSHFleetWith is fenceSSHFleet whose node accepting(name) reports its
// sshd accepting the managed key, and whose agents run in mode(name).
func fenceSSHFleetWith(t *testing.T, nodes int, seed int64, accepting func(string) bool,
	mode func(string) string) (*Cluster, map[string]*fenceSSHNode) {
	c, fs, _ := fenceSSHFleetFull(t, nodes, seed, accepting, mode)
	return c, fs
}

func fenceSSHFleetFull(t *testing.T, nodes int, seed int64, accepting func(string) bool,
	mode func(string) string) (*Cluster, map[string]*fenceSSHNode, map[string]*health.Checker) {
	t.Helper()
	ips := make([]string, nodes)
	for i := range ips {
		ips[i] = fenceSSHIP(i)
	}
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true, FaultSeed: seed, HostCertIPs: ips})
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	c.WaitConverged(t, convergeTimeout)
	// The HA monitor drives every unlatched mandatory token in production;
	// here the scenario does, for the release token fence_ssh is under.
	for _, n := range c.Nodes {
		for _, tok := range []string{capabilities.FailoverScopeV1, capabilities.Release202612V1} {
			if !gates[n.Name].Enforced(context.Background(), tok) {
				t.Fatalf("%s: %s did not latch", n.Name, tok)
			}
		}
	}
	out := map[string]*fenceSSHNode{}
	for i, n := range c.Nodes {
		out[n.Name] = newFenceSSHNode(t, n, ips[i], accepting, mode)
	}
	return c, out, gates
}

// newFenceSSHNode is n's fence ssh agent over its real database, PKI dir and
// release gate, with one sshd host key file and an sshd evaluation that
// answers accepting(n).
func newFenceSSHNode(t *testing.T, n *Node, ip string, accepting func(string) bool, mode func(string) string) *fenceSSHNode {
	t.Helper()
	root := t.TempDir()
	hk := filepath.Join(root, "etc")
	if err := os.MkdirAll(hk, 0o755); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	if err := os.WriteFile(filepath.Join(hk, "ssh_host_ed25519_key.pub"), ssh.MarshalAuthorizedKey(sp), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "ssh")
	name := n.Name
	return &fenceSSHNode{n: n, dir: dir, ip: ip, agent: fencessh.New(fencessh.Config{
		Self: n.Name, PKIDir: n.PKIDir, DB: n.DB, Gate: n.Server, Dir: dir,
		HostKeyGlob: filepath.Join(hk, "ssh_host_*_key.pub"),
		Accepting: func(context.Context, []string) (bool, string, error) {
			if accepting(name) {
				return true, "", nil
			}
			return false, "sshd does not read the rendered authorized_keys (modelled)", nil
		},
		Mode:        func() string { return mode(name) },
		OnAccepting: n.Server.FenceSSHAccepting,
	})}
}

// syncAll runs every listed agent's Sync, failing on an error.
func syncAll(t *testing.T, nodes ...*fenceSSHNode) {
	t.Helper()
	for _, f := range nodes {
		if err := f.agent.Sync(context.Background()); err != nil {
			t.Fatalf("%s: fence ssh Sync: %v", f.n.Name, err)
		}
	}
}

// publishAndRender is every node publishing, the rows replicating, and
// every node rendering them.
func publishAndRender(t *testing.T, c *Cluster, fs map[string]*fenceSSHNode) {
	t.Helper()
	all := make([]*fenceSSHNode, 0, len(fs))
	for _, n := range c.Nodes {
		all = append(all, fs[n.Name])
	}
	syncAll(t, all...)
	c.WaitConverged(t, convergeTimeout)
	syncAll(t, all...)
}

// akLine is one rendered authorized_keys line.
type akLine struct{ host, from, key string }

// authorizedKeys parses f's rendered authorized_keys.
func (f *fenceSSHNode) authorizedKeys(t *testing.T) map[string]akLine {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, fencessh.AuthorizedKeysName))
	if err != nil {
		t.Fatalf("%s: %v", f.n.Name, err)
	}
	out := map[string]akLine{}
	for _, l := range strings.Split(string(raw), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			t.Fatalf("%s: bad line %q: %v", f.n.Name, l, err)
		}
		var from string
		restricted, command := false, false
		for _, o := range opts {
			switch {
			case o == "restrict":
				restricted = true
			case strings.HasPrefix(o, "from="):
				from = strings.Trim(strings.TrimPrefix(o, "from="), `"`)
			case strings.HasPrefix(o, "command="):
				command = strings.Trim(strings.TrimPrefix(o, "command="), `"`) == filepath.Join(f.dir, fencessh.CommandName)
			}
		}
		if !restricted || !command {
			t.Fatalf("%s: line %q is not restricted to the forced command", f.n.Name, l)
		}
		parts := strings.Split(comment, ":")
		if len(parts) < 2 {
			t.Fatalf("%s: line %q names no host", f.n.Name, l)
		}
		out[parts[1]] = akLine{host: parts[1], from: from, key: fencessh.KeyLine(pub)}
	}
	return out
}

// ownKey is f's own fence key line.
func (f *fenceSSHNode) ownKey(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, fencessh.KeyName+".pub"))
	if err != nil {
		t.Fatalf("%s: %v", f.n.Name, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return fencessh.KeyLine(pub)
}

// wantRendered fails unless every node in on renders exactly the peers in
// want (and never itself), each from its certificate address with its key.
func wantRendered(t *testing.T, fs map[string]*fenceSSHNode, on []string, want []string) {
	t.Helper()
	for _, name := range on {
		f := fs[name]
		got := f.authorizedKeys(t)
		var expect []string
		for _, p := range want {
			if p != name {
				expect = append(expect, p)
			}
		}
		if len(got) != len(expect) {
			t.Fatalf("%s renders %d peers %v, want %v", name, len(got), got, expect)
		}
		for _, p := range expect {
			l, ok := got[fencessh.HexName(p)]
			if !ok || l.from != fs[p].ip || l.key != fs[p].ownKey(t) {
				t.Fatalf("%s's line for %s = %+v, want from=%s and %s's own key", name, p, l, fs[p].ip, p)
			}
		}
		kh, err := os.ReadFile(filepath.Join(f.dir, fencessh.KnownHostsName))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range expect {
			if !strings.Contains(string(kh), fencessh.Alias(p)+" ") {
				t.Fatalf("%s's known_hosts does not pin %s:\n%s", name, p, kh)
			}
		}
		if strings.Contains(string(kh), fencessh.Alias(name)+" ") {
			t.Fatalf("%s pins itself", name)
		}
	}
}

// TestFleet_FenceSSH_PublishVerifyRender: once release_2026_12_v1 latches,
// every host publishes its signed row (marking fence_ssh used), the rows
// replicate, and every host renders exactly its peers' keys, each accepted
// only from that peer's certificate address and only to run the forced
// command, and pins each peer's sshd key. No host renders its own key.
//
// Mutation: render every row without verifying it (verifiedPeers) — the
// forged-row scenario below goes red; drop from= from AuthorizedKeys — red
// here.
func TestFleet_FenceSSH_PublishVerifyRender(t *testing.T) {
	c, fs := fenceSSHFleet(t, 3, 2612)
	publishAndRender(t, c, fs)
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.Release202612V1, string(capabilities.FeatureFenceSSH)) {
			t.Fatalf("%s: fence_ssh is not recorded used after every host published", n.Name)
		}
	}
	wantRendered(t, fs, names(c.Nodes), names(c.Nodes))
}

// TestFleet_FenceSSH_ForgedRowIsNotRendered: node-1 writes a row naming
// node-2 under its own certificate (a compromised node trying to get its key
// trusted as node-2's). No node renders the forged key; node-2's line is
// gone until node-2 republishes, and then it is back everywhere.
func TestFleet_FenceSSH_ForgedRowIsNotRendered(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleet(t, 3, 2613)
	publishAndRender(t, c, fs)
	n1, n2 := fs["node-1"], fs["node-2"]

	own, ok, err := corrosion.GetHostFenceSSH(ctx, n1.n.DB, "node-1")
	if err != nil || !ok {
		t.Fatalf("node-1's row: %v %v", ok, err)
	}
	forged := own
	forged.HostName = "node-2" // node-1's key and certificate, under node-2's name
	if err := corrosion.PutHostFenceSSH(ctx, n1.n.DB, capabilities.GrantForTest(t, capabilities.FeatureFenceSSH), forged); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	syncAll(t, fs["node-0"], n1)
	for _, name := range []string{"node-0", "node-1"} {
		got := fs[name].authorizedKeys(t)
		if l, ok := got[fencessh.HexName("node-2")]; ok {
			t.Fatalf("%s renders the forged row for node-2: %+v", name, l)
		}
	}
	// node-2 sees its row is not the one it signed, and republishes.
	syncAll(t, n2)
	c.WaitConverged(t, convergeTimeout)
	publishAndRender(t, c, fs)
	wantRendered(t, fs, names(c.Nodes), names(c.Nodes))
}
