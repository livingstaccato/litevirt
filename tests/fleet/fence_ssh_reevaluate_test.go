package fleet

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// reevalInstall runs `lv host install-fence-ssh` for every node against
// node via, with a freshness bound of freshAfter, under a ctx that ends after
// budget. It returns the error, the output and how long it took.
func reevalInstall(t *testing.T, c *Cluster, fs map[string]*fenceSSHNode, via *Node, freshAfter, budget time.Duration) (error, string, time.Duration) {
	t.Helper()
	all := map[string]string{}
	var hosts []cli.FenceSSHHost
	for _, n := range c.Nodes {
		all[n.Name] = fs[n.Name].ip
		hosts = append(hosts, installedFenceSSHHost{name: n.Name, addr: fs[n.Name].ip})
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var out bytes.Buffer
	start := time.Now()
	err := cli.InstallFenceSSH(ctx, c.SelfClient(via), hosts, all,
		cli.FenceSSHOptions{Out: &out, Wait: 2 * freshAfter, FreshAfter: freshAfter})
	return err, out.String(), time.Since(start)
}

// actAsOlderBuild makes n answer GetFenceSSHStatus as a build that predates
// reevaluate: the request reaches its handler without the field, and its
// answer carries no evaluated_for_request.
func actAsOlderBuild(n *Node) {
	for range 200 {
		n.HookUnary("GetFenceSSHStatus", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
			r := proto.Clone(req.(*pb.FenceSSHStatusRequest)).(*pb.FenceSSHStatusRequest)
			r.Reevaluate = false
			resp, err := handler(ctx, r)
			if st, ok := resp.(*pb.FenceSSHStatus); ok {
				for _, node := range st.GetNodes() {
					node.EvaluatedForRequest, node.ReevaluateOutcome = false, ""
				}
			}
			return resp, err
		})
	}
}

// TestFleet_FenceSSH_ReevaluateConfirmsInSeconds: node-2's sshd starts to
// accept the managed key after its agent last evaluated it, so its cached
// evaluation, and its row, still say no. A run whose freshness bound is an
// hour confirms every host in seconds all the same: each host, node-2 reached
// only through the fan-out, re-evaluates for the request and proves it.
//
// Mutations: the fan-out does not pass reevaluate on (node-2 proves nothing
// and the run times out), red; a fresh sync takes the cached evaluation
// (node-2's row stays not accepting), red.
func TestFleet_FenceSSH_ReevaluateConfirmsInSeconds(t *testing.T) {
	var node2 atomic.Bool
	c, fs := fenceSSHFleetWith(t, 3, 2631, func(name string) bool { return name != "node-2" || node2.Load() },
		func(string) string { return fencessh.ModeAuto })
	for _, n := range c.Nodes {
		n.Server.SetFenceSSH(fs[n.Name].agent)
	}
	publishAndRender(t, c, fs) // every peer verified: the evaluation's peer set is settled
	node2.Store(true)          // the install
	if err := fs["node-2"].agent.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := getFenceSSHRow(t, fs["node-2"]); r {
		t.Fatal("premise: an ordinary sync re-evaluated node-2's sshd within its cache")
	}

	err, out, took := reevalInstall(t, c, fs, c.Nodes[0], time.Hour, 45*time.Second)
	if err != nil {
		t.Fatalf("install-fence-ssh: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Every host accepts") || took > 30*time.Second {
		t.Fatalf("took %s:\n%s", took, out)
	}
}

// getFenceSSHRow is f's own row as f holds it: accepting, and whether any.
func getFenceSSHRow(t *testing.T, f *fenceSSHNode) (bool, bool, error) {
	t.Helper()
	st, err := f.agent.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range st {
		if p.Host == f.n.Name {
			return p.Accepting, p.Row == fencessh.RowVerified, nil
		}
	}
	return false, false, nil
}

// TestFleet_FenceSSH_ReevaluateOlderBuildFallsBack: a rolling upgrade.
// node-2 runs a build that predates reevaluate. Asked through node-0, node-0
// and node-1 prove their evaluation at once, but node-2's false is never
// taken as proof: under an hour's bound the run cannot confirm it, and with a
// short bound it confirms node-2 only once the bound has passed. Asked
// through node-2 itself (an older origin that drops the field, so its
// fan-out asks nobody), no host proves anything.
//
// Mutations: the CLI takes evaluated_for_request=false as proof, red; the
// origin marks a peer's answer evaluated itself, red.
func TestFleet_FenceSSH_ReevaluateOlderBuildFallsBack(t *testing.T) {
	c, fs := fenceSSHFleetWith(t, 3, 2632, func(string) bool { return true },
		func(string) string { return fencessh.ModeAuto })
	for _, n := range c.Nodes {
		n.Server.SetFenceSSH(fs[n.Name].agent)
	}
	syncAll(t, fs["node-0"], fs["node-1"], fs["node-2"])
	actAsOlderBuild(c.Nodes[2])

	oc := wantEvaluated(t, c, c.Nodes[0], map[string]bool{"node-0": true, "node-1": true, "node-2": false})
	if oc["node-0"] != "proved" || oc["node-1"] != "proved" || oc["node-2"] != "" {
		t.Fatalf("reevaluate_outcome via node-0: %q", oc)
	}
	err, out, _ := reevalInstall(t, c, fs, c.Nodes[0], time.Hour, 12*time.Second)
	if err == nil || strings.Contains(out, "Every host accepts") {
		t.Fatalf("node-2's older build confirmed without proof: err %v\n%s", err, out)
	}

	const bound = 3 * time.Second
	err, out, took := reevalInstall(t, c, fs, c.Nodes[0], bound, 60*time.Second)
	if err != nil {
		t.Fatalf("with a %s bound: %v\n%s", bound, err, out)
	}
	if took < bound {
		t.Fatalf("node-2 confirmed after %s, before its %s bound", took, bound)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("an upgraded origin (node-0) was warned about:\n%s", out)
	}

	wantEvaluated(t, c, c.Nodes[2], map[string]bool{"node-0": false, "node-1": false, "node-2": false})
	err, out, _ = reevalInstall(t, c, fs, c.Nodes[2], time.Hour, 12*time.Second)
	if err == nil || strings.Contains(out, "Every host accepts") {
		t.Fatalf("through the older origin: err %v\n%s", err, out)
	}
	// Through the older origin, every host falls back, with a warning that
	// names it and says the confirmation was time-based only.
	err, out, took = reevalInstall(t, c, fs, c.Nodes[2], bound, 60*time.Second)
	if err != nil || took < bound {
		t.Fatalf("through the older origin with a %s bound: err %v after %s\n%s", bound, err, took, out)
	}
	if !strings.Contains(out, "WARNING: node-2") || !strings.Contains(out, "time-based only") {
		t.Fatalf("no older-origin warning naming node-2:\n%s", out)
	}
}

// TestFleet_FenceSSH_ReevaluateWedgedAgentIsNotProof: node-1's agent is
// wedged in an sshd evaluation that never returns, while its row still says
// accepting from before. It answers the re-evaluation within its bound with
// no proof, so under an hour's freshness bound it never confirms; node-0 and
// node-2 do.
//
// Mutation: a host answers evaluated_for_request whatever its re-evaluation
// proved: node-1 confirms its stale row, red.
func TestFleet_FenceSSH_ReevaluateWedgedAgentIsNotProof(t *testing.T) {
	c, fs := fenceSSHFleetWith(t, 3, 2633, func(string) bool { return true },
		func(string) string { return fencessh.ModeAuto })
	f1 := fs["node-1"]
	unwedge := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unwedge) }) })
	var calls atomic.Int32
	f1.agent = fencessh.New(fencessh.Config{
		Self: f1.n.Name, PKIDir: f1.n.PKIDir, DB: f1.n.DB, Gate: f1.n.Server, Dir: f1.dir,
		HostKeyGlob:       filepath.Join(filepath.Dir(f1.dir), "etc", "ssh_host_*_key.pub"),
		ReevaluateTimeout: time.Second,
		Accepting: func(ctx context.Context, _ []string) (bool, string, error) {
			if calls.Add(1) > 1 {
				<-unwedge // ignores ctx, as a hung sshd -T child might
			}
			return true, "", nil
		},
	})
	for _, n := range c.Nodes {
		n.Server.SetFenceSSH(fs[n.Name].agent)
	}
	syncAll(t, fs["node-0"], f1, fs["node-2"])
	if acc, verified, _ := getFenceSSHRow(t, f1); !acc || !verified {
		t.Fatal("premise: node-1's row does not say accepting before it wedges")
	}

	start := time.Now()
	wantEvaluated(t, c, c.Nodes[0], map[string]bool{"node-0": true, "node-1": false, "node-2": true})
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the wedged agent held the read %s; its bound is 1s", d)
	}
	err, out, _ := reevalInstall(t, c, fs, c.Nodes[0], time.Hour, 15*time.Second)
	if err == nil || strings.Contains(out, "Every host accepts") {
		t.Fatalf("a wedged agent's stale row confirmed: err %v\n%s", err, out)
	}
	// Its build knows reevaluate, so it does not fall back to the freshness
	// bound even once that bound has passed: the run fails, naming it and why.
	// Red on 903ddfc66, which confirmed node-1 here after 2s.
	err, out, _ = reevalInstall(t, c, fs, c.Nodes[0], 2*time.Second, 60*time.Second)
	if err == nil || !strings.Contains(err.Error(), "node-1") || strings.Contains(err.Error(), "node-0") ||
		strings.Contains(err.Error(), "node-2") {
		t.Fatalf("a wedged new-build host fell back to the freshness bound: err %v\n%s", err, out)
	}
	if !strings.Contains(out, "proved nothing") || !strings.Contains(out, "wedged") {
		t.Fatalf("node-1's reason is not shown:\n%s", out)
	}
}

// wantEvaluated asks via for a re-evaluating fanned-out read and checks which
// hosts prove their evaluation.
func wantEvaluated(t *testing.T, c *Cluster, via *Node, want map[string]bool) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	st, err := c.SelfClient(via).GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{FanOut: true, Reevaluate: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	outcome := map[string]string{}
	for _, n := range st.GetNodes() {
		got[n.GetHost()] = n.GetEvaluatedForRequest()
		outcome[n.GetHost()] = n.GetReevaluateOutcome()
	}
	for h, w := range want {
		if got[h] != w {
			t.Fatalf("via %s: evaluated_for_request = %v, want %v", via.Name, got, want)
		}
	}
	return outcome
}

// TestFleet_FenceSSH_ReevaluateReadFollowsTheEvaluation: one re-evaluating
// read. node-0 (the origin) and node-2 (a peer) published accepting, and
// their sshd stopped accepting after their agents cached that answer. The
// row each reports beside evaluated_for_request must be the one its fresh
// evaluation wrote, not the one before it: a proof paired with the stale
// accepting row is the false confirmation this feature exists to prevent.
//
// Mutation: read the host's own status before Reevaluate: the stale
// accepting row comes back marked proved, red.
func TestFleet_FenceSSH_ReevaluateReadFollowsTheEvaluation(t *testing.T) {
	var refusing sync.Map
	c, fs := fenceSSHFleetWith(t, 3, 2634, func(name string) bool { _, no := refusing.Load(name); return !no },
		func(string) string { return fencessh.ModeAuto })
	for _, n := range c.Nodes {
		n.Server.SetFenceSSH(fs[n.Name].agent)
	}
	publishAndRender(t, c, fs)
	refusing.Store("node-0", true)
	refusing.Store("node-2", true)
	for _, name := range []string{"node-0", "node-2"} {
		if err := fs[name].agent.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		if acc, _, _ := getFenceSSHRow(t, fs[name]); !acc {
			t.Fatalf("premise: %s's cached evaluation did not hold its row at accepting", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	st, err := c.SelfClient(c.Nodes[0]).GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{FanOut: true, Reevaluate: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.GetNodes() {
		var self *pb.FenceSSHPeer
		for _, p := range n.GetPeers() {
			if p.GetHost() == n.GetHost() {
				self = p
			}
		}
		if !n.GetEvaluatedForRequest() || self == nil {
			t.Fatalf("%s: not proven, or no own row: %+v", n.GetHost(), n)
		}
		_, refused := refusing.Load(n.GetHost())
		if self.GetAccepting() == refused {
			t.Fatalf("%s: proved, with its own row accepting=%v; its fresh evaluation says %v",
				n.GetHost(), self.GetAccepting(), !refused)
		}
	}
}
