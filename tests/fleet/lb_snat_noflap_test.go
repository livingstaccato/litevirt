package fleet

import (
	"context"
	"encoding/json"
	"google.golang.org/grpc"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/lbtestproc"
)

// composeLBSNATNoFlap: an LB with snat over two LB hosts on a host-isolated
// network, with health, sticky sessions, a TLS listener and a redirect.
// CERT and KEY are replaced with real files.
const composeLBSNATNoFlap = `name: lbn

images:
  test:
    source: file:///dev/null

networks:
  hinet:
    type: bridge
    subnet: 10.205.0.0/24
    dhcp: true
    host-isolation: true

vms:
  lbn1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: hinet
        ip: 10.205.0.10
    loadbalancer:
      enabled: true
      vip: 10.205.0.250/24
      snat: true
      sticky-sessions: true
      hosts:
        - node-0
        - node-1
      ports:
        - listen: 80
          target: 8080
          protocol: http
          redirect-https: true
        - listen: 443
          target: 8080
          protocol: http
          tls:
            cert: CERT
            key: KEY
      health:
        type: http
        path: /healthz
        interval-ms: 1500
`

func countLines(path string, sub string) int {
	b, _ := os.ReadFile(path)
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// TestFleet_LBSNATNoFlapAcrossApplyPaths: a two-host stack LB with snat is
// applied on each host both by that host's own refresh (applyLBForStack) and
// by the other host's forwarded apply (ApplyLB). Over repeated refreshes from
// both hosts, each host's keepalived is started once and never restarted
// (its VIP stays with the master), its conntrackd is started once and stays,
// and every apply on either host serves the whole LB: sticky, health, TLS,
// redirect and the conntrackd sync. Before, the forwarded apply carried none
// of these: it rendered keepalived without the notify hooks and tore
// conntrackd down, and the next own apply put them back, restarting
// keepalived on every round.
//
// Mutations (each red): forwardLBApply sends no Health/StickySessions, or
// plain ports; ApplyLB skips lbSNATSync.
func TestFleet_LBSNATNoFlapAcrossApplyPaths(t *testing.T) { testPrivateStackLB(t, false) }
func TestFleet_StackLBUpdateKeepsWholeSpec(t *testing.T)  { testPrivateStackLB(t, true) }
func testPrivateStackLB(t *testing.T, update bool) {
	runtimes := []*lbtestproc.Runtime{lbtestproc.New(t, true), lbtestproc.New(t, true)}
	certDir := t.TempDir()
	cert, key := filepath.Join(certDir, "lbn.crt"), filepath.Join(certDir, "lbn.key")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("PEM "+f+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	yaml := strings.NewReplacer("CERT", cert, "KEY", key).Replace(composeLBSNATNoFlap)
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	var mu sync.Mutex
	applied := map[string][]lb.Config{}
	var dependenciesClosed atomic.Bool
	for i, n := range c.Nodes {
		n := n
		seedImage(t, ctx, n, "test")
		if err := corrosion.UpsertStack(ctx, n.DB, corrosion.StackRecord{Name: "lbn", ComposeYAML: yaml, State: "running"}); err != nil {
			t.Fatal(err)
		}
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
		n.Server.SetBridgeExists(func(string) bool { return true })
		if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "lbn_hinet", StackName: "lbn", Type: "bridge", Config: `{"subnet":"10.205.0.0/24","dhcp":true,"HostIsolation":true}`}); err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		t.Cleanup(c.waitLBWork)
		mgr := lb.NewManagerAt(filepath.Join(root, "config"), filepath.Join(root, "run"))
		mgr.SetProcessRuntime(runtimes[i])
		n.Server.SetLBApply(func(ctx context.Context, cfg lb.Config) error {
			if dependenciesClosed.Load() {
				t.Error("LB apply after dependent fixture teardown")
			}
			mu.Lock()
			applied[n.Name] = append(applied[n.Name], cfg)
			mu.Unlock()
			return mgr.Apply(ctx, cfg)
		})
	}

	t.Cleanup(func() { c.waitLBWork(); dependenciesClosed.Store(true); c.Stop() })
	for _, p := range deployCollect(t, ctx, c.SelfClient(c.Nodes[0]), yaml) {
		if p.Phase == "error" {
			t.Fatalf("deploy: %s: %s", p.VmName, p.Error)
		}
	}
	c.waitLBWork()
	for _, n := range c.Nodes {
		eventually(t, 20*time.Second, "stack spec visible on "+n.Name, func() bool {
			r, e := corrosion.GetStack(ctx, n.DB, "lbn")
			return e == nil && r != nil && r.ComposeYAML != ""
		})
	}
	if update {
		for _, n := range c.Nodes {
			if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "other_hinet", StackName: "other", Type: "bridge", Config: `{"interface":"hinet","subnet":"10.205.0.0/24","HostIsolation":true}`}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.SelfClient(c.Nodes[0]).UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbn-lb", AddBackends: []*pb.LBBackendAddress{{Name: "extra", Address: "10.205.0.12"}}}); err != nil {
			t.Fatal(err)
		}
		c.waitLBWork()
		mu.Lock()
		for _, n := range c.Nodes {
			cfgs := applied[n.Name]
			if len(cfgs) == 0 {
				t.Errorf("%s: update never applied", n.Name)
				continue
			}
			found := false
			for _, backend := range cfgs[len(cfgs)-1].Backends {
				if backend.Name == "extra" && backend.IP == "10.205.0.12" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: supported backend edit was discarded", n.Name)
			}
		}
		mu.Unlock()
	}
	for round := 0; round < 3; round++ {
		for _, n := range c.Nodes {
			n.Server.RefreshLBForStack(ctx, "lbn")
		}
	}
	c.waitLBWork()
	if update {
		proveLBChainedDrain(t, c)
	}
	for _, n := range c.Nodes {
		n.Net.mu.Lock()
		routes, forwards := n.Net.lbRoutes, n.Net.lbForwards
		n.Net.mu.Unlock()
		if routes == 0 || routes != forwards {
			t.Errorf("%s: private route/forward calls %d/%d", n.Name, routes, forwards)
		}
		t.Logf("%s: LB/VTEP work joined; private route/forward calls %d/%d", n.Name, routes, forwards)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"node-0", "node-1"} {
		cfgs := applied[name]
		if len(cfgs) < 4 {
			t.Fatalf("%s: %d applies, want several from both paths", name, len(cfgs))
		}
		for i, cfg := range cfgs {
			if cfg.Interface != "lbn_hinet" {
				t.Errorf("%s apply %d: interface %q, want lbn_hinet", name, i, cfg.Interface)
			}
			if !cfg.SNATEnabled || cfg.PeerIP == "" || cfg.KeepSNAT {
				t.Errorf("%s apply %d: SNAT sync enabled=%v peer=%q keep=%v, want the sync", name, i, cfg.SNATEnabled, cfg.PeerIP, cfg.KeepSNAT)
			}
			if !cfg.Sticky || cfg.Health == nil || cfg.Health.Path != "/healthz" || cfg.Health.IntervalMS != 1500 {
				t.Errorf("%s apply %d: sticky=%v health=%+v, want sticky and the http check", name, i, cfg.Sticky, cfg.Health)
			}
			if len(cfg.Ports) != 2 || !cfg.Ports[0].RedirectHTTPS || cfg.Ports[1].TLS == nil || cfg.Ports[1].TLS.Cert != cert {
				t.Errorf("%s apply %d: ports %+v, want the redirect and the TLS listener", name, i, cfg.Ports)
			}
		}
	}
	// One keepalived start and one conntrackd start per host, over every
	// apply: nothing restarted them.
	if got := runtimes[0].Starts["keepalived"] + runtimes[1].Starts["keepalived"]; got != 2 {
		t.Errorf("keepalived started %d times on two hosts, want 2 (once each)", got)
	}
	if got := runtimes[0].Starts["conntrackd"] + runtimes[1].Starts["conntrackd"]; got != 2 {
		t.Errorf("conntrackd started %d times on two hosts, want 2 (once each)", got)
	}
}

// A producer on node1 has returned after registering its RefreshLB fanout.
// Hold that peer request before it creates node0 work, then hold node0's
// chained ApplyLB on node1. Neither an idle earlier node nor the first request
// returning is sufficient to declare the cluster drained.
func proveLBChainedDrain(t *testing.T, c *Cluster) {
	t.Helper()
	// Refresh reads the replicated VM spec, not just the preseeded compose row.
	for _, n := range c.Nodes {
		eventually(t, 20*time.Second, "refreshable VM spec on "+n.Name, func() bool {
			vms, err := corrosion.ListVMs(context.Background(), n.DB, "lbn", "")
			if err != nil {
				return false
			}
			for _, vm := range vms {
				var spec pb.VMSpec
				if json.Unmarshal([]byte(vm.Spec), &spec) == nil && spec.StackName == "lbn" && spec.GetLoadbalancer().GetEnabled() {
					return true
				}
			}
			return false
		})
	}
	first, second := c.Nodes[0], c.Nodes[1]
	refreshParked, releaseRefresh := make(chan struct{}), make(chan struct{})
	applyParked, releaseApply := make(chan struct{}), make(chan struct{})
	firstIdle, drained := make(chan struct{}), make(chan struct{})
	var releaseRefreshOnce, releaseApplyOnce, idleOnce sync.Once
	release1 := func() { releaseRefreshOnce.Do(func() { close(releaseRefresh) }) }
	release2 := func() { releaseApplyOnce.Do(func() { close(releaseApply) }) }
	started := false
	wait := func(ch <-chan struct{}, label string) {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not complete", label)
		}
	}
	t.Cleanup(func() {
		release1()
		release2()
		if started {
			select {
			case <-drained:
			case <-time.After(10 * time.Second):
				t.Error("LB barrier drain failed cleanup join")
			}
		}
	})
	first.HookUnary("RefreshLB", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		close(refreshParked)
		<-releaseRefresh
		return handler(ctx, req)
	})
	second.Server.RefreshLBForStack(context.Background(), "lbn")
	wait(refreshParked, "peer refresh park")
	var completed atomic.Bool
	second.HookUnary("ApplyLB", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		close(applyParked)
		<-releaseApply
		result, err := handler(ctx, req)
		if err == nil {
			completed.Store(true)
		}
		return result, err
	})
	started = true
	go func() {
		defer close(drained)
		c.waitLBWorkObserved(func(n *Node) {
			if n == first {
				idleOnce.Do(func() { close(firstIdle) })
			}
		})
	}()
	wait(firstIdle, "earlier node idle observation")
	select {
	case <-drained:
		t.Fatal("drain retired while peer refresh was parked")
	default:
	}
	release1()
	wait(applyParked, "chained peer apply park")
	select {
	case <-drained:
		t.Fatal("drain retired before chained peer apply completed")
	default:
	}
	release2()
	wait(drained, "chained LB work drain")
	if !completed.Load() {
		t.Fatal("drain did not include successful chained ApplyLB")
	}
	t.Log("quiescent producer; earlier node idle; delayed RefreshLB registered chained ApplyLB; barriers released and all tracked work joined")
}
