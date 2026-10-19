package fleet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/lb"
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

// lbStandIns puts haproxy, keepalived and sysctl stand-ins on PATH, each
// logging its arguments to <dir>/<name>.calls, and a conntrackd stand-in that
// logs and leaves a process running whose command line names its config, as
// conntrackd's does.
//
// Each process left running records its pid in <dir>/standins.pids, and the
// cleanup kills those pids and nothing else. Its shell loops 'sleep 1; ... true'
// while the test process lives, never 'sleep 600; :': branches without this cleanup still end each LB test
// with `pkill -f "sleep 600; : .*<test name>"`, and the stand-ins' command
// lines name their temp dir, which names the test. One such cleanup anywhere
// on the host killed the stand-ins of every process running the test at that
// moment, and each one's next apply started keepalived and conntrackd again
// (TestLBStandIns_AnotherRunsCleanupLeavesThemAlone).
func lbStandIns(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pids := filepath.Join(dir, "standins.pids")
	// A stand-in outlives nothing: it polls its test process and exits when
	// that is gone, so a test killed before t.Cleanup runs (a timeout, a
	// SIGKILL, a rebuilt tree) leaves no process behind. 600 iterations of
	// one second bound it regardless.
	alive := fmt.Sprintf("i=0; while [ $i -lt 600 ] && kill -0 %d 2>/dev/null; do sleep 1; i=$((i+1)); done; true", os.Getpid())
	for name, body := range map[string]string{
		"haproxy": "",
		// keepalived daemonizes and writes its pidfile (-p); the apply
		// restarts one that is not alive.
		"keepalived": "while [ $# -gt 0 ]; do [ \"$1\" = -p ] && pidf=$2; shift; done\n" +
			"nohup sh -c '" + alive + "' keepalived-standin " + dir + " >/dev/null 2>&1 &\n" +
			"echo $! > \"$pidf\"\necho $! >> " + pids + "\n",
		"sysctl": "",
		"conntrackd": "nohup sh -c '" + alive + "' conntrackd \"$@\" >/dev/null 2>&1 &\n" +
			"echo $! >> " + pids + "\n",
	} {
		script := fmt.Sprintf("#!/bin/sh\necho \"$@\" >> %s\n%s", filepath.Join(dir, name+".calls"), body)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	t.Cleanup(func() {
		b, _ := os.ReadFile(pids)
		for _, f := range strings.Fields(string(b)) {
			pid, err := strconv.Atoi(f)
			if err != nil || pid <= 0 {
				continue
			}
			exec.Command("pkill", "-KILL", "-P", f).Run() //nolint:errcheck // its sleep
			syscall.Kill(pid, syscall.SIGKILL)            //nolint:errcheck // gone already when an apply restarted it
		}
	})
	return dir
}

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
func TestFleet_LBSNATNoFlapAcrossApplyPaths(t *testing.T) {
	bin := lbStandIns(t)
	certDir := t.TempDir()
	cert, key := filepath.Join(certDir, "lbn.crt"), filepath.Join(certDir, "lbn.key")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("PEM "+f+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	var mu sync.Mutex
	applied := map[string][]lb.Config{}
	for _, n := range c.Nodes {
		n := n
		seedImage(t, ctx, n, "test")
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
		n.Server.SetBridgeExists(func(string) bool { return true })
		root := t.TempDir()
		mgr := lb.NewManagerAt(filepath.Join(root, "config"), filepath.Join(root, "run"))
		n.Server.SetLBApply(func(ctx context.Context, cfg lb.Config) error {
			mu.Lock()
			applied[n.Name] = append(applied[n.Name], cfg)
			mu.Unlock()
			return mgr.Apply(ctx, cfg)
		})
	}

	yaml := strings.NewReplacer("CERT", cert, "KEY", key).Replace(composeLBSNATNoFlap)
	for _, p := range deployCollect(t, ctx, c.SelfClient(c.Nodes[0]), yaml) {
		if p.Phase == "error" {
			t.Fatalf("deploy: %s: %s", p.VmName, p.Error)
		}
	}
	for round := 0; round < 3; round++ {
		for _, n := range c.Nodes {
			n.Server.RefreshLBForStack(ctx, "lbn")
		}
	}
	// The refreshes forward in the background: wait until the applies stop.
	total := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(applied["node-0"]) + len(applied["node-1"])
	}
	last, stable := -1, time.Now()
	for time.Since(stable) < 3*time.Second {
		if n := total(); n != last {
			last, stable = n, time.Now()
		}
		time.Sleep(100 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"node-0", "node-1"} {
		cfgs := applied[name]
		if len(cfgs) < 4 {
			t.Fatalf("%s: %d applies, want several from both paths", name, len(cfgs))
		}
		for i, cfg := range cfgs {
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
	if got := countLines(filepath.Join(bin, "keepalived.calls"), "-f "); got != 2 {
		b, _ := os.ReadFile(filepath.Join(bin, "keepalived.calls"))
		t.Errorf("keepalived started %d times on two hosts, want 2 (once each):\n%s", got, b)
	}
	if got := countLines(filepath.Join(bin, "conntrackd.calls"), "-d"); got != 2 {
		b, _ := os.ReadFile(filepath.Join(bin, "conntrackd.calls"))
		t.Errorf("conntrackd started %d times on two hosts, want 2 (once each):\n%s", got, b)
	}
}
