package fleet

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// A stack LB asking for everything its definition can carry.
const composeLBFullSpec = `name: lbf

images:
  test:
    source: file:///dev/null

networks:
  lan:
    type: bridge
    subnet: 10.203.0.0/24
    dhcp: true

vms:
  web:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: lan
        ip: 10.203.0.10
    loadbalancer:
      enabled: true
      vip: 10.203.0.250/24
      algorithm: leastconn
      sticky-sessions: true
      hosts:
        - node-0
      ports:
        - listen: 80
          target: 8080
          protocol: http
          redirect-https: true
        - listen: 443
          target: 8080
          protocol: http
          tls:
            cert: /etc/litevirt/lb-certs/lbf.crt
            key: /etc/litevirt/lb-certs/lbf.key
      health:
        type: http
        path: /healthz
        interval-ms: 1500
`

// TestFleet_StackLBDeployKeepsTheWholeSpec: a stack LB with sticky sessions,
// an http health check, a TLS listener and a redirect-https listener is
// applied with all of them, on the first deploy and on a re-deploy. Before,
// the deploy plan's LB step built a stub spec of VIP, algorithm and plain
// ports, so every deploy re-applied the LB without the rest of what the file
// asked for.
//
// Mutations (each red): the stub back in applyLBActions; Sticky, Health, the
// port's TLS or RedirectHTTPS dropped from compose.BuildLBSpec or from
// lbSettingsFromPB.
func TestFleet_StackLBDeployKeepsTheWholeSpec(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	node.Server.SetBridgeExists(node.Net.HasDevice)
	var mu sync.Mutex
	var applied []lb.Config
	node.Server.SetLBApply(func(_ context.Context, c lb.Config) error {
		mu.Lock()
		defer mu.Unlock()
		applied = append(applied, c)
		return nil
	})

	for round := 1; round <= 2; round++ {
		mu.Lock()
		applied = nil
		mu.Unlock()
		msgs := deployCollect(t, ctx, client, composeLBFullSpec)
		if p := errorPhaseFor(msgs, "web"); p != nil {
			t.Fatalf("deploy %d of web failed: %s", round, p.Error)
		}
		mu.Lock()
		got := append([]lb.Config(nil), applied...)
		mu.Unlock()
		if len(got) == 0 {
			t.Fatalf("deploy %d: the load balancer was never applied", round)
		}
		for i, c := range got {
			checkFullLBConfig(t, round, i, c)
		}
	}
}

func checkFullLBConfig(t *testing.T, round, i int, c lb.Config) {
	t.Helper()
	if c.Algorithm != "leastconn" {
		t.Errorf("deploy %d apply %d: algorithm %q, want leastconn", round, i, c.Algorithm)
	}
	if !c.Sticky {
		t.Errorf("deploy %d apply %d: sticky sessions dropped", round, i)
	}
	if h := c.Health; h == nil || h.Type != "http" || h.Path != "/healthz" || h.IntervalMS != 1500 {
		t.Errorf("deploy %d apply %d: health %+v, want http /healthz 1500ms", round, i, h)
	}
	if len(c.Ports) != 2 {
		t.Fatalf("deploy %d apply %d: ports %+v, want 2", round, i, c.Ports)
	}
	if p := c.Ports[0]; p.Listen != 80 || !p.RedirectHTTPS || p.TLS != nil {
		t.Errorf("deploy %d apply %d: port 80 %+v, want redirect-https", round, i, p)
	}
	if p := c.Ports[1]; p.Listen != 443 || p.TLS == nil || p.TLS.Cert != "/etc/litevirt/lb-certs/lbf.crt" || p.TLS.Key != "/etc/litevirt/lb-certs/lbf.key" {
		t.Errorf("deploy %d apply %d: port 443 %+v, want TLS with the file's cert and key", round, i, p)
	}
}

// An extends base carrying the stack's LB, and two children of it.
const composeLBExtendsBase = `name: lbe

images:
  test:
    source: file:///dev/null

networks:
  hinet:
    type: bridge
    subnet: 10.206.0.0/24
    dhcp: true
    host-isolation: true

vms:
  base:
    image: test
    cpu: 1
    memory: 512
    replicas: 0
    placement:
      host: node-0
    network:
      - name: hinet
    loadbalancer:
      vip: 10.206.0.250/24
      hosts:
        - node-0
      ports:
        - listen: 80
          target: 8080
  web:
    extends: base
    replicas: 1
    network:
      - name: hinet
        ip: 10.206.0.10
  api:
    extends: base
    replicas: 1
    network:
      - name: hinet
        ip: 10.206.0.11
`

// TestFleet_ExtendsBaseLBDeploysOneLB (I-R1): the documented extends
// pattern with the LB on the base deploys, as on main, and gives the stack
// one load balancer.
func TestFleet_ExtendsBaseLBDeploysOneLB(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	node.Server.SetBridgeExists(node.Net.HasDevice)
	var mu sync.Mutex
	names := map[string]bool{}
	node.Server.SetLBApply(func(_ context.Context, c lb.Config) error {
		mu.Lock()
		defer mu.Unlock()
		names[c.Name] = true
		return nil
	})
	msgs := deployCollect(t, ctx, client, composeLBExtendsBase)
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy: %s: %s", p.VmName, p.Error)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(names) != 1 || !names["lbe-lb"] {
		t.Errorf("load balancers applied: %v, want lbe-lb only", names)
	}
	cfgs, err := corrosion.ListLBConfigs(ctx, node.DB)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range cfgs {
		if c.StackName == "lbe" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d LB rows for the stack, want 1: %+v", n, cfgs)
	}
}
