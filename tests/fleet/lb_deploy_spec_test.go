package fleet

import (
	"context"
	"sync"
	"testing"

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
            cert: /etc/lbf/cert.pem
            key: /etc/lbf/key.pem
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
	if p := c.Ports[1]; p.Listen != 443 || p.TLS == nil || p.TLS.Cert != "/etc/lbf/cert.pem" || p.TLS.Key != "/etc/lbf/key.pem" {
		t.Errorf("deploy %d apply %d: port 443 %+v, want TLS with the file's cert and key", round, i, p)
	}
}
