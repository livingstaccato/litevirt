package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
)

// latchProjectIncarnation drives project_incarnation_v1 on every node through
// real checkers and wires each node's corrosion gate to its durable latch, as
// the daemon does. withhold, when set, is a node whose advertisement lacks the
// token while held reads true: a host on the previous build.
func latchProjectIncarnation(t *testing.T, c *Cluster, withhold *Node, held *atomic.Bool) map[string]*health.Checker {
	t.Helper()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		node := n
		g := gates[node.Name]
		if withhold != nil {
			g.SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
				caps, wall, err := node.Server.PeerCapabilities(ctx, host)
				if held.Load() && host == withhold.Name {
					caps = withoutToken(caps, capabilities.ProjectIncarnationV1)
				}
				return caps, wall, err
			})
		}
		node.DB.SetProjectIncarnationGate(func() bool { return g.DurablyLatched(capabilities.ProjectIncarnationV1) })
	}
	for _, n := range c.Nodes {
		if n == withhold {
			continue
		}
		latched := gates[n.Name].Enforced(context.Background(), capabilities.ProjectIncarnationV1)
		if withhold == nil && !latched {
			t.Fatalf("%s: project_incarnation_v1 did not latch with every host advertising it", n.Name)
		}
		if withhold != nil && latched {
			t.Fatalf("%s latched project_incarnation_v1 while %s runs a build without it", n.Name, withhold.Name)
		}
	}
	return gates
}
