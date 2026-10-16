package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// A stack whose `bridge` network is named br-iso-web — main accepted that,
// and its guests routed out with NAT.
const composeBridgeNamedBrIso = `name: brisoweb

images:
  test:
    source: file:///dev/null

networks:
  br-iso-web:
    type: bridge
    subnet: 10.60.0.0/24
    dhcp: true

vms:
  web:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    network:
      - name: br-iso-web
`

// TestFleet_BridgeNetworkNamedBrIsoKeepsWorking: the stack deploys, deploys
// again (a re-apply after an upgrade), and the firewall this node renders
// names its bridge nowhere: isolated bridges are held by interface group, so a
// bridge network's br-iso-* bridge keeps routing.
//
// Mutation: refuse br-iso-* bridge names at create (round 0's fix) — the
// deploy fails, red; or match br-iso-* by name in the firewall — red.
func TestFleet_BridgeNetworkNamedBrIsoKeepsWorking(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)

	for i := 0; i < 2; i++ {
		msgs := deployCollect(t, ctx, client, composeBridgeNamedBrIso)
		for _, p := range msgs {
			if p.Phase == "error" {
				t.Fatalf("deploy %d: %s: %s", i+1, p.VmName, p.Error)
			}
		}
	}
	rows, err := node.DB.Query(ctx, `SELECT name, type FROM networks WHERE deleted_at IS NULL AND config LIKE '%br-iso-web%'`)
	if err != nil || len(rows) != 1 || rows[0].String("type") != "bridge" {
		t.Fatalf("network rows %v (err %v), want one bridge network on br-iso-web", rows, err)
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "web"); vm == nil {
		t.Fatal("web was not created")
	}

	plan, err := firewall.CorrosionPlanLoader(node.DB, node.Name, firewall.Plan{}, firewall.LoaderOptions{})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out, err := firewall.Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "br-iso") {
		t.Errorf("the firewall names a br-iso device for a bridge network:\n%s", out)
	}
}
