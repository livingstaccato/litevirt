package fleet

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Lab 2, bug 3: a guest lost its gateway for ~18 s after a live migration.
// Its ARP cache held the gateway at the SOURCE host's bridge MAC, and the
// gratuitous ARP litevirt sent ran on the source, through `arping` (absent),
// for the guest's own address. Once the move commits, the TARGET now
// announces the gateway of each of the guest's networks from its own bridge.
//
// Mutation: call announceGatewaysOf on the source instead of
// announceOnTarget — the source announces and the target does not.
func TestFleet_LiveMigrationAnnouncesTheGatewayOnTheTarget(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	var mu sync.Mutex
	announced := map[string][]string{}
	for _, n := range c.Nodes {
		name := n.Name
		n.Server.SetGatewayAnnouncer(func(bridge string, gw netip.Addr) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			announced[name] = append(announced[name], bridge+" "+gw.String())
			return true, nil
		})
	}
	cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "mvbr", Subnet: "172.46.0.0/24", DHCP: true})
	if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: "mv_lan", StackName: "mv", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "mover", HostName: src.Name, State: "running", Spec: `{"name":"mover","cpu":1,"memory_mib":512}`,
		CPUActual: 1, MemActual: 512,
	}, []corrosion.InterfaceRecord{{VMName: "mover", NetworkName: "mv_lan", MAC: "52:54:00:46:00:07", IP: "172.46.0.7"}}, nil); err != nil {
		t.Fatalf("seed mover: %v", err)
	}
	src.Virt.SetState("mover", "running")

	if err := migrateAt(t, c, src, "mover", dst.Name); err != nil {
		t.Fatalf("migrate mover to %s: %v", dst.Name, err)
	}
	eventually(t, 10*time.Second, dst.Name+" to announce mv_lan's gateway", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(announced[dst.Name]) > 0
	})
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(announced[dst.Name], ","); got != "mvbr 172.46.0.1" {
		t.Errorf("%s (target) announced %q, want mvbr 172.46.0.1", dst.Name, got)
	}
	if got := announced[src.Name]; len(got) != 0 {
		t.Errorf("%s (source) announced %q; the guest has left it", src.Name, got)
	}
}
