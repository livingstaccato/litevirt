// Fleet scenario: an isolated network's dnsmasq offers no router to a NIC of
// a VM that also has a NIC on a routed network, and the bridge to a VM whose
// NICs are all isolated.
//
// Lab 2 (F5): RHEL-family cloud-init drops the seed's use-routes: false, so a
// hot-attached DHCP NIC on an isolated network took a default route through
// the host's bridge beside eth0's. The tag is per MAC in the bridge's DHCP
// hosts file, so it must follow the VM's NIC count through create, attach,
// detach and delete — and be in place before the guest can ask.
//
// Multi-node by construction: the attach and detach are sent to the node that
// does NOT own the VM and reach the owner over real gRPC, where the hosts file
// is rewritten.
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// Mutation: drop the rewrite when pendingNICs registers NICs — the tag is not
// there at the first start or the hot attach; drop the rewrite after a detach
// or a delete — the single-NIC VM keeps its tag, the deleted VM's MACs stay;
// count any second NIC as routed — the all-isolated VM is tagged.
func TestFleet_IsolatedNoRouterFollowsNICCount(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]

	var mu sync.Mutex
	files := map[string]map[string]map[string]network.DHCPHost{} // node → bridge → mac → line
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		node := n.Name
		n.Server.SetDHCPHostsSync(func(bridge string, hosts map[string]network.DHCPHost) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			if files[node] == nil {
				files[node] = map[string]map[string]network.DHCPHost{}
			}
			cp := make(map[string]network.DHCPHost, len(hosts))
			for m, h := range hosts {
				cp[m] = h
			}
			files[node][bridge] = cp
			return true, nil
		})
	}
	for name, def := range map[string]compose.NetworkDef{
		"dnet":   {Type: "bridge", Subnet: "10.64.0.0/24", DHCP: true},
		"isonet": {Type: "isolated", Subnet: "10.65.0.0/24", DHCP: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	isoBridge := network.IsolatedBridgeName("isonet")
	tagged := func(mac string) bool {
		mu.Lock()
		defer mu.Unlock()
		return files[src.Name][isoBridge][strings.ToLower(mac)].NoRouter
	}
	listed := func(mac string) bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok := files[src.Name][isoBridge][strings.ToLower(mac)]
		return ok
	}

	const (
		macMD = "52:54:00:6e:00:01" // multi, on dnet
		macM  = "52:54:00:6e:00:02" // multi, on isonet
		macS  = "52:54:00:6e:00:03" // single, on isonet
	)
	atStart := map[string]bool{}
	src.Virt.FailStartDomain = func(name string) error {
		atStart[name] = tagged(map[string]string{"multi": macM, "single": macS}[name])
		return nil
	}
	create := func(name string, nics ...*pb.NetworkAttachment) {
		t.Helper()
		if _, err := c.SelfClient(src).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: src.Name}, Network: nics,
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
	}

	// Create: a VM with another NIC is tagged before its first start; a VM
	// whose only NIC is isolated is not.
	create("multi", &pb.NetworkAttachment{Name: "dnet", Mac: macMD}, &pb.NetworkAttachment{Name: "isonet", Mac: macM})
	create("single", &pb.NetworkAttachment{Name: "isonet", Mac: macS})
	if !atStart["multi"] || !tagged(macM) {
		t.Errorf("multi's isolated NIC: tagged at start %v, after create %v; want both true", atStart["multi"], tagged(macM))
	}
	if atStart["single"] || tagged(macS) {
		t.Errorf("single's only NIC is tagged (at start %v, after create %v): it would lose the router main offers it", atStart["single"], tagged(macS))
	}
	if tagged(macMD) {
		t.Errorf("a NIC on the bridge network is in the isolated network's hosts file as tagged")
	}

	latchHardwareV2(t, c, gateAll(t, c)) // two NICs on one network need it

	// Attach a second NIC: single's isolated NIC is tagged.
	d := mustAttachNIC(t, c, dst, "single", "dnet")
	if !tagged(macS) {
		t.Errorf("single gained a NIC, its isolated NIC %s is not tagged", macS)
	}
	// Detach it: single's only NIC is offered the router again.
	mustDetachNIC(t, c, dst, "single", d.MAC)
	if tagged(macS) {
		t.Errorf("single is back to one NIC, its isolated NIC %s is still tagged", macS)
	}

	// Attach a second isolated NIC to single: its NICs are all isolated, so
	// neither is tagged — the router main offers them is kept.
	var atAttach [2]bool
	src.Virt.FailAttachNIC = func(_, _, _, mac string) error {
		atAttach = [2]bool{tagged(mac), tagged(macS)}
		return nil
	}
	x := mustAttachNIC(t, c, dst, "single", "isonet")
	if atAttach[0] || atAttach[1] || tagged(x.MAC) || tagged(macS) {
		t.Errorf("single has only isolated NICs, yet a NIC is tagged: at the attach new %v old %v, after new %v old %v",
			atAttach[0], atAttach[1], tagged(x.MAC), tagged(macS))
	}

	// Hot-attach an isolated NIC to multi, which has a routed NIC: the new
	// NIC is tagged before the guest sees it.
	y := mustAttachNIC(t, c, dst, "multi", "isonet")
	src.Virt.FailAttachNIC = nil
	if !atAttach[0] || !tagged(y.MAC) || !tagged(macM) {
		t.Errorf("multi's new isolated NIC: tagged at the attach %v, after %v; old NIC %v; want all true", atAttach[0], tagged(y.MAC), tagged(macM))
	}

	// Delete: the VM's MAC leaves the file.
	if _, err := c.SelfClient(src).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "multi"}); err != nil {
		t.Fatalf("DeleteVM multi: %v", err)
	}
	if listed(macM) || listed(y.MAC) {
		t.Errorf("deleted VM's NICs are still in the hosts file: %s %v, %s %v", macM, listed(macM), y.MAC, listed(y.MAC))
	}
}

// The same owner used before buildServer replaces a server must wait for an
// actual DHCP backend reader, including a callback already in progress.
func TestFleet_ServerLoopStopJoinsDHCPWorker(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 1, SharedCRDT: true})
	n := c.Nodes[0]
	old := n.Server
	cfg, err := json.Marshal(compose.NetworkDef{Type: "isolated", Subnet: "10.66.0.0/24", DHCP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "lifetime-dhcp", Type: "isolated", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	old.SetDHCPHostsSync(func(string, map[string]network.DHCPHost) (bool, error) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		return false, nil
	})
	workerDone := old.StartDHCPReservations(ctx, time.Hour)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); old.StopDHCPReservations(); <-workerDone })
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the old server's DHCP worker did not enter its backend")
	}
	stop := n.stopServerLoops
	stopped := make(chan struct{})
	go func() { defer close(stopped); stop() }()
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); <-stopped })
	select {
	case <-stopped:
		t.Fatal("replacement stop returned while the old DHCP worker still owned its backend")
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("replacement stop did not finish after the held backend returned")
	}
	select {
	case <-workerDone:
	default:
		t.Fatal("replacement stop returned before the actual DHCP worker completed")
	}
	restartNode(t, c, n)
	if n.Server == old {
		t.Fatal("the fixture did not replace the server")
	}
}
