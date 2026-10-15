package fleet

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/nictap"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A VM whose NICs were hot-plugged keeps exactly its live NICs wherever its
// domain is rebuilt from stored state: a failover start on another host, a
// redefine of the stopped VM, and the networks a migration sets up on its
// target. On a cluster with hardware_v2 latched an attach writes only vm_nics
// and a detach tombstones only vm_nics, so a rebuild from vm_interfaces boots
// the create-time NICs: the attached one missing, the detached one back.
//
// Mutations, each turning the named test red:
//   - domainXMLFor reads GetVMInterfaces again (Failover, latched: the domain
//     has na+nb, not na+nc; nb is provisioned on the survivor);
//   - UpdateVM's regenerate reads GetVMInterfaces again (UpdateVM, latched);
//   - provisionVMNetworksOnRemote reads GetVMInterfaces again (Migrate,
//     latched: nc is not provisioned on the target, nb is);
//   - retireDetachedNICGuard does nothing (every test here, both kinds: the
//     guard records name the gone NIC, and the start or the migration is
//     refused because its guard cannot be put in force);
//   - the detach alone skips it (Failover, UpdateVM and Migrate, both kinds);
//   - the attach rollback alone skips it (FailedNICAttach, both kinds);
//   - a same-name promotion builds its NICs from the spec again
//     (PromoteTakeover, both kinds: the domain has na+nb, and nb, its guard
//     record retired, would boot with no guard).
//
// The unlatched variants stay green under the first three: before the latch
// both tables carry every attach and detach, and the overlay reads as the
// legacy table did.

const (
	mnA = "52:54:00:6e:00:0a"
	mnB = "52:54:00:6e:00:0b"
)

// mergedNICsCluster is a three-node cluster with NIC guards open, the
// operation protocol latched (hotplug needs it) and, when latched, hardware_v2
// latched, with three isolated networks na, nb and nc. refresh renews every
// node's quorum view before a gated step (the fleet runs no HA monitor).
func mergedNICsCluster(t *testing.T, latched bool) (c *Cluster, refresh func()) {
	t.Helper()
	c = New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	gates := gateAll(t, c)
	if latched {
		latchHardwareV2(t, c, gates)
	} else {
		latchOperationProtocol(t, c, gates)
	}
	for name, subnet := range map[string]string{"na": "172.16.71.0/24", "nb": "172.16.72.0/24", "nc": "172.16.73.0/24"} {
		if _, err := c.SelfClient(c.Nodes[0]).CreateNetwork(ctx, &pb.CreateNetworkRequest{
			Name: name, Type: "isolated", Subnet: subnet, Dhcp: true,
		}); err != nil {
			t.Fatalf("CreateNetwork %s: %v", name, err)
		}
	}
	return c, func() {
		for _, n := range c.Nodes {
			gates[n.Name].QuorumProof(ctx)
			peers := map[string]bool{}
			for _, o := range c.Nodes {
				if o != n {
					peers[o.Name] = true
				}
			}
			gates[n.Name].SeedPeersForTests(peers)
		}
	}
}

// hotplugged creates vm on home with NICs A (na) and B (nb), hot-attaches C
// (nc) and detaches B, and returns C's MAC.
func hotplugged(t *testing.T, c *Cluster, home *Node, vm string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := c.SelfClient(home).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: vm, Cpu: 1, MemoryMib: 256, OnHostFailure: "restart-any",
		Placement: &pb.PlacementSpec{Host: home.Name},
		Network: []*pb.NetworkAttachment{
			{Name: "na", Mac: mnA},
			{Name: "nb", Mac: mnB},
		},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	cNIC := mustAttachNIC(t, c, home, vm, "nc")
	mustDetachNIC(t, c, home, vm, mnB)
	want := map[string]string{mnA: "na", strings.ToLower(cNIC.MAC): "nc"}
	if got := liveNICSet(t, home, vm); !sameNICSet(got, want) {
		t.Fatalf("fixture: live NICs after the hotplug = %v, want %v", got, want)
	}
	return strings.ToLower(cNIC.MAC)
}

func liveNICSet(t *testing.T, n *Node, vm string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, r := range liveNICs(t, n, vm) {
		out[strings.ToLower(r.MAC)] = r.NetworkName
	}
	return out
}

func sameNICSet(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// domainNICSet is the NICs of a domain definition: MAC → bridge.
func domainNICSet(t *testing.T, domXML string) map[string]string {
	t.Helper()
	var d struct {
		Interfaces []struct {
			MAC struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Source struct {
				Bridge string `xml:"bridge,attr"`
			} `xml:"source"`
		} `xml:"devices>interface"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, domXML)
	}
	out := map[string]string{}
	for _, i := range d.Interfaces {
		out[strings.ToLower(i.MAC.Address)] = i.Source.Bridge
	}
	return out
}

// bridgesOf maps a MAC → network set to MAC → the isolated bridge.
func bridgesOf(nics map[string]string) map[string]string {
	out := map[string]string{}
	for mac, net := range nics {
		out[mac] = network.IsolatedBridgeName(net)
	}
	return out
}

func guardedSet(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	macs, err := corrosion.GuardedMACsOf(context.Background(), n.DB, vm)
	if err != nil {
		t.Fatalf("GuardedMACsOf(%s): %v", vm, err)
	}
	sort.Strings(macs)
	return macs
}

func wantMACs(nics map[string]string) []string {
	var out []string
	for m := range nics {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// pinTo rewrites vm's stored placement to host, so a failover places it there.
func pinTo(t *testing.T, n *Node, vm, host string) {
	t.Helper()
	ctx := context.Background()
	rec, err := corrosion.GetVM(ctx, n.DB, vm)
	if err != nil || rec == nil {
		t.Fatalf("GetVM %s: %+v %v", vm, rec, err)
	}
	var spec map[string]any
	if err := json.Unmarshal([]byte(rec.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	spec["placement"] = map[string]any{"host": host}
	b, _ := json.Marshal(spec)
	if err := n.DB.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?`, string(b), n.DB.NowTS(), vm); err != nil {
		t.Fatal(err)
	}
}

func assertGuardsOf(t *testing.T, nft *recordingNft, live map[string]string, gone ...string) {
	t.Helper()
	table := nft.nicTable()
	for mac := range live {
		if !strings.Contains(table, "chain guard_"+nictap.Name(mac)+" {") {
			t.Errorf("no guard chain in force for live NIC %s:\n%s", mac, table)
		}
	}
	for _, mac := range gone {
		if strings.Contains(table, "chain guard_"+nictap.Name(mac)+" {") {
			t.Errorf("a guard chain is rendered for detached NIC %s", mac)
		}
	}
}

func testFailoverKeepsLiveNICs(t *testing.T, latched bool) {
	c, _ := mergedNICsCluster(t, latched)
	ctx := context.Background()
	// The networks were created through Nodes[0], which provisioned them
	// there; the survivor is a host that has none of them yet.
	coord, home, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	nft := wireNodeFirewall(t, other)
	wireNodeFirewall(t, home)

	cMAC := hotplugged(t, c, home, "web")
	live := map[string]string{mnA: "na", cMAC: "nc"}
	if got, want := guardedSet(t, home, "web"), wantMACs(live); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("guarded NICs after the hotplug = %v, want %v", got, want)
	}

	pinTo(t, coord, "web", other.Name)
	if got := fenceVictim(t, c, coord, home, other, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "web"); vm == nil || vm.HostName != other.Name {
		t.Fatalf("web after the failover = %+v, want it on %s", vm, other.Name)
	}
	rec := health.NewReconciler(other.Name, t.TempDir(), other.DB, other.Virt)
	rec.SetNetworkProvision(other.Net.Provision)
	rec.ReconcileOnce(ctx)

	if vm, _ := corrosion.GetVM(ctx, coord.DB, "web"); vm == nil || vm.State != "running" {
		t.Fatalf("web = %+v, want it running on %s", vm, other.Name)
	}
	if got, want := domainNICSet(t, other.Virt.DefinedXML("web")), bridgesOf(live); !sameNICSet(got, want) {
		t.Errorf("web's domain on %s has NICs %v, want exactly the live ones %v", other.Name, got, want)
	}
	if _, up := other.Net.Up("nb"); up {
		t.Errorf("nb, the network of the detached NIC only, was provisioned on %s", other.Name)
	}
	if _, up := other.Net.Up("nc"); !up {
		t.Errorf("nc, the network of the hot-attached NIC, was not provisioned on %s", other.Name)
	}
	if got, want := guardedSet(t, other, "web"), wantMACs(live); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("guarded NICs after the failover = %v, want %v", got, want)
	}
	assertGuardsOf(t, nft, live, mnB)
}

func TestFleet_FailoverKeepsHotpluggedNICs_Latched(t *testing.T) {
	testFailoverKeepsLiveNICs(t, true)
}

func TestFleet_FailoverKeepsHotpluggedNICs_Unlatched(t *testing.T) {
	testFailoverKeepsLiveNICs(t, false)
}

func testUpdateVMKeepsLiveNICs(t *testing.T, latched bool) {
	c, refresh := mergedNICsCluster(t, latched)
	ctx := context.Background()
	home := c.Nodes[1]
	nft := wireNodeFirewall(t, home)

	cMAC := hotplugged(t, c, home, "web")
	live := map[string]string{mnA: "na", cMAC: "nc"}
	if _, err := c.SelfClient(home).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	// A guest-agent change is not patched in place: the definition is
	// regenerated from stored state.
	on := true
	if _, err := c.SelfClient(home).UpdateVM(ctx, &pb.UpdateVMRequest{Name: "web", GuestAgent: &on}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	if got, want := domainNICSet(t, home.Virt.DefinedXML("web")), bridgesOf(live); !sameNICSet(got, want) {
		t.Errorf("web's regenerated domain has NICs %v, want exactly the live ones %v", got, want)
	}
	refresh()
	if _, err := c.SelfClient(home).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM after the update: %v", err)
	}
	if got, want := guardedSet(t, home, "web"), wantMACs(live); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("guarded NICs = %v, want %v", got, want)
	}
	assertGuardsOf(t, nft, live, mnB)
}

func TestFleet_UpdateVMRegenerateKeepsHotpluggedNICs_Latched(t *testing.T) {
	testUpdateVMKeepsLiveNICs(t, true)
}

func TestFleet_UpdateVMRegenerateKeepsHotpluggedNICs_Unlatched(t *testing.T) {
	testUpdateVMKeepsLiveNICs(t, false)
}

func testMigrateProvisionsLiveNICNetworks(t *testing.T, latched bool) {
	c, refresh := mergedNICsCluster(t, latched)
	src, dst := c.Nodes[1], c.Nodes[2]
	wireNodeFirewall(t, src)
	dstNft := wireNodeFirewall(t, dst)

	cMAC := hotplugged(t, c, src, "web")
	live := map[string]string{mnA: "na", cMAC: "nc"}
	refresh()
	if err := migrateAt(t, c, src, "web", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, up := dst.Net.Up("nc"); !up {
		t.Errorf("nc, the network of the hot-attached NIC, was not provisioned on the target %s", dst.Name)
	}
	if _, up := dst.Net.Up("nb"); up {
		t.Errorf("nb, the network of the detached NIC only, was provisioned on the target %s", dst.Name)
	}
	assertGuardsOf(t, dstNft, live, mnB)
}

func TestFleet_MigrateProvisionsHotpluggedNICNetworks_Latched(t *testing.T) {
	testMigrateProvisionsLiveNICNetworks(t, true)
}

func TestFleet_MigrateProvisionsHotpluggedNICNetworks_Unlatched(t *testing.T) {
	testMigrateProvisionsLiveNICNetworks(t, false)
}

// An attach that fails and is rolled back leaves no guard record for its NIC:
// a record for a NIC that is in no domain and no row can never be in force,
// and the VM's next start would refuse for want of it.
func testFailedAttachLeavesNoGuard(t *testing.T, latched bool) {
	c, refresh := mergedNICsCluster(t, latched)
	ctx := context.Background()
	home := c.Nodes[1]
	nft := wireNodeFirewall(t, home)
	if _, err := c.SelfClient(home).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: home.Name},
		Network: []*pb.NetworkAttachment{{Name: "na", Mac: mnA}},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	var tried string
	home.Virt.FailAttachNIC = func(_, _, _, mac string) error {
		tried = strings.ToLower(mac)
		return errors.New("live attach refused by the hypervisor")
	}
	if _, err := attachNIC(c, home, "web", "nc"); err == nil {
		t.Fatal("an attach whose live hotplug fails reported success")
	}
	home.Virt.FailAttachNIC = nil
	if tried == "" {
		t.Fatal("fixture: the attach never reached the live hotplug")
	}
	live := map[string]string{mnA: "na"}
	if got, want := guardedSet(t, home, "web"), wantMACs(live); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("guarded NICs after the rolled-back attach = %v, want %v", got, want)
	}
	if _, err := c.SelfClient(home).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	refresh()
	if _, err := c.SelfClient(home).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM after the rolled-back attach: %v", err)
	}
	assertGuardsOf(t, nft, live, tried)
}

func TestFleet_FailedNICAttachLeavesNoGuardRecord_Latched(t *testing.T) {
	testFailedAttachLeavesNoGuard(t, true)
}

func TestFleet_FailedNICAttachLeavesNoGuardRecord_Unlatched(t *testing.T) {
	testFailedAttachLeavesNoGuard(t, false)
}

// A same-name promotion (a takeover) keeps the VM's NIC rows and guard
// records, so it boots exactly the live NICs: the spec still lists the
// detached NIC, whose guard record is retired, and booting it would put a NIC
// on the wire that no guard covers.
func testPromoteKeepsLiveNICs(t *testing.T, latched bool) {
	c, refresh := mergedNICsCluster(t, latched)
	ctx := context.Background()
	home := c.Nodes[1]
	nft := wireNodeFirewall(t, home)

	cMAC := hotplugged(t, c, home, "web")
	live := map[string]string{mnA: "na", cMAC: "nc"}
	if _, err := c.SelfClient(home).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	dr := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, home.DB, corrosion.StoragePoolRecord{
		HostName: home.Name, Name: "dr", Driver: "dir", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	const replica = "web-root-20261001-000000.qcow2"
	for _, p := range []string{disk, filepath.Join(dr, replica)} {
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertDisk(ctx, home.DB, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: home.Name, Path: disk, StorageType: "local",
	}); err != nil {
		t.Fatal(err)
	}
	refresh()
	st, err := c.SelfClient(home).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", Replica: replica, NoLocalize: true, Force: true,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if err != io.EOF {
		t.Fatalf("promote web: %v", err)
	}
	got := domainNICSet(t, home.Virt.DefinedXML("web"))
	if strings.Join(wantMACs(got), ",") != strings.Join(wantMACs(live), ",") {
		t.Errorf("web's promoted domain has NICs %v, want exactly the live ones %v", got, live)
	}
	if got, want := guardedSet(t, home, "web"), wantMACs(live); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("guarded NICs = %v, want %v", got, want)
	}
	assertGuardsOf(t, nft, live, mnB)
}

func TestFleet_PromoteTakeoverKeepsHotpluggedNICs_Latched(t *testing.T) {
	testPromoteKeepsLiveNICs(t, true)
}

func TestFleet_PromoteTakeoverKeepsHotpluggedNICs_Unlatched(t *testing.T) {
	testPromoteKeepsLiveNICs(t, false)
}
