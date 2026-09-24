package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

const composeRetarget = `name: hc

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    network:
      - name: hc
`

// seedLegacyStackVM creates db the way a build before the compose fix did: its
// NIC on the stack-scoped network "hc_hc", which has no record, so it landed on
// a flat bridge of that name. The spec is otherwise exactly what the file
// builds today, so the ONLY difference a re-deploy sees is the NIC's network.
func seedLegacyStackVM(t *testing.T, ctx context.Context, client pb.LiteVirtClient, host string) *pb.VMSpec {
	t.Helper()
	f, err := compose.ParseBytes([]byte(composeRetarget))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	vm := f.VMs["db"]
	spec, err := compose.BuildVMSpec("db", "db", &vm, f)
	if err != nil {
		t.Fatalf("BuildVMSpec: %v", err)
	}
	spec.Network[0].Name = "hc_hc"
	if host != "" {
		spec.Placement = &pb.PlacementSpec{Host: host}
	}
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil {
		t.Fatalf("CreateVM (legacy shape): %v", err)
	}
	return spec
}

// A move whose old network is a real record is not the legacy flat-bridge
// case. The deploy refuses it for that VM and leaves the VM exactly as it was
// — it neither moves the NIC nor falls through to a recreate.
func TestFleet_ComposeRedeployRefusesToMoveANICOffARealNetwork(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)

	for _, name := range []string{"hc", "hc_hc"} {
		if _, err := client.CreateNetwork(ctx, &pb.CreateNetworkRequest{
			Name: name, Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
		}); err != nil {
			t.Fatalf("CreateNetwork %s: %v", name, err)
		}
	}
	seedLegacyStackVM(t, ctx, client, "")
	before, _ := corrosion.GetVM(ctx, node.DB, "db")
	eventsBefore := len(node.Virt.EventLog())

	msgs := deployCollect(t, ctx, client, composeRetarget)
	p := errorPhaseFor(msgs, "db")
	if p == nil || !strings.Contains(p.Error, "is a real network") {
		t.Fatalf("deploy moving db's NIC off the real network hc_hc: error=%+v, want a refusal saying hc_hc is a real network", p)
	}
	after, _ := corrosion.GetVM(ctx, node.DB, "db")
	if after == nil || after.CreatedAt != before.CreatedAt {
		t.Fatalf("db was recreated or removed: before=%+v after=%+v", before, after)
	}
	if evs := node.Virt.EventLog()[eventsBefore:]; len(evs) != 0 {
		t.Errorf("the refused deploy touched db's domain: %+v", evs)
	}
	want := network.IsolatedBridgeName("hc_hc")
	if got := domainBridges(node.Virt.DefinedXML("db")); len(got) != 1 || got[0] != want {
		t.Errorf("db attaches to %v, want it left on [%s]", got, want)
	}
	if nics, _ := corrosion.MergedVMNICs(ctx, node.DB, "db"); len(nics) != 1 || nics[0].NetworkName != "hc_hc" {
		t.Errorf("db NICs = %+v, want it left on hc_hc", nics)
	}
}

// The VM's own host does the host half of a move recorded elsewhere: a deploy
// entered on another node writes the move into the VM's spec, and the owner's
// network pass re-plugs the NIC and rewrites its rows once that reaches it. A
// flat bridge that still has a port is left alone.
func TestFleet_OwnerPassFinishesANICMoveRecordedOnAnotherNode(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	n0, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	owner.Server.SetBridgeEnsure(owner.Net.EnsureBridge)
	if err := writeEmptyImageFile(owner.Server.ImagePathForTests("test")); err != nil {
		t.Fatalf("stage image: %v", err)
	}
	if err := owner.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if _, err := c.SelfClient(owner).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	seedLegacyStackVM(t, ctx, c.SelfClient(owner), owner.Name)
	mac := func() string {
		nics, _ := corrosion.MergedVMNICs(ctx, owner.DB, "db")
		return nics[0].MAC
	}()

	// The deploy node's half, as it lands in the replicated state: the spec
	// names "hc" where the rows still say "hc_hc".
	n0.DB.MergeStateBytesLWW(pullDump(t, c, owner))
	if _, _, err := corrosion.MutateDesiredSpec(ctx, n0.DB, "db", func(old string) (string, error) {
		return strings.Replace(old, `"hc_hc"`, `"hc"`, 1), nil
	}); err != nil {
		t.Fatalf("record the move on %s: %v", n0.Name, err)
	}

	// Before the owner hears of it, its pass has nothing to do.
	reconcileNetworks(t, owner)
	if got := domainBridges(owner.Virt.DefinedXML("db")); len(got) != 1 || got[0] != "hc_hc" {
		t.Fatalf("db moved before the move reached its host: %v", got)
	}

	// A bridge an unscoped NIC used and left: empty and unreferenced, but not
	// "<stack>_<name>", so it is not litevirt's to remove.
	if err := owner.Net.EnsureBridge("lan0"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertInterface(ctx, owner.DB, corrosion.InterfaceRecord{
		VMName: "ghost", NetworkName: "lan0", Ordinal: 0, MAC: "52:54:00:00:00:99",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SoftDeleteInterfaceByMAC(ctx, owner.DB, "ghost", "52:54:00:00:00:99"); err != nil {
		t.Fatal(err)
	}

	owner.DB.MergeStateBytesLWW(pullDump(t, c, n0))
	owner.Net.SetBridgeBusy("hc_hc", true)
	reconcileNetworks(t, owner)

	want := network.IsolatedBridgeName("hc")
	if got := domainBridges(owner.Virt.DefinedXML("db")); len(got) != 1 || got[0] != want {
		t.Errorf("db attaches to %v after the owner's pass, want [%s]", got, want)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, owner.DB, "db")
	if len(nics) != 1 || nics[0].NetworkName != "hc" || !strings.EqualFold(nics[0].MAC, mac) {
		t.Errorf("db NICs = %+v, want one on hc with MAC %s", nics, mac)
	}
	if !containsString(owner.Net.FlatBridges(), "hc_hc") {
		t.Errorf("hc_hc was removed while it still had a port")
	}

	// Once it is empty, the next pass removes it.
	owner.Net.SetBridgeBusy("hc_hc", false)
	reconcileNetworks(t, owner)
	if containsString(owner.Net.FlatBridges(), "hc_hc") {
		t.Errorf("the empty flat bridge hc_hc was not removed by the pass")
	}
	if !containsString(owner.Net.FlatBridges(), "lan0") {
		t.Errorf("lan0, which is not a stack-scoped name, was removed")
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// A stack deployed before the compose fix must not lose its VM when the same
// file is applied again. The NIC moves from the flat "hc_hc" bridge to the
// cluster network's br-iso-hc in place: same domain, same MAC, same disks,
// and the flat bridge nothing uses any more is removed.
func TestFleet_ComposeRedeployMovesALegacyStackNICInPlace(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)

	if _, err := client.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	seedLegacyStackVM(t, ctx, client, "")
	before, err := corrosion.GetVM(ctx, node.DB, "db")
	if err != nil || before == nil {
		t.Fatalf("legacy db: %+v %v", before, err)
	}
	beforeNICs, _ := corrosion.MergedVMNICs(ctx, node.DB, "db")
	if len(beforeNICs) != 1 || beforeNICs[0].NetworkName != "hc_hc" {
		t.Fatalf("legacy db NICs = %+v, want one on hc_hc", beforeNICs)
	}
	mac := beforeNICs[0].MAC
	if got := domainBridges(node.Virt.DefinedXML("db")); len(got) != 1 || got[0] != "hc_hc" {
		t.Fatalf("legacy db attaches to %v, want [hc_hc]", got)
	}
	eventsBefore := len(node.Virt.EventLog())

	msgs := deployCollect(t, ctx, client, composeRetarget)
	if p := errorPhaseFor(msgs, "db"); p != nil {
		t.Fatalf("redeploy of db failed: %s", p.Error)
	}

	after, err := corrosion.GetVM(ctx, node.DB, "db")
	if err != nil || after == nil {
		t.Fatalf("db after redeploy: %+v %v", after, err)
	}
	if after.CreatedAt != before.CreatedAt {
		t.Errorf("db was recreated (created_at %s → %s)", before.CreatedAt, after.CreatedAt)
	}
	for _, e := range node.Virt.EventLog()[eventsBefore:] {
		if e.Op == "undefine" || e.Op == "destroy" || e.Op == "define" {
			t.Errorf("redeploy ran libvirt %s on %s — a NIC move must not redefine or destroy the VM", e.Op, e.Domain)
		}
	}
	want := network.IsolatedBridgeName("hc")
	if got := domainBridges(node.Virt.DefinedXML("db")); len(got) != 1 || got[0] != want {
		t.Errorf("db attaches to %v after redeploy, want [%s]", got, want)
	}
	if !strings.Contains(strings.ToLower(node.Virt.DefinedXML("db")), strings.ToLower(mac)) {
		t.Errorf("db's NIC lost its MAC %s", mac)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, node.DB, "db")
	if len(nics) != 1 || nics[0].NetworkName != "hc" || !strings.EqualFold(nics[0].MAC, mac) {
		t.Errorf("db NICs after redeploy = %+v, want one on hc with MAC %s", nics, mac)
	}
	for _, b := range node.Net.FlatBridges() {
		if b == "hc_hc" {
			t.Errorf("the flat bridge hc_hc is still there with nothing on it")
		}
	}

	// The same file again is no change at all.
	msgs = deployCollect(t, ctx, client, composeRetarget)
	for _, p := range msgs {
		if p.VmName == "db" && (p.Phase == "applying" || p.Phase == "error") {
			t.Errorf("second redeploy touched db: %s %s %s", p.Phase, p.Detail, p.Error)
		}
	}
}
