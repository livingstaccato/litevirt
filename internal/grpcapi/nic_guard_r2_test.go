package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedReplacedVM writes the VM a recreate replaces — its row, with a spec
// naming its uuid and networks — and returns ctx carrying it, as a rebuild or
// a rolling update does.
func seedReplacedVM(t *testing.T, s *Server, ctx context.Context, name, spec string) context.Context {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: name, HostName: s.hostName, Spec: spec, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	return withReplacedVM(ctx, vm)
}

// TestAdmitNICGuards_RecreateMatchesSameNIC (re-review I-7): a recreate may
// carry a relaxation only onto the NIC it was granted for. A relaxation one
// NIC had on a network the caller governs must not let another NIC, on a
// shared network the caller does not, carry the same relaxation unchecked.
func TestAdmitNICGuards_RecreateMatchesSameNIC(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "priv", Type: "bridge", Config: `{"Subnet":"10.7.0.0/24"}`, Project: "team"}); err != nil {
		t.Fatal(err)
	}
	bob := sgBindUser(t, s, "bob", "team")
	rctx := seedReplacedVM(t, s, bob, "web", `{"name":"web","uuid":"u-1","network":[{"name":"priv"},{"name":"lan"}]}`)
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOff}, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:02",
		Mode: corrosion.NICGuardOn}, "bob"); err != nil {
		t.Fatal(err)
	}
	atts := []*pb.NetworkAttachment{
		{Name: "priv", Mac: "52:54:00:00:00:01", SpoofGuard: "off"},
		{Name: "lan", Mac: "52:54:00:00:00:02", SpoofGuard: "off"},
	}
	if _, err := s.admitNICGuards(rctx, "web", atts, admitRecreate); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a recreate turning off the shared-network NIC's guard on the strength of the other NIC's record: %v, want PermissionDenied", err)
	}
}

// TestCheckNICIdentities_ReadErrorsAreInternal (re-review m-b): a local read
// failing before a mutation is a server fault, whichever read it is.
func TestCheckNICIdentities_ReadErrorsAreInternal(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := s.db.Execute(ctx, `DROP TABLE cluster_policies`); err != nil {
		t.Fatal(err)
	}
	err := s.checkNICIdentities(ctx, "", []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:00:09"}}, "vm")
	if status.Code(err) != codes.Internal {
		t.Errorf("guard read failure: %v, want Internal", err)
	}
	s2 := guardServer(t, true)
	if err := s2.db.Execute(ctx, `DROP TABLE vm_nics`); err != nil {
		t.Fatal(err)
	}
	err = s2.checkNICIdentities(ctx, "", []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:00:09"}}, "vm")
	if status.Code(err) != codes.Internal {
		t.Errorf("identity read failure: %v, want Internal", err)
	}
}

// TestDHCPReservable_OnlyWhereServedHereAlone (re-review I-8): an exact
// reservation is made only where this host's dnsmasq is the network's one
// DHCP server — a host-local bridge, an isolated network. On vxlan another
// host serves, and on a bridge with an uplink another server may answer
// first: the guest would take an address its exact guard drops, for the whole
// lease. There the guard stays confined to the subnet.
func TestDHCPReservable_OnlyWhereServedHereAlone(t *testing.T) {
	s := guardServer(t, true)
	s.dhcpServedHere = func(string) bool { return true }
	s.bridgeHasUplink = func(string) bool { return false }
	att := &pb.NetworkAttachment{Name: "lan"}
	vx := &compose.NetworkDef{Type: "vxlan", VNI: 10, Subnet: "10.9.0.0/24", DHCP: true}
	if s.dhcpReservable(att, vx) {
		t.Error("a vxlan network got an exact reservation on a host that may not serve it")
	}
	br := &compose.NetworkDef{Type: "bridge", Subnet: "10.9.0.0/24", DHCP: true}
	if !s.dhcpReservable(att, br) {
		t.Error("a host-local bridge served here got no reservation")
	}
	s.bridgeHasUplink = func(string) bool { return true }
	if s.dhcpReservable(att, br) {
		t.Error("a bridge with an uplink, where another server may answer first, got an exact reservation")
	}
	s.bridgeHasUplink = func(string) bool { return false }
	s.dhcpServedHere = func(string) bool { return false }
	if s.dhcpReservable(att, br) {
		t.Error("a bridge this host's dnsmasq does not serve got a reservation")
	}
}

// TestCheckNICIdentities_GatewayFromConfig (re-review I-9): the address a NIC
// may not claim as the network's router is the network's configured gateway,
// its reserved addresses and the gateway other tenants' NICs route through —
// not network+1, which on a network litevirt does not route for is an
// ordinary host address.
func TestCheckNICIdentities_GatewayFromConfig(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "ext", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"br0","Subnet":"10.5.0.0/24","External":true,"Gateway":"10.5.0.254","ReservedAddresses":["10.5.0.253"]}`}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "other", HostName: s.hostName, State: "running", Project: "acme",
		Spec: `{"name":"other","network":[{"name":"ext","ip":"10.5.0.20","gateway":"10.5.0.250"}]}`},
		[]corrosion.InterfaceRecord{{VMName: "other", NetworkName: "ext", MAC: "52:54:00:00:00:20", IP: "10.5.0.20"}}, nil); err != nil {
		t.Fatal(err)
	}
	bob := sgBindUser(t, s, "bob", "team") // no authority over the shared network
	for name, c := range map[string]struct {
		ip   string
		code codes.Code
	}{
		"the configured gateway":           {"10.5.0.254", codes.InvalidArgument},
		"a reserved address":               {"10.5.0.253", codes.InvalidArgument},
		"another tenant's NIC gateway":     {"10.5.0.250", codes.InvalidArgument},
		"network+1, an ordinary host here": {"10.5.0.1", codes.OK},
		"a free address":                   {"10.5.0.30", codes.OK},
	} {
		if err := s.checkNICIdentities(bob, "team", []*pb.NetworkAttachment{{Name: "ext", Ip: c.ip}}, "attacker"); status.Code(err) != c.code {
			t.Errorf("%s (%s): %v, want %v", name, c.ip, err, c.code)
		}
	}
	// The gateway VMs of its own project route through is a project's own
	// router to run.
	if err := s.checkNICIdentities(bob, "acme", []*pb.NetworkAttachment{{Name: "ext", Ip: "10.5.0.250"}}, "router"); err != nil {
		t.Errorf("a project claiming the gateway its own VMs route through: %v", err)
	}
}

// TestSeedFirewallEnforcementLoop_FounderDecisionOnly (re-review I-3): only a
// founder's genesis decision is ever seeded; with no decision on disk (a
// joiner, a rejoiner, an upgraded host) nothing is written and the cluster
// observes until `lv firewall enforce`. The seed is audited and consumes the
// decision.
func TestSeedFirewallEnforcementLoop_FounderDecisionOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := guardServer(t, true)
	dir := t.TempDir()
	decision := filepath.Join(dir, "firewall-initial-mode")
	s.SeedFirewallEnforcementLoop(ctx, 10*time.Millisecond, decision)
	if e, _ := corrosion.GetFirewallEnforcement(ctx, s.db); e.Recorded {
		t.Fatalf("seeded %+v with no founder decision", e)
	}
	if err := os.WriteFile(decision, []byte("enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SeedFirewallEnforcementLoop(ctx, 10*time.Millisecond, decision)
	e, err := corrosion.GetFirewallEnforcement(ctx, s.db)
	if err != nil || !e.Recorded || e.Mode != corrosion.FirewallEnforce {
		t.Fatalf("founder decision not seeded: %+v, %v", e, err)
	}
	if _, err := os.Stat(decision); !os.IsNotExist(err) {
		t.Errorf("the decision outlived its seed: %v", err)
	}
	rows, err := s.db.Query(ctx, `SELECT COUNT(*) AS n FROM audit_log WHERE action = 'firewall.enforcement'`)
	if err != nil || rows[0].Int("n") != 1 {
		t.Errorf("the seed was not audited: %v %v", rows, err)
	}
}

// TestGuardDecision_TrunkNICKeepsTheDefaultGuard (re-review R2-I1): a NIC on
// the `trunk:` feature is guarded like any other new NIC — declaring a trunk
// is no way around the guard. Which VLANs it carries is the network's to
// allow, not the tenant's.
func TestGuardDecision_TrunkNICKeepsTheDefaultGuard(t *testing.T) {
	var d guardDecision
	trunk := &pb.NetworkAttachment{Name: "core", Trunk: []int32{100, 101}}
	if r := d.record("rt", "u", 0, "52:54:00:00:00:01", trunk); r == nil || !r.Guarded() || !d.guarded(trunk) {
		t.Errorf("a new trunk NIC got no guard: %+v", r)
	}
	if _, err := guardServer(t, true).admitNICGuards(context.Background(), "rt", []*pb.NetworkAttachment{trunk}, admitNew); err != nil {
		t.Errorf("a trunk NIC that asks for nothing more needs no authority to be created: %v", err)
	}
}

// fakeArmer is a firewall reconciler whose passes fail on demand.
type fakeArmer struct {
	fakeReconciler
	err   error
	armed []string
}

func (f *fakeArmer) Arm(_ context.Context, vm string) error {
	f.armed = append(f.armed, vm)
	return f.err
}
func (f *fakeArmer) SetPending(string, []corrosion.HostVMNIC) {}
func (f *fakeArmer) ClearPending(string)                      {}

// TestArmNICsFor_FailsClosedForGuardedVMs (re-review I-10): a VM whose NIC
// guard is on is not run where its guard could not be put in force; a VM with
// no guard runs as it did before guards existed.
func TestArmNICsFor_FailsClosedForGuardedVMs(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	a := &fakeArmer{err: errors.New("the kernel refused the per-NIC table")}
	s.SetFirewallReconciler(a)
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "guarded", MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.ArmNICsFor(ctx, "guarded"); err == nil {
		t.Error("a guarded VM was cleared to run with its guard not in force")
	}
	if err := s.ArmNICsFor(ctx, "plain"); err != nil {
		t.Errorf("a VM with no guard was refused: %v", err)
	}
	a.err = nil
	// Two passes: the unguarded VM ran none (re-review m3).
	if err := s.ArmNICsFor(ctx, "guarded"); err != nil || len(a.armed) != 2 {
		t.Errorf("after the pass succeeds: %v (armed %v)", err, a.armed)
	}
}
