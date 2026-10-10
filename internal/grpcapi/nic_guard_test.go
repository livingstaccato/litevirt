package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func guardServer(t *testing.T, open bool) *Server {
	t.Helper()
	s := testServer(t)
	if open {
		s.db.SetClusterPolicyGate(func() bool { return true })
	}
	return s
}

// TestAdmitNICGuards pins who may create a NIC with which guard: the default
// needs nothing (and is created unguarded while records cannot be written); an
// explicit setting is refused rather than dropped while records cannot be
// written; a weakening one needs network.update over the NIC's network, which
// a NetworkAdmin of one project holds for a network that project owns and not
// for a shared one.
func TestAdmitNICGuards(t *testing.T) {
	att := func(netName string, f func(*pb.NetworkAttachment)) []*pb.NetworkAttachment {
		a := &pb.NetworkAttachment{Name: netName}
		f(a)
		return []*pb.NetworkAttachment{a}
	}
	def := att("lan", func(*pb.NetworkAttachment) {})
	off := att("lan", func(a *pb.NetworkAttachment) { a.SpoofGuard = "off" })
	on := att("lan", func(a *pb.NetworkAttachment) { a.SpoofGuard = "on" })

	closed := guardServer(t, false)
	if err := closed.admitNICGuards(adminCtx(), "vm", def, admitNew); err != nil {
		t.Errorf("default guard with the store closed: %v", err)
	}
	if err := closed.admitNICGuards(adminCtx(), "vm", on, admitNew); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("explicit guard with the store closed: %v, want FailedPrecondition", err)
	}

	s := guardServer(t, true)
	if err := s.admitNICGuards(adminCtx(), "vm", off, admitNew); err != nil {
		t.Errorf("admin turning a guard off: %v", err)
	}
	for name, bad := range map[string][]*pb.NetworkAttachment{
		"mode":    att("lan", func(a *pb.NetworkAttachment) { a.SpoofGuard = "strict" }),
		"address": att("lan", func(a *pb.NetworkAttachment) { a.AllowedAddresses = []string{"10.0.0.1; drop"} }),
	} {
		if err := s.admitNICGuards(adminCtx(), "vm", bad, admitNew); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}

	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{
		Name: "teamnet", Type: "bridge", Config: `{"Subnet":"10.7.0.0/24"}`, Project: "team"}); err != nil {
		t.Fatal(err)
	}
	project := sgBindUser(t, s, "bob", "team")
	for name, weak := range map[string]func(*pb.NetworkAttachment){
		"off":     func(a *pb.NetworkAttachment) { a.SpoofGuard = "off" },
		"allowed": func(a *pb.NetworkAttachment) { a.AllowedAddresses = []string{"10.0.0.250"} },
		"dhcp":    func(a *pb.NetworkAttachment) { a.AllowDhcpServer = true },
		"ra":      func(a *pb.NetworkAttachment) { a.AllowRouterAdvertisement = true },
		"vlan":    func(a *pb.NetworkAttachment) { a.AllowVlanTags = true },
	} {
		if err := s.admitNICGuards(project, "vm", att("lan", weak), admitNew); status.Code(err) != codes.PermissionDenied {
			t.Errorf("a project's NetworkAdmin weakening (%s) on a shared network: %v, want PermissionDenied", name, err)
		}
		if err := s.admitNICGuards(project, "vm", att("teamnet", weak), admitNew); err != nil {
			t.Errorf("a project's NetworkAdmin weakening (%s) on its own network: %v", name, err)
		}
	}
	if err := s.admitNICGuards(project, "vm", on, admitNew); err != nil {
		t.Errorf("project NetworkAdmin asking for the default guard: %v", err)
	}
}

// TestAdmitNICGuards_RecreateCarriesOnlyWhatItHad (review I5a): a re-create
// (rebuild, a stack's rolling update) may carry a relaxed guard the VM already
// had without authority — but not a new relaxation slipped into the new spec.
func TestAdmitNICGuards_RecreateCarriesOnlyWhatItHad(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOff}, "admin"); err != nil {
		t.Fatal(err)
	}
	bob := sgBindUser(t, s, "bob", "_default")
	same := []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}
	if err := s.admitNICGuards(bob, "web", same, admitRecreate); err != nil {
		t.Errorf("re-create carrying the guard it had: %v", err)
	}
	more := []*pb.NetworkAttachment{{Name: "lan", AllowedAddresses: []string{"10.0.0.7"}}}
	if err := s.admitNICGuards(bob, "web", more, admitRecreate); status.Code(err) != codes.PermissionDenied {
		t.Errorf("re-create adding a relaxation: %v, want PermissionDenied", err)
	}
}

// TestAdmitNICGuards_PeerOwnerBeforeRelease (review I5b): an owner leg trusts
// the entry node's authority check only once every host is a build that
// makes it; before, a forwarded relaxation is refused.
func TestAdmitNICGuards_PeerOwnerBeforeRelease(t *testing.T) {
	s := guardServer(t, true)
	off := []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}
	if err := s.admitNICGuards(adminCtx(), "vm", off, admitPeerOwner); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("forwarded relaxation before the release latch: %v, want FailedPrecondition", err)
	}
	s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{capabilities.FirewallIPv6V1: true}})
	if err := s.admitNICGuards(adminCtx(), "vm", off, admitPeerOwner); err != nil {
		t.Errorf("forwarded relaxation after the release latch: %v", err)
	}
}

// TestCheckNICIdentities (review C4): an explicit MAC, IPv4 or IPv6 address
// another live NIC holds is refused, as is a subnet's own address; the
// re-created VM's own rows do not count.
func TestCheckNICIdentities(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge",
		Config: `{"Subnet":"10.9.0.0/24","DHCP":true}`}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "victim", HostName: s.hostName, Spec: "{}", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "victim", NetworkName: "lan", MAC: "52:54:00:00:00:aa", IP: "10.9.0.5"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, corrosion.NICGuardRecord{VMName: "victim", MAC: "52:54:00:00:00:aa",
		Mode: corrosion.NICGuardOn, Known: []string{"fd00::5"}}, "x"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		att  *pb.NetworkAttachment
		code codes.Code
	}{
		"victim's MAC":   {&pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:00:00:AA"}, codes.AlreadyExists},
		"victim's IPv4":  {&pb.NetworkAttachment{Name: "lan", Ip: "10.9.0.5/24"}, codes.AlreadyExists},
		"victim's IPv6":  {&pb.NetworkAttachment{Name: "lan", Ipv6: "fd00::5/64"}, codes.AlreadyExists},
		"the gateway":    {&pb.NetworkAttachment{Name: "lan", Ip: "10.9.0.1"}, codes.InvalidArgument},
		"the broadcast":  {&pb.NetworkAttachment{Name: "lan", Ip: "10.9.0.255"}, codes.InvalidArgument},
		"a free address": {&pb.NetworkAttachment{Name: "lan", Ip: "10.9.0.6", Mac: "52:54:00:00:00:bb"}, codes.OK},
	} {
		if err := s.checkNICIdentities(ctx, []*pb.NetworkAttachment{c.att}, "attacker"); status.Code(err) != c.code {
			t.Errorf("%s: %v, want %v", name, err, c.code)
		}
	}
	if err := s.checkNICIdentities(ctx, []*pb.NetworkAttachment{{Name: "lan", Ip: "10.9.0.5", Mac: "52:54:00:00:00:aa"}}, "victim"); err != nil {
		t.Errorf("the VM's own identity on a re-create: %v", err)
	}
}

// TestReserveDHCPAddress (ruling 7): a guarded NIC on a DHCP network gets the
// lowest address no NIC row, lease or in-flight reservation holds — never the
// network address or the gateway.
func TestReserveDHCPAddress(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "a", HostName: s.hostName, Spec: "{}", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "a", NetworkName: "lan", MAC: "52:54:00:00:00:01", IP: "10.9.0.2"}}, nil); err != nil {
		t.Fatal(err)
	}
	first, err := s.reserveDHCPAddress(ctx, "lan", "10.9.0.0/24", "no-such-bridge", "52:54:00:00:00:02")
	if err != nil || first != "10.9.0.3" {
		t.Fatalf("first reservation = %q, %v; want 10.9.0.3", first, err)
	}
	second, err := s.reserveDHCPAddress(ctx, "lan", "10.9.0.0/24", "no-such-bridge", "52:54:00:00:00:03")
	if err != nil || second != "10.9.0.4" {
		t.Fatalf("second reservation = %q, %v; want 10.9.0.4 (the first is in flight)", second, err)
	}
	def := &compose.NetworkDef{Type: "bridge", Subnet: "10.9.0.0/24", DHCP: true}
	if !s.dhcpReservable(&pb.NetworkAttachment{Name: "lan"}, def) {
		t.Error("a default (guarded) NIC on a DHCP network is not reservable")
	}
	if s.dhcpReservable(&pb.NetworkAttachment{Name: "lan", SpoofGuard: "off"}, def) ||
		s.dhcpReservable(&pb.NetworkAttachment{Name: "lan", Ip: "10.9.0.9"}, def) {
		t.Error("an unguarded NIC, or one with an explicit address, got a reservation")
	}
}

// TestNewNICGuardRecord: a request becomes the record a new NIC gets; an empty
// spoof_guard is on, and a static IPv6 address is recorded as known.
func TestNewNICGuardRecord(t *testing.T) {
	r := newNICGuardRecord("vm", "52:54:00:aa:bb:cc", &pb.NetworkAttachment{Name: "lan", Ipv6: "2001:db8::5/64"})
	if r.Mode != corrosion.NICGuardOn || len(r.Known) != 1 || r.Known[0] != "2001:db8::5" {
		t.Errorf("record = %+v", r)
	}
	r = newNICGuardRecord("vm", "52:54:00:aa:bb:cc", &pb.NetworkAttachment{SpoofGuard: "OFF"})
	if r.Mode != corrosion.NICGuardOff {
		t.Errorf("mode = %q, want off", r.Mode)
	}
}

// TestSetNICGuard writes the record, audits before and after, and reports the
// addresses the guard lets the NIC use; a project-scoped caller is refused.
func TestSetNICGuard(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, Spec: "{}", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: "52:54:00:00:00:01", IP: "10.0.0.5"}}, nil); err != nil {
		t.Fatal(err)
	}
	admin := adminCtxWithEngine(t, s)
	g, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "on",
		AllowedAddresses: []string{"10.0.0.250"}})
	if err != nil {
		t.Fatalf("SetNICGuard: %v", err)
	}
	if g.Mode != "on" || strings.Join(g.EffectiveIpv4, ",") != "10.0.0.5,10.0.0.250" || !g.Ipv6Unrestricted {
		t.Errorf("guard = %+v", g)
	}
	wantAudit(t, s, "nic.guard.set", "alice", "web",
		"mac=52:54:00:00:00:01 before=unset after={mode=on allowed=[10.0.0.250] dhcp-server=false router-advert=false vlan-tags=false}")

	list, err := s.ListNICGuards(admin, &pb.ListNICGuardsRequest{VmName: "web"})
	if err != nil || len(list.Guards) != 1 || list.Guards[0].Mode != "on" {
		t.Fatalf("ListNICGuards = %+v, %v", list, err)
	}

	bob := sgBindUser(t, s, "bob", "_default")
	if _, err := s.SetNICGuard(bob, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "off"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("project NetworkAdmin turning a guard off: %v, want PermissionDenied", err)
	}
	if rec, _ := corrosion.GetNICGuard(ctx, s.db, "web", "52:54:00:00:00:01"); rec == nil || rec.Mode != "on" {
		t.Errorf("a refused call changed the record: %+v", rec)
	}
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "nope", Mode: "on"}); status.Code(err) != codes.NotFound {
		t.Errorf("no such NIC: %v, want NotFound", err)
	}

	// A macvtap NIC bypasses the bridge: a guard there would protect nothing
	// while `ls` said "on" (review m3).
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "uplink", Type: "direct", Config: `{"Type":"direct"}`}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "mv", HostName: s.hostName, Spec: "{}", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "mv", NetworkName: "uplink", MAC: "52:54:00:00:00:09"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "mv", NetworkName: "uplink", Mode: "on"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("guard on a macvtap NIC: %v, want FailedPrecondition", err)
	}
}

// TestFirewallIPv6Rule_PreconditionUntilLatch: an IPv6 rule written before
// firewall_ipv6_v1 has latched is a precondition failure (retry after the
// upgrade), not a malformed request; once the gate opens it is accepted.
func TestFirewallIPv6Rule_PreconditionUntilLatch(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	req := &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "22", Cidr: "2001:db8::/32"}}
	if _, err := s.CreateClusterFirewallRule(ctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("before the latch: %v, want FailedPrecondition", err)
	}
	if _, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "v6", Cidrs: []string{"fd00::/8"}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ip set before the latch: %v, want FailedPrecondition", err)
	}
	s.db.SetFirewallIPv6Gate(func() bool { return true })
	if _, err := s.CreateClusterFirewallRule(ctx, req); err != nil {
		t.Fatalf("after the latch: %v", err)
	}
}
