package grpcapi

import (
	"context"
	"strings"
	"testing"

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
// written; a weakening one needs cluster-root network authority, which a
// NetworkAdmin of one project does not have — unless it is a re-create carrying
// the guard its authorized original create stored.
func TestAdmitNICGuards(t *testing.T) {
	att := func(f func(*pb.NetworkAttachment)) []*pb.NetworkAttachment {
		a := &pb.NetworkAttachment{Name: "lan"}
		f(a)
		return []*pb.NetworkAttachment{a}
	}
	def := att(func(*pb.NetworkAttachment) {})
	off := att(func(a *pb.NetworkAttachment) { a.SpoofGuard = "off" })
	vip := att(func(a *pb.NetworkAttachment) { a.AllowedAddresses = []string{"10.0.0.250"} })
	on := att(func(a *pb.NetworkAttachment) { a.SpoofGuard = "on" })

	closed := guardServer(t, false)
	if err := closed.admitNICGuards(adminCtx(), def, false); err != nil {
		t.Errorf("default guard with the store closed: %v", err)
	}
	if err := closed.admitNICGuards(adminCtx(), on, false); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("explicit guard with the store closed: %v, want FailedPrecondition", err)
	}

	s := guardServer(t, true)
	if err := s.admitNICGuards(adminCtx(), off, false); err != nil {
		t.Errorf("admin turning a guard off: %v", err)
	}
	for name, bad := range map[string][]*pb.NetworkAttachment{
		"mode":    att(func(a *pb.NetworkAttachment) { a.SpoofGuard = "strict" }),
		"address": att(func(a *pb.NetworkAttachment) { a.AllowedAddresses = []string{"10.0.0.1; drop"} }),
	} {
		if err := s.admitNICGuards(adminCtx(), bad, false); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}

	project := sgBindUser(t, s, "bob", "_default")
	for name, weak := range map[string][]*pb.NetworkAttachment{"off": off, "allowed": vip,
		"dhcp": att(func(a *pb.NetworkAttachment) { a.AllowDhcpServer = true }),
		"ra":   att(func(a *pb.NetworkAttachment) { a.AllowRouterAdvertisement = true })} {
		if err := s.admitNICGuards(project, weak, false); status.Code(err) != codes.PermissionDenied {
			t.Errorf("project NetworkAdmin weakening (%s): %v, want PermissionDenied", name, err)
		}
		if err := s.admitNICGuards(project, weak, true); err != nil {
			t.Errorf("re-create carrying %s: %v", name, err)
		}
	}
	if err := s.admitNICGuards(project, on, false); err != nil {
		t.Errorf("project NetworkAdmin asking for the default guard: %v", err)
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
		"mac=52:54:00:00:00:01 before=unset after={mode=on allowed=[10.0.0.250] dhcp-server=false router-advert=false}")

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
