package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

const lbInject = "x\nglobal\n    pidfile /etc/litevirt/pki/host.key"

func validLBSpec() *pb.LBSpec {
	return &pb.LBSpec{
		Enabled: true, Vip: "10.0.0.50/24", Algorithm: "roundrobin",
		Ports: []*pb.LBPort{
			{Listen: 80, Target: 8080, Protocol: "http", RedirectHttps: true},
			{Listen: 443, Target: 8080, Protocol: "http", Tls: &pb.LBTlsSpec{Cert: lb.CertDir + "/a.crt", Key: lb.CertDir + "/a.key"}},
		},
		Health: &pb.LBHealthSpec{Type: "http", Path: "/healthz"},
	}
}

// TestValidateSpecNames_StackAndLB: CreateVM's name check refuses a stack
// name that traverses or carries shell metacharacters (it names the LB's
// root-owned files and notify script), and an LB whose rendered values are
// outside their enums or not one token, per field family.
//
// Mutations (each red): drop the StackName check; drop validateLBSpec.
func TestValidateSpecNames_StackAndLB(t *testing.T) {
	ok := &pb.VMSpec{Name: "web", StackName: "shop", Loadbalancer: validLBSpec()}
	if err := validateSpecNames(ok); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
	for _, stack := range []string{"../../profile.d/$(id)", "a;b", "a b", "..", "a/b"} {
		spec := &pb.VMSpec{Name: "web", StackName: stack}
		if err := validateSpecNames(spec); err == nil {
			t.Errorf("stack name %q accepted", stack)
		}
	}
	for name, mutate := range map[string]func(*pb.LBSpec){
		"algorithm":   func(l *pb.LBSpec) { l.Algorithm = "roundrobin\n" + lbInject },
		"protocol":    func(l *pb.LBSpec) { l.Ports[1].Protocol = "http\n" + lbInject },
		"health type": func(l *pb.LBSpec) { l.Health.Type = "http\n" + lbInject },
		"health path": func(l *pb.LBSpec) { l.Health.Path = "/" + lbInject },
		"tls path":    func(l *pb.LBSpec) { l.Ports[1].Tls.Cert = lb.CertDir + "/a\n" + lbInject },
		"redirect":    func(l *pb.LBSpec) { l.Ports[0].Protocol = "tcp" },
	} {
		l := validLBSpec()
		mutate(l)
		if err := validateSpecNames(&pb.VMSpec{Name: "web", Loadbalancer: l}); err == nil {
			t.Errorf("%s: injected LB accepted", name)
		}
	}
}

// TestRequireAdminForLBTLS: a TLS file outside lb.CertDir needs the admin
// role; inside it, an operator may name it.
//
// Mutation: make requireAdminForLBTLS return nil — red.
func TestRequireAdminForLBTLS(t *testing.T) {
	if err := requireAdminForLBTLS(operatorCtx(), validLBSpec()); err != nil {
		t.Errorf("operator refused a file under %s: %v", lb.CertDir, err)
	}
	for _, f := range []string{"/etc/litevirt/pki/host.key", "/root/x.pem", lb.CertDir + "/../pki/host.key"} {
		l := validLBSpec()
		l.Ports[1].Tls.Key = f
		err := requireAdminForLBTLS(operatorCtx(), l)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("operator naming %s: %v, want PermissionDenied", f, err)
		}
		if err := requireAdminForLBTLS(adminCtx(), l); err != nil {
			t.Errorf("admin naming %s: %v", f, err)
		}
	}
}

// TestCreateVM_LBTLSOutsideCertDirNeedsAdmin: the check is wired into CreateVM.
func TestCreateVM_LBTLSOutsideCertDirNeedsAdmin(t *testing.T) {
	s := testServer(t)
	l := validLBSpec()
	l.Ports[1].Tls.Key = "/etc/litevirt/pki/host.key"
	_, err := s.CreateVM(userCtx("op", "operator"), &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "web", Image: "img", StackName: "shop", Loadbalancer: l}})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), lb.CertDir) {
		t.Errorf("CreateVM: %v, want PermissionDenied naming %s", err, lb.CertDir)
	}
	_, err = s.CreateVM(userCtx("op", "operator"), &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "web", Image: "img", StackName: "../../x$(id)"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("CreateVM with a traversal stack name: %v, want InvalidArgument", err)
	}
}

// TestServableLBPorts: a stored redirect-https that cannot work is left out
// of its port with an event, the rest of the LB served; a stored TLS file
// outside lb.CertDir is served with an event naming it and the rule.
//
// Mutation: skip the RedirectProblem drop — red.
func TestServableLBPorts(t *testing.T) {
	s := testServer(t)
	ch, cancel := s.events.Subscribe()
	defer cancel()
	in := []lb.Port{
		{Listen: 80, Target: 8080, Protocol: "tcp", RedirectHTTPS: true},
		{Listen: 443, Target: 8080, Protocol: "tcp", TLS: &lb.TLSConfig{Cert: "/srv/old.crt", Key: lb.CertDir + "/a.key"}},
	}
	out := s.servableLBPorts("shop-lb", in)
	if out[0].RedirectHTTPS || out[1].TLS == nil || !in[0].RedirectHTTPS {
		t.Errorf("servable ports %+v (input %+v)", out, in)
	}
	got := map[string]string{}
	for len(got) < 2 {
		select {
		case e := <-ch:
			got[e.Action] = e.Detail
		case <-time.After(2 * time.Second):
			t.Fatalf("events %v, want redirect_ignored and tls_outside_cert_dir", got)
		}
	}
	if d := got["lb.redirect_ignored"]; !strings.Contains(d, "port 80") {
		t.Errorf("redirect event %q", d)
	}
	if d := got["lb.tls_outside_cert_dir"]; !strings.Contains(d, "/srv/old.crt") || !strings.Contains(d, lb.CertDir) || !strings.Contains(d, "admin") {
		t.Errorf("tls event %q", d)
	}
}

// TestLBSNATSync_NotOnANonIsolatedBridge (M6): SNAT, and so conntrackd,
// applies only on a host-isolated network's bridge.
//
// Mutation: drop the subnet=="" return in lbSNATSync — red.
func TestLBSNATSync_NotOnANonIsolatedBridge(t *testing.T) {
	s := testServer(t)
	putNetwork(t, s, "lbr_plain", "bridge", compose.NetworkDef{Interface: "plain", Subnet: "10.204.0.0/24"})
	for name, addr := range map[string]string{s.hostName: "192.0.2.11", "peer-host": "192.0.2.12"} {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: name, Address: addr, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := lb.Config{Name: "x-lb", Interface: "plain"}
	s.lbSNATSync(context.Background(), &cfg, lbPlacement{iface: "plain", network: "lbr_plain"}, []string{s.hostName, "peer-host"})
	if cfg.SNATEnabled {
		t.Error("conntrackd enabled for an LB on a bridge that is not host-isolated")
	}
}

// TestDeployStack_LBTLSOutsideCertDirNeedsAdmin: a compose deploy naming an
// LB TLS file outside lb.CertDir is refused for an operator before anything
// is deployed (the deploy step applies the LB without CreateVM).
//
// Mutation: drop the requireAdminForLBTLS loop in DeployStack — red.
func TestDeployStack_LBTLSOutsideCertDirNeedsAdmin(t *testing.T) {
	s := testServerR2(t)
	yaml := strings.Replace(lbComposeTLS, "KEY", "/etc/litevirt/pki/host.key", 1)
	stream := &mockDeployStreamR2{ctx: userCtx("op", "operator")}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml, DryRun: true}, stream)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), lb.CertDir) {
		t.Errorf("DeployStack: %v, want PermissionDenied naming %s", err, lb.CertDir)
	}
	stream = &mockDeployStreamR2{ctx: userCtx("op", "operator")}
	err = s.DeployStack(&pb.DeployStackRequest{ComposeYaml: strings.Replace(lbComposeTLS, "KEY", lb.CertDir+"/a.key", 1), DryRun: true}, stream)
	if status.Code(err) == codes.PermissionDenied {
		t.Errorf("DeployStack with files under %s: %v", lb.CertDir, err)
	}
}

const lbComposeTLS = `name: shop
vms:
  web:
    image: ubuntu-22.04
    loadbalancer:
      vip: 10.0.0.50/24
      ports:
        - listen: 443
          target: 8080
          protocol: http
          tls:
            cert: /etc/litevirt/lb-certs/a.crt
            key: KEY
`
