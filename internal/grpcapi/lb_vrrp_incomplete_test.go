package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/lbtestproc"
)

type failedVRRPApplyRuntime struct {
	*lbtestproc.Runtime
	fail        bool
	validations int
}

func (r *failedVRRPApplyRuntime) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	out, err := r.Runtime.Run(ctx, bin, args...)
	if err != nil {
		return out, err
	}
	if bin == "haproxy" {
		r.validations++
		if r.fail {
			return nil, errors.New("injected actual candidate validation failure")
		}
	}
	return out, nil
}

func TestVRRPTransport_FailedActualApplyCannotServeAndIsRetried(t *testing.T) {
	ctx := context.Background()
	s := vrrpServer(t, true, true, true)
	markLatched(t, s)
	root := t.TempDir()
	m := lb.NewManagerAt(filepath.Join(root, "config"), filepath.Join(root, "run"))
	r := &failedVRRPApplyRuntime{Runtime: lbtestproc.New(t, false)}
	m.SetProcessRuntime(r)
	s.SetLBManager(m)
	s.lbApplyOverride = m.Apply
	s.lbIfaceRunningOverride = func(string) bool { return true }
	putNetwork(t, s, "lbr_hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	req := &pb.ApplyLBRequest{LbName: "lbr-lb", Vip: "10.202.0.250/24", Hosts: []string{"self", "peer-1"}, Ports: []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}}, Backends: []*pb.LBBackend{{VmName: "lbr1", Address: "10.202.0.72"}}}
	if err := corrosion.SetVRRPTransport(ctx, s.db, "multicast", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyLB(mtlsCtx("peer-1"), req); err != nil {
		t.Fatal(err)
	}
	if !m.KeepalivedRunning(req.LbName) || r.Starts["keepalived"] != 1 {
		t.Fatal("initial actual keepalived child absent")
	}
	if s.vrrpUnicastServing(req.LbName) {
		t.Fatal("multicast positive fixture reported unicast")
	}
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{Name: req.LbName, VIP: req.Vip, Algorithm: "roundrobin", Hosts: `["self","peer-1"]`, Ports: `[{"listen":80,"target":8080,"protocol":"tcp"}]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetVRRPTransport(ctx, s.db, "unicast", "test"); err != nil {
		t.Fatal(err)
	}
	r.fail = true
	if _, err := s.ApplyLB(mtlsCtx("peer-1"), req); err == nil {
		t.Fatal("real candidate validation did not fail")
	}
	if _, err := os.Stat(filepath.Join(root, "config", req.LbName+".applying")); err != nil {
		t.Fatal("failed apply did not leave durable marker", err)
	}
	if !m.KeepalivedRunning(req.LbName) || r.Starts["keepalived"] != 1 {
		t.Fatal("failed candidate replaced the old actual child")
	}
	if _, ok := m.KeepalivedTransport(req.LbName); ok {
		t.Error("failed candidate file was presented as committed running transport")
	}
	if s.vrrpUnicastServing(req.LbName) {
		t.Error("failed candidate supplied false actual serving evidence")
	}
	r.fail = false
	before := r.validations
	s.reconcileDeadLBs(ctx)
	if r.validations <= before || r.Starts["keepalived"] != 2 {
		t.Error("actual reconciler skipped incomplete apply while old child was alive", r.validations, before, r.Starts)
	}
	if _, err := os.Stat(filepath.Join(root, "config", req.LbName+".applying")); !os.IsNotExist(err) {
		t.Error("actual retry did not complete", err)
	}
	if !s.vrrpUnicastServing(req.LbName) {
		t.Error("successful real retry did not restore unicast serving")
	}
}
