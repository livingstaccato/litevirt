package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// upsertStackContainer inserts a container tagged with its stack (and optionally
// a recorded static IP), the way buildContainerRequest does at deploy time.
func upsertStackContainer(t *testing.T, ctx context.Context, s *Server, name, stack, host, state, ip string) {
	t.Helper()
	labels := map[string]string{corrosion.LabelStack: stack}
	if ip != "" {
		labels[corrosion.LabelIP] = ip
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: host, Name: name, State: state, Image: "alpine:3.21",
		CPULimit: 1, MemMiB: 256, Labels: labels,
	}); err != nil {
		t.Fatalf("UpsertContainer(%s): %v", name, err)
	}
}

// A running stack container with a recorded static IP shows up as an active LB
// backend in the status view — cluster-wide, no local runtime needed.
func TestLBBackends_IncludesContainerStaticIP(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 {
		t.Fatalf("expected 1 container backend, got %d", len(backends))
	}
	if backends[0].VmName != "web" || backends[0].Address != "10.0.0.20" || backends[0].Status != "active" {
		t.Errorf("container backend = %+v, want web/10.0.0.20/active", backends[0])
	}
}

// A stopped container is still listed but marked down.
func TestLBBackends_StoppedContainerIsDown(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "stopped", "10.0.0.20")

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 || backends[0].Status != "down" {
		t.Fatalf("expected 1 down backend, got %+v", backends)
	}
}

// A single stack LB fronts a mix of VMs and containers — the headline case.
func TestLBBackends_MixedVMAndContainer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "api-1", StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "api-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	backends := s.lbBackends(ctx, "app-lb")
	got := map[string]string{} // name -> address
	for _, b := range backends {
		got[b.VmName] = b.Address
	}
	if len(got) != 2 || got["api-1"] != "10.0.0.10" || got["web"] != "10.0.0.20" {
		t.Fatalf("mixed backends = %+v, want api-1=10.0.0.10 + web=10.0.0.20", got)
	}
}

// The HAProxy render path (collectLBBackends) includes a running container with
// the LB's target port, and skips stopped / IP-less containers.
func TestCollectLBBackends_IncludesContainer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")
	upsertStackContainer(t, ctx, s, "stopped-ct", "app", "other-host", "stopped", "10.0.0.21")
	upsertStackContainer(t, ctx, s, "noip-ct", "app", "other-host", "running", "") // no IP, not local → skipped

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "app", lbSpec)
	if len(backends) != 1 {
		t.Fatalf("expected 1 rendered backend (running+IP only), got %d: %+v", len(backends), backends)
	}
	if backends[0].Name != "web" || backends[0].IP != "10.0.0.20" || backends[0].Port != 8080 {
		t.Errorf("rendered backend = %+v, want web/10.0.0.20/8080", backends[0])
	}
}

// Render path: a stack LB renders both the VM and the container as server lines.
func TestCollectLBBackends_MixedVMAndContainer(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "api-1", StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "api-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	upsertStackContainer(t, ctx, s, "web", "app", "other-host", "running", "10.0.0.20")

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "app", lbSpec)
	got := map[string]string{}
	for _, b := range backends {
		got[b.Name] = b.IP
	}
	if len(got) != 2 || got["api-1"] != "10.0.0.10" || got["web"] != "10.0.0.20" {
		t.Fatalf("rendered mixed backends = %+v, want api-1 + web", got)
	}
}

// containerBackendIP prefers the recorded static label, then falls back to a
// local lxc-info lookup for a container on this host (DHCP NICs); a remote
// container with no recorded IP is left unresolved.
func TestContainerBackendIP_StaticThenLocalFallback(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{ipByName: map[string]string{"local-ct": "10.0.0.30"}})

	// Static label wins, no runtime call needed (even on a remote host).
	if ip := s.containerBackendIP(ctx, corrosion.ContainerRecord{
		Name: "web", HostName: "other-host", Labels: map[string]string{corrosion.LabelIP: "10.0.0.20"},
	}); ip != "10.0.0.20" {
		t.Errorf("static label IP = %q, want 10.0.0.20", ip)
	}

	// No label, but container is local → lxc-info fallback resolves it.
	if ip := s.containerBackendIP(ctx, corrosion.ContainerRecord{
		Name: "local-ct", HostName: "test-host",
	}); ip != "10.0.0.30" {
		t.Errorf("local fallback IP = %q, want 10.0.0.30", ip)
	}

	// No label and remote → unresolved (cross-host DHCP discovery is a follow-up).
	if ip := s.containerBackendIP(ctx, corrosion.ContainerRecord{
		Name: "remote-ct", HostName: "other-host",
	}); ip != "" {
		t.Errorf("remote no-label IP = %q, want empty", ip)
	}
}
