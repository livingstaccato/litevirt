package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// mtuGate is a release gate that is open or closed for every feature and
// counts each time it is asked about one, by any of its three entry points.
type mtuGate struct {
	t  testing.TB
	on bool

	mu    sync.Mutex
	asked map[capabilities.Feature]int
}

func newMTUGate(t testing.TB, on bool) *mtuGate {
	return &mtuGate{t: t, on: on, asked: map[capabilities.Feature]int{}}
}

func (g *mtuGate) count(f capabilities.Feature) {
	g.mu.Lock()
	g.asked[f]++
	g.mu.Unlock()
}

func (g *mtuGate) times(f capabilities.Feature) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.asked[f]
}

func (g *mtuGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.count(f)
	if !g.on {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *mtuGate) FeatureAvailable(f capabilities.Feature) bool {
	g.count(f)
	return g.on
}

func (g *mtuGate) FeatureRefusal(_ context.Context, f capabilities.Feature) error {
	g.count(f)
	if !g.on {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
	}
	return nil
}

func mtuCreate(name string, mtu int32) *pb.CreateVMRequest {
	req := disklessCreateRequest(name)
	req.Spec.Network[0].Mtu = mtu
	return req
}

// mtuCreateServer is a server whose create reaches the durable write, with the
// release gate given and the loopback NIC's bridge at bridgeMTU.
func mtuCreateServer(t *testing.T, gate *mtuGate, bridgeMTU int) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, fake := provableCreateServer(t)
	s.SetReleaseFeatureGate(gate)
	fake.SetBridgeMTU("lo", bridgeMTU)
	return s, fake
}

// Before the latch a NIC MTU is refused, naming nic_mtu, on every way in: a
// create (direct, forwarded or recreated), a recreate's preflight and a
// stack. A file or spec with no MTU is not.
//
// Mutations: make specSetsNICMTU answer false — the create and preflight go
// red; drop the stack refusal from DeployStack — the stack case goes red.
func TestNICMTUGate_UnlatchedRefusesNamingTheFeature(t *testing.T) {
	ctx := adminCtx()
	s, _ := mtuCreateServer(t, newMTUGate(t, false), 9000)
	_, err := s.CreateVM(ctx, mtuCreate("m", 9000))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "nic_mtu") {
		t.Errorf("CreateVM with an MTU before the latch: %v, want FailedPrecondition naming nic_mtu", err)
	}
	if _, err := s.recreatePreflightSpec(ctx, mtuCreate("m", 1).Spec, "test-host"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("recreate preflight with an MTU before the latch: %v", err)
	}
	stackYAML := "name: st\nnetworks:\n  n1: {}\nvms:\n  web:\n    image: img\n    network:\n      - name: n1\n        mtu: bridge\n"
	err = s.DeployStack(&pb.DeployStackRequest{ComposeYaml: stackYAML}, &mockDeployStream{ctx: ctx})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `vm "web"`) || !strings.Contains(err.Error(), "nic_mtu") {
		t.Errorf("stack with an MTU before the latch: %v", err)
	}
	f, err := compose.ParseBytes([]byte(strings.Replace(stackYAML, "        mtu: bridge\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.refuseUnlatchedStackNICMTU(ctx, f); err != nil {
		t.Errorf("stack with no MTU: %v", err)
	}
}

// A spec with no MTU never asks the nic_mtu gate: a plain create behaves as it
// did before the feature existed, however the gate would answer.
//
// Mutation: have specSetsNICMTU answer true — the count goes red.
func TestNICMTUGate_NoMTUNeverAsksTheGate(t *testing.T) {
	gate := newMTUGate(t, true)
	s, _ := mtuCreateServer(t, gate, 1500)
	if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("plain")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	f, _ := compose.ParseBytes([]byte("name: st\nnetworks:\n  n1: {}\nvms:\n  web:\n    image: img\n    network:\n      - name: n1\n"))
	if err := s.refuseUnlatchedStackNICMTU(adminCtx(), f); err != nil {
		t.Fatal(err)
	}
	if n := gate.times(capabilities.FeatureNICMTU); n != 0 {
		t.Errorf("the nic_mtu gate was asked %d times for a create and a stack that set no MTU", n)
	}
}

// After the latch the MTU is stored in the spec, the create takes the
// feature's grant on the node that writes it, and the domain carries <mtu>:
// the explicit value, or the bridge's own for `bridge`.
//
// Mutation: leave the create's nic_mtu grant out of its writer's grants — the
// writer refuses it and the create goes red.
func TestCreateVM_NICMTUStoredAfterTheLatch(t *testing.T) {
	gate := newMTUGate(t, true)
	s, fake := mtuCreateServer(t, gate, 9000)
	ctx := adminCtx()
	for name, mtu := range map[string]int32{"explicit": 9000, "bridge": compose.NICMTUBridge} {
		if _, err := s.CreateVM(ctx, mtuCreate(name, mtu)); err != nil {
			t.Fatalf("%s: CreateVM: %v", name, err)
		}
		if got := loadStoredSpec(t, s, name).Network[0].GetMtu(); got != mtu {
			t.Errorf("%s: stored mtu = %d, want %d", name, got, mtu)
		}
		if x := fake.DefinedXML(name); !strings.Contains(x, `<mtu size="9000">`) {
			t.Errorf("%s: the domain has no <mtu size=9000>:\n%s", name, x)
		}
	}
	if gate.times(capabilities.FeatureNICMTU) == 0 {
		t.Error("the creates never took the nic_mtu grant")
	}
}

// An explicit MTU must EQUAL its bridge's on the host that defines the domain:
// larger and smaller are both refused, before anything is defined, with the
// NIC, the bridge and the host named.
//
// Mutation: drop the reader from the create's render (read the host's real
// interfaces) — the refusals change and go red.
func TestCreateVM_NICMTUMustEqualItsBridge(t *testing.T) {
	s, fake := mtuCreateServer(t, newMTUGate(t, true), 1500)
	for name, mtu := range map[string]int32{"larger": 9000, "smaller": 1400} {
		_, err := s.CreateVM(adminCtx(), mtuCreate(name, mtu))
		want := "does not match bridge lo MTU 1500 on host test-host (a guest MTU must equal its bridge's)"
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "NIC 0 MTU") {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
		if x := fake.DefinedXML(name); x != "" {
			t.Errorf("%s: a refused create defined a domain", name)
		}
	}
	if _, err := s.CreateVM(adminCtx(), mtuCreate("equal", 1500)); err != nil {
		t.Errorf("equal: %v", err)
	}
}

// orderVirt records when the bridge's MTU is read, against the provisioning
// steps the scenario records itself.
type orderVirt struct {
	*libvirtfake.Fake
	rec func(string)
}

func (o orderVirt) BridgeMTU(b string) (int, error) {
	o.rec("read:" + b)
	return o.Fake.BridgeMTU(b)
}

// A `bridge` NIC's MTU is read from the bridge only after the create has made
// sure the bridge exists on this host: a bridge that is not there yet would
// have no MTU to read.
//
// Mutation: read the bridge's MTU before the NIC loop's provisioning — red.
func TestCreateVM_NICMTUReadAfterProvisioning(t *testing.T) {
	s, fake := mtuCreateServer(t, newMTUGate(t, true), 9000)
	var mu sync.Mutex
	var order []string
	rec := func(e string) { mu.Lock(); order = append(order, e); mu.Unlock() }
	s.virt = orderVirt{Fake: fake, rec: rec}
	s.SetBridgeEnsure(func(name string) error { rec("ensure:" + name); return nil })
	if _, err := s.CreateVM(adminCtx(), mtuCreate("o", compose.NICMTUBridge)); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	ensure, read := -1, -1
	for i, e := range order {
		switch {
		case e == "ensure:lo" && ensure < 0:
			ensure = i
		case e == "read:lo" && read < 0:
			read = i
		}
	}
	if ensure < 0 || read < 0 || read < ensure {
		t.Errorf("order = %v, want the bridge ensured before its MTU is read", order)
	}
}

// Restore-live and promote take their spec from a manifest or a peer: before
// the gate opens an MTU is dropped with a warning (a restore main allows must
// still work), after it the spec keeps it under the feature's grant, and an
// invalid value is dropped and named rather than refused.
//
// Mutations: skip the strip — the unlatched case goes red; skip the grant —
// the latched case goes red.
func TestRestrictRestoredNICMTU(t *testing.T) {
	ctx := context.Background()
	mk := func(mtu int32) *pb.VMSpec {
		return &pb.VMSpec{Name: "r", Network: []*pb.NetworkAttachment{{Name: "n", Mtu: mtu}, {Name: "o"}}}
	}
	un := &Server{releaseFeatures: newMTUGate(t, false)}
	spec := mk(9000)
	r := un.restrictRestoredNICMTU(ctx, spec)
	if !r.stripped || specSetsNICMTU(spec) {
		t.Errorf("unlatched: %+v spec=%+v; want the MTU stripped", r, spec)
	}
	la := &Server{releaseFeatures: newMTUGate(t, true)}
	spec = mk(9000)
	r = la.restrictRestoredNICMTU(ctx, spec)
	if r.stripped || spec.Network[0].Mtu != 9000 || r.grant.Check(capabilities.FeatureNICMTU) != nil {
		t.Errorf("latched: %+v spec=%+v; want the MTU kept under the grant", r, spec)
	}
	spec = mk(70000)
	r = la.restrictRestoredNICMTU(ctx, spec)
	if spec.Network[0].Mtu != 0 || len(r.invalid) != 1 || !strings.Contains(r.invalid[0], "network 0 mtu") {
		t.Errorf("latched, mtu 70000: %+v spec=%+v; want it dropped and named", r, spec)
	}
	gate := newMTUGate(t, true)
	plain := &Server{releaseFeatures: gate}
	if r := plain.restrictRestoredNICMTU(ctx, mk(0)); r.stripped || gate.times(capabilities.FeatureNICMTU) != 0 {
		t.Errorf("a spec with no MTU: %+v, gate asked %d times", r, gate.times(capabilities.FeatureNICMTU))
	}
}
