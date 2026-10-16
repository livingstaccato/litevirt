package fleet

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type fixLBFixture struct {
	c           *Cluster
	mu          sync.Mutex
	applied     map[string][]lb.Config
	spec        *pb.LBSpec
	beforeApply func(context.Context, *Node)
	retired     atomic.Bool
}

func newFixLBFixture(t *testing.T) *fixLBFixture {
	t.Helper()
	f := &fixLBFixture{c: New(t, Options{Nodes: 2, IndependentReplicas: true}), applied: map[string][]lb.Config{}}
	cert, key := filepath.Join(t.TempDir(), "service.crt"), filepath.Join(t.TempDir(), "service.key")
	f.spec = &pb.LBSpec{Enabled: true, Vip: "10.205.0.250/24", Algorithm: "roundrobin", Hosts: []string{"node-0", "node-1"}, Snat: true, StickySessions: true, Health: &pb.LBHealthSpec{Type: "http", Path: "/healthz", Interval: "1500ms"}, Ports: []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "http", RedirectHttps: true}, {Listen: 443, Target: 8080, Protocol: "http", Tls: &pb.LBTlsSpec{Cert: cert, Key: key}}}}
	ports, _ := json.Marshal(f.spec.Ports)
	hosts, _ := json.Marshal(f.spec.Hosts)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "lbn1", StackName: "lbn", Loadbalancer: f.spec})
	yaml := strings.NewReplacer("CERT", cert, "KEY", key).Replace(composeLBSNATNoFlap)
	ctx := context.Background()
	for _, n := range f.c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
		n.Server.SetBridgeExists(func(string) bool { return true })
		n.Server.SetLBApply(func(ctx context.Context, cfg lb.Config) error {
			if f.retired.Load() {
				t.Error("apply after fixture dependencies retired")
			}
			if f.beforeApply != nil {
				f.beforeApply(ctx, n)
			}
			f.mu.Lock()
			f.applied[n.Name] = append(f.applied[n.Name], cfg)
			f.mu.Unlock()
			return nil
		})
		for _, err := range []error{
			corrosion.UpsertStack(ctx, n.DB, corrosion.StackRecord{Name: "lbn", ComposeYAML: yaml, State: "running"}),
			corrosion.UpsertNetwork(ctx, n.DB, corrosion.NetworkRecord{Name: "lbn_hinet", StackName: "lbn", Type: "bridge", Config: `{"subnet":"10.205.0.0/24","HostIsolation":true}`}),
			corrosion.UpsertLBConfig(ctx, n.DB, corrosion.LBConfigRecord{Name: "lbn-lb", StackName: "lbn", VIP: f.spec.Vip, Algorithm: f.spec.Algorithm, Hosts: string(hosts), Ports: string(ports), Enabled: true, Generation: "fix-generation"}),
			corrosion.UpsertLBBackend(ctx, n.DB, corrosion.LBBackendRecord{LBName: "lbn-lb", Name: "base", Address: "10.205.0.10", Enabled: true, Generation: "fix-generation"}),
			corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{Name: "lbn1", HostName: "node-0", StackName: "lbn", State: "running", Spec: string(spec)}, nil, nil),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.c.WaitConverged(t, convergeTimeout)
	t.Cleanup(func() { f.c.Stop(); f.retired.Store(true) })
	return f
}
func (f *fixLBFixture) counts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := map[string]int{}
	for k, v := range f.applied {
		r[k] = len(v)
	}
	return r
}
func (f *fixLBFixture) assertSettings(t *testing.T, ports []*pb.LBPort, extra string) {
	t.Helper()
	f.c.waitLBWork()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.c.Nodes {
		cs := f.applied[n.Name]
		if len(cs) == 0 {
			t.Errorf("%s: no apply", n.Name)
			continue
		}
		c := cs[len(cs)-1]
		if !c.Sticky || c.Health == nil || c.Health.Path != "/healthz" || len(c.Ports) != 2 || !c.Ports[0].RedirectHTTPS || c.Ports[1].TLS == nil || c.Ports[1].TLS.Cert != ports[1].Tls.Cert || c.Ports[1].TLS.Key != ports[1].Tls.Key {
			t.Errorf("%s: full effective TLS/redirect/health/sticky settings lost: %+v", n.Name, c)
		}
		if extra != "" {
			found := false
			for _, b := range c.Backends {
				if b.Name == extra {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: requested backend %s lost", n.Name, extra)
			}
		}
	}
}
func fixUser(t *testing.T, c *Cluster, n *Node, name, role string) pb.LiteVirtClient {
	t.Helper()
	ctx := context.Background()
	pw := name + "-password-0123456789"
	if _, err := c.SelfClient(n).CreateUser(ctx, &pb.CreateUserRequest{Username: name, Password: pw, Role: role}); err != nil {
		t.Fatal(err)
	}
	login, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: name, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	return c.bearerClient(n, login.Token)
}
func TestFleet_StackLBUpdateTLSAuthorization(t *testing.T) {
	f := newFixLBFixture(t)
	c := f.c
	n := c.Nodes[0]
	ctx := context.Background()
	operator := fixUser(t, c, n, "operator-update", "operator")
	admin := c.SelfClient(n)
	inside := proto.Clone(f.spec).(*pb.LBSpec).Ports
	inside[1].Tls = &pb.LBTlsSpec{Cert: lb.CertDir + "/allowed.crt", Key: lb.CertDir + "/allowed.key"}
	snapshot := func() any {
		a, e := corrosion.ListLBConfigs(ctx, n.DB)
		if e != nil {
			t.Fatal(e)
		}
		b, e := corrosion.ListLBBackends(ctx, n.DB, "lbn-lb")
		if e != nil {
			t.Fatal(e)
		}
		return []any{a, b}
	}
	for _, which := range []string{"cert", "key"} {
		t.Run("operator-outside-"+which, func(t *testing.T) {
			p := proto.Clone(&pb.LBSpec{Ports: inside}).(*pb.LBSpec).Ports
			if which == "cert" {
				p[1].Tls.Cert = f.spec.Ports[1].Tls.Cert
			} else {
				p[1].Tls.Key = f.spec.Ports[1].Tls.Key
			}
			before, count := snapshot(), f.counts()
			generation := n.Server.WaitNetworkWork()
			n.Net.mu.Lock()
			routes := n.Net.lbRoutes
			n.Net.mu.Unlock()
			_, err := operator.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbn-lb", Ports: p, AddBackends: []*pb.LBBackendAddress{{Name: "forbidden-" + which, Address: "10.205.0.90"}}})
			c.waitLBWork()
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("operator outside %s: %v, want PermissionDenied", which, err)
			}
			if !reflect.DeepEqual(snapshot(), before) {
				t.Error("refusal changed persisted LB/backend state")
			}
			if !reflect.DeepEqual(f.counts(), count) || n.Server.WaitNetworkWork() != generation {
				t.Error("refusal performed local apply or peer fanout")
			}
			n.Net.mu.Lock()
			after := n.Net.lbRoutes
			n.Net.mu.Unlock()
			if after != routes {
				t.Error("refusal performed network effects")
			}
		})
	}
	if _, err := admin.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbn-lb", Ports: f.spec.Ports, AddBackends: []*pb.LBBackendAddress{{Name: "admin-added", Address: "10.205.0.91"}}}); err != nil {
		t.Fatal(err)
	}
	f.assertSettings(t, f.spec.Ports, "admin-added")
	if _, err := operator.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbn-lb", AddBackends: []*pb.LBBackendAddress{{Name: "operator-added", Address: "10.205.0.92"}}}); err != nil {
		t.Fatal(err)
	}
	f.assertSettings(t, f.spec.Ports, "operator-added")
	if _, err := operator.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbn-lb", Ports: inside}); err != nil {
		t.Fatal(err)
	}
	f.assertSettings(t, inside, "operator-added")
}

type fixApplyMark struct{}

func TestFleet_LBDrainOwnsTimedOutHandlerAndChild(t *testing.T) {
	f := newFixLBFixture(t)
	c := f.c
	early, later := c.Nodes[0], c.Nodes[1]
	parked, release, clientDone, handlerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{})
	drainDone, stopDone := make(chan struct{}), make(chan struct{})
	closeAttempt := make(chan string, 2)
	allowClose := make(chan struct{})
	var once, closeOnce sync.Once
	unpark := func() { once.Do(func() { close(release) }) }
	permitClose := func() { closeOnce.Do(func() { close(allowClose) }) }
	var drainStarted, stopStarted bool
	join := func(ch <-chan struct{}, label string) {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Errorf("%s failed bounded join", label)
		}
	}
	t.Cleanup(func() {
		unpark()
		permitClose()
		if drainStarted {
			join(drainDone, "drain")
		}
		if stopStarted {
			join(stopDone, "stop")
		}
	})
	early.Server.SetPeerUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if methodName(method) != "RefreshLB" {
			return c.networkRPCClient()(ctx, method, req, reply, cc, invoke, opts...)
		}
		ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		err := c.networkRPCClient()(ctx, method, req, reply, cc, invoke, opts...)
		clientDone <- err
		return err
	})
	later.HookUnary("RefreshLB", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		defer close(handlerDone)
		return handler(context.WithValue(ctx, fixApplyMark{}, true), req)
	})
	f.beforeApply = func(ctx context.Context, n *Node) {
		if n == later && ctx.Value(fixApplyMark{}) == true {
			close(parked)
			<-release
		}
	}
	early.Server.RefreshLBForStack(context.Background(), "lbn")
	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("later-node effect never parked")
	}
	select {
	case err := <-clientDone:
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("client returned %v, want deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client deadline did not complete")
	}
	early.Server.WaitNetworkWork() // actual outgoing client is complete, handler still parked
	select {
	case <-handlerDone:
		t.Fatal("handler unexpectedly completed")
	default:
	}
	before := f.counts()[early.Name]
	drainStarted = true
	go func() { defer close(drainDone); c.waitLBWork() }()
	select {
	case <-drainDone:
		t.Error("drain returned while timed-out peer effect remained parked")
	case <-time.After(100 * time.Millisecond):
	}
	c.beforeDependencyClose = func(n *Node) {
		select {
		case closeAttempt <- n.Name:
		default:
		}
		<-allowClose
	}
	stopStarted = true
	go func() { defer close(stopDone); c.Stop() }()
	select {
	case name := <-closeAttempt:
		t.Errorf("dependency close attempted on %s before later-node handler completed", name)
	case <-time.After(100 * time.Millisecond):
	}
	unpark()
	join(handlerDone, "actual timed-out handler")
	join(drainDone, "causal child drain")
	if f.counts()[early.Name] <= before {
		t.Error("late causal child did not apply on earlier node before transport shutdown")
	}
	permitClose()
	join(stopDone, "all-node stop")
	f.retired.Store(true)
	if !t.Failed() {
		t.Log("client deadline preceded effect completion; drain and teardown joined handler and child")
	}
}

// The hook deliberately detaches cancellation to model noncooperative late work;
// the real TLS/auth interceptors still run. This does not model gRPC detaching it.
func TestFleet_LBDrainSealsTimedOutBeforeAdmission(t *testing.T) {
	f := newFixLBFixture(t)
	c := f.c
	early, later := c.Nodes[0], c.Nodes[1]
	parked, release := make(chan struct{}), make(chan struct{})
	returned := make(chan error, 1)
	clientDone := make(chan error, 1)
	var once sync.Once
	unpark := func() { once.Do(func() { close(release) }) }
	join := func(ch <-chan error, label string) error {
		select {
		case err := <-ch:
			return err
		case <-time.After(10 * time.Second):
			t.Errorf("%s failed bounded join", label)
			return context.DeadlineExceeded
		}
	}
	var clientJoined, handlerJoined bool
	t.Cleanup(func() {
		unpark()
		if !clientJoined {
			join(clientDone, "client")
		}
		if !handlerJoined {
			join(returned, "late handler")
		}
	})
	later.HookUnary("ApplyLB", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		close(parked)
		<-release
		response, err := handler(context.WithoutCancel(ctx), req)
		returned <- err
		return response, err
	})
	client := c.PeerClient(early, later)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := client.ApplyLB(ctx, &pb.ApplyLBRequest{LbName: "lbn-lb", StackName: "lbn", Vip: f.spec.Vip, Algorithm: f.spec.Algorithm, Hosts: f.spec.Hosts, Ports: f.spec.Ports, Health: f.spec.Health, StickySessions: true})
		clientDone <- err
	}()
	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("actual RPC never reached pre-admission hook")
	}
	err := join(clientDone, "deadline client")
	clientJoined = true
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("client returned %v, want deadline", err)
	}
	c.waitLBWork()
	before := f.counts()
	unpark()
	err = join(returned, "late admission")
	handlerJoined = true
	c.waitLBWork()
	if status.Code(err) != codes.Canceled {
		t.Errorf("sealed late admission returned %v, want Canceled", err)
	}
	if !reflect.DeepEqual(before, f.counts()) {
		t.Error("sealed late admission entered actual apply effects")
	}
}

// An arbitrary metadata value cannot mint private fixture ownership. Real TLS
// and authorization still run before the hook substitutes the unknown ticket.
func TestFleet_LBAdmissionRejectsUnknownTicket(t *testing.T) {
	f := newFixLBFixture(t)
	c := f.c
	early, later := c.Nodes[0], c.Nodes[1]
	later.HookUnary("ApplyLB", func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		md = md.Copy()
		md.Set(networkCallKey, "not-a-registered-call")
		return handler(metadata.NewIncomingContext(ctx, md), req)
	})
	before := f.counts()
	_, err := c.PeerClient(early, later).ApplyLB(context.Background(), &pb.ApplyLBRequest{LbName: "lbn-lb", StackName: "lbn", Vip: f.spec.Vip, Ports: f.spec.Ports, Hosts: f.spec.Hosts})
	c.waitLBWork()
	if status.Code(err) != codes.Canceled {
		t.Errorf("unknown ticket: %v, want Canceled", err)
	}
	if !reflect.DeepEqual(before, f.counts()) {
		t.Error("unknown ticket entered apply effects")
	}
	c.networkCalls.mu.Lock()
	outstanding := len(c.networkCalls.calls)
	c.networkCalls.mu.Unlock()
	if outstanding != 0 {
		t.Errorf("registry retained %d completed calls", outstanding)
	}
}
