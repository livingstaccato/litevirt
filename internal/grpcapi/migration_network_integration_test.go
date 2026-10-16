package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/compose"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestMigrationNetwork_ArrivalKeepsReturnedDevice(t *testing.T) {
	s, p, v, _, next := moveFixture(t)
	p.fail = map[string]error{}
	ctx := context.Background()
	if e := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "arrival", HostName: "source", State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "arrival", NetworkName: "lan", MAC: "52:54:00:00:00:ab"}}, nil); e != nil {
		t.Fatal(e)
	}
	peer := adminCtx()
	resp, e := s.EnsureDisks(peer, &pb.EnsureDisksRequest{VmName: "arrival", WantNetworkDevices: true})
	if e != nil {
		t.Fatal(e)
	}
	if resp.NetworkDevices["lan"] != "oldbr" {
		t.Fatalf("served response: %v", resp.NetworkDevices)
	}
	// Existing holder leaves after the response; the source has not yet made
	// the arriving domain visible. Network reconcile now tries the move.
	if e := v.UndefineDomain("guest", false); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Error("move retired returned device before arrival")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("move did not join")
	}
	if !p.ServingGateway("lan", compose.NetworkDef{Interface: "oldbr"}) {
		t.Error("returned device lost its service before arrival")
	}
}

// Private loopback TLS stub exercises the production source-side dial and
// fallback, with no disks, host commands, packets or system-owned state.
type migrationNetPeer struct {
	pb.UnimplementedLiteVirtServer
	ensure   func(*pb.EnsureDisksRequest) (*pb.EnsureDisksResponse, error)
	announce func(context.Context) error
}

func (p migrationNetPeer) EnsureDisks(_ context.Context, r *pb.EnsureDisksRequest) (*pb.EnsureDisksResponse, error) {
	return p.ensure(r)
}
func (p migrationNetPeer) AnnounceMigratedGuest(ctx context.Context, _ *pb.AnnounceMigratedGuestRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, p.announce(ctx)
}
func networkPeerFixture(t *testing.T, s *Server, p migrationNetPeer) *corrosion.HostRecord {
	t.Helper()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if e := pki.GenerateCA(crt, key); e != nil {
		t.Fatal(e)
	}
	if e := pki.GenerateHostCert(crt, key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "dst", net.ParseIP("127.0.0.1")); e != nil {
		t.Fatal(e)
	}
	cfg, e := pki.PeerTLSConfig(dir)
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterLiteVirtServer(srv, p)
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(l) }()
	t.Cleanup(func() {
		srv.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("TLS server did not join")
		}
	})
	s.pkiDir = dir
	h := &corrosion.HostRecord{Name: "dst", Address: "127.0.0.1", GRPCPort: l.Addr().(*net.TCPAddr).Port, State: "active", CertSerial: "private"}
	if e := corrosion.InsertHost(context.Background(), s.db, *h); e != nil {
		t.Fatal(e)
	}
	return h
}
func TestMigrationNetwork_OldTargetFallback(t *testing.T) {
	for _, mode := range []string{"unimplemented", "empty", "error", "served"} {
		t.Run(mode, func(t *testing.T) {
			s, _, v, _, _ := moveFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if e := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "guest", HostName: s.hostName, State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "guest", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); e != nil {
				t.Fatal(e)
			}
			v.SetActiveXML("guest", v.DefinedXML("guest"))
			v.SetState("guest", "running")
			called := false
			networkPeerFixture(t, s, migrationNetPeer{ensure: func(r *pb.EnsureDisksRequest) (*pb.EnsureDisksResponse, error) {
				called = true
				if !r.WantNetworkDevices {
					t.Error("mapping not requested")
				}
				switch mode {
				case "unimplemented":
					return nil, status.Error(codes.Unimplemented, "old target")
				case "error":
					return nil, status.Error(codes.Unavailable, "target unavailable")
				case "served":
					return &pb.EnsureDisksResponse{NetworkDevices: map[string]string{"lan": "targetbr"}}, nil
				}
				return &pb.EnsureDisksResponse{}, nil
			}})
			out, e := s.ensureDisksOnTargetNet(ctx, "dst", "guest", nil, false, true)
			if e != nil {
				t.Fatal(e)
			}
			if !called {
				t.Fatal("actual peer was not called")
			}
			got := s.migrationNICBridges(ctx, "guest", out.netDevices)
			if mode == "served" {
				if got["52:54:00:00:00:01"] != "targetbr" {
					t.Fatalf("mapping %v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("fallback retargeted: %v", got)
			}
		})
	}
}
func TestMigrationNetwork_DetachedAnnouncementJoins(t *testing.T) {
	s := testServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h := networkPeerFixture(t, s, migrationNetPeer{announce: func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.startGatewayAnnouncement(ctx, h, "guest")
	joined := make(chan struct{})
	go func() { s.WaitGatewayAnnouncements(); close(joined) }()
	defer func() {
		close(release)
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("announcement did not join")
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled caller prevented detached delivery")
	}
	select {
	case <-joined:
		t.Fatal("worker returned before delayed target")
	default:
	}
}
func TestProto_NetworkAutomationWireUnion(t *testing.T) {
	messages := []proto.Message{&pb.AnnounceMigratedGuestRequest{VmName: "arrived"}, &pb.EnsureDisksRequest{VmName: "arrived", WantNetworkDevices: true, NetworkArrivalId: "attempt"}, &pb.CleanupMigrationArtifactsRequest{VmName: "arrived", NetworkArrivalId: "attempt"}, &pb.EnsureDisksResponse{NetworkDevices: map[string]string{"lan": "oldbr", "second": "newbr"}}, &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: []byte{0, 1, 255}}}, &pb.LUNAllocationValue{RunHost: "h", Kept: true, Project: "p", ReplacedCreatedAt: "time"}, &pb.VM{VncUnknown: "unknown"}}
	for _, m := range messages {
		b, e := proto.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		out := m.ProtoReflect().New().Interface()
		if e := proto.Unmarshal(b, out); e != nil || !proto.Equal(m, out) {
			t.Fatalf("wire %T: %v %v", m, out, e)
		}
	}
	for _, f := range []struct {
		m    proto.Message
		n    protoreflect.FieldNumber
		name protoreflect.Name
	}{{&pb.AnnounceMigratedGuestRequest{}, 1, "vm_name"}, {&pb.EnsureDisksRequest{}, 10, "want_network_devices"}, {&pb.EnsureDisksResponse{}, 9, "network_devices"}, {&pb.EnsureDisksRequest{}, 11, "network_arrival_id"}, {&pb.CleanupMigrationArtifactsRequest{}, 7, "network_arrival_id"}, {&pb.AutomationClaimValue{}, 1, "envelope"}, {&pb.RecoveryClaimValue{}, 15, "automation"}, {&pb.LUNAllocationValue{}, 8, "run_host"}, {&pb.LUNAllocationValue{}, 9, "kept"}, {&pb.LUNAllocationValue{}, 10, "project"}, {&pb.LUNAllocationValue{}, 11, "replaced_created_at"}} {
		fd := f.m.ProtoReflect().Descriptor().Fields().ByNumber(f.n)
		if fd == nil || fd.Name() != f.name {
			t.Fatalf("descriptor %T %d", f.m, f.n)
		}
	}
	desc := pb.File_litevirt_v1_service_proto.Services().ByName("LiteVirt")
	registered := map[string]bool{}
	for _, m := range pb.LiteVirt_ServiceDesc.Methods {
		registered[m.MethodName] = true
	}
	for _, m := range pb.LiteVirt_ServiceDesc.Streams {
		registered[m.StreamName] = true
	}
	for _, name := range []string{"AnnounceMigratedGuest", "ExportAutomationSource", "GetAutomationDecision", "InstallAutomationDecision"} {
		if desc.Methods().ByName(protoreflect.Name(name)) == nil || !registered[name] {
			t.Fatalf("method %s missing", name)
		}
	}

}

func TestMigrationNetwork_DelayedCleanupAndRestart(t *testing.T) {
	s, p, v, _, next := moveFixture(t)
	p.fail = map[string]error{}
	ctx := adminCtx()
	if e := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "arrival", HostName: "source", State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "arrival", NetworkName: "lan", MAC: "52:54:00:00:00:ab"}}, nil); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"attempt-A", "attempt-B"} {
		r, e := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "arrival", WantNetworkDevices: true, NetworkArrivalId: id})
		if e != nil || r.GetNetworkDevices()["lan"] != "oldbr" {
			t.Fatalf("attempt %s: %v %v", id, r, e)
		}
	}
	if e := v.UndefineDomain("guest", false); e != nil {
		t.Fatal(e)
	}
	fresh := testServer(t)
	fresh.db = s.db
	fresh.virt = v
	fresh.SetNetworkProvisioner(p)
	fresh.SetNetworkDeviceStatePath(s.netDevs.statePath)
	// A delayed A cleanup, followed by an older tokenless cleanup, cannot
	// remove B's exact-device hold in a new Server before B arrives.
	for _, id := range []string{"attempt-A", ""} {
		if _, e := fresh.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{VmName: "arrival", NetworkArrivalId: id}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := fresh.provisionDevice(ctx, fresh.db, "lan", next, "", fresh.hostName); e == nil {
		t.Fatal("delayed A cleanup released pending B arrival")
	}
	if e := fresh.deprovisionDevice(ctx, "lan", nextWithBridge(next, "oldbr")); e == nil {
		t.Fatal("delete bypassed pending B arrival")
	}
	if _, e := fresh.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{VmName: "arrival", NetworkArrivalId: "attempt-B"}); e != nil {
		t.Fatal(e)
	}
	if _, e := fresh.provisionDevice(ctx, fresh.db, "lan", next, "", fresh.hostName); e != nil {
		t.Fatalf("own cleanup did not allow convergence: %v", e)
	}
}
func nextWithBridge(d compose.NetworkDef, b string) compose.NetworkDef { d.Interface = b; return d }
func TestMigrationNetwork_RecordFailureRefusesPromiseAndTransition(t *testing.T) {
	for _, mode := range []string{"corrupt", "truncated", "unreadable", "save-error"} {
		t.Run(mode, func(t *testing.T) {
			s, p, _, _, next := moveFixture(t)
			ctx := adminCtx()
			path := s.netDevs.statePath
			if e := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "arrival", HostName: "source", State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "arrival", NetworkName: "lan", MAC: "52:54:00:00:00:ab"}}, nil); e != nil {
				t.Fatal(e)
			}
			good, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "corrupt":
				_ = os.WriteFile(path, []byte("bad"), 0600)
			case "truncated":
				_ = os.WriteFile(path, []byte(`{"defs":`), 0600)
			case "unreadable":
				_ = os.Remove(path)
				_ = os.Mkdir(path, 0700)
			case "save-error":
				_ = os.Mkdir(path+".tmp", 0700)
			}
			s.SetNetworkDeviceStatePath(path)
			if _, e := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "arrival", WantNetworkDevices: true, NetworkArrivalId: "attempt"}); e == nil {
				t.Fatal("unreadable/unsaved arrival promise accepted")
			}
			if mode != "save-error" {
				if _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); e == nil {
					t.Fatal("unknown state allowed transition")
				}
				if len(p.released) != 0 {
					t.Fatal("unknown state released gateway")
				}
			}
			if mode == "unreadable" {
				_ = os.Remove(path)
			}
			if mode == "save-error" {
				_ = os.Remove(path + ".tmp")
			}
			if e := os.WriteFile(path, good, 0600); e != nil {
				t.Fatal(e)
			}
			s.SetNetworkDeviceStatePath(path)
			if _, e := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "arrival", WantNetworkDevices: true, NetworkArrivalId: "attempt"}); e != nil {
				t.Fatalf("repaired record cannot retry: %v", e)
			}
		})
	}
}
func TestMigrationNetwork_MultiNICMappingAndDefinitions(t *testing.T) {
	s, _, v, _, _ := moveFixture(t)
	ctx := context.Background()
	if e := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "multi", HostName: s.hostName, State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "multi", NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:AA:00:01"}, {VMName: "multi", NetworkName: "missing", Ordinal: 1, MAC: "52:54:00:aa:00:02"}, {VMName: "multi", NetworkName: "absent-nic", Ordinal: 2, MAC: "52:54:00:aa:00:03"}}, nil); e != nil {
		t.Fatal(e)
	}
	live := `<domain><name>multi</name><devices><interface type="bridge"><mac address="52:54:00:aa:00:01"/><source bridge="sourcebr"/></interface><interface type="bridge"><mac address="52:54:00:aa:00:02"/><source bridge="rawbr"/></interface></devices></domain>`
	persist := `<domain><name>multi</name><devices><interface type="bridge"><mac address="52:54:00:AA:00:01"/><source bridge="persistbr"/></interface></devices></domain>`
	v.SetActiveXML("multi", live)
	v.SetInactiveXML("multi", persist)
	v.SetState("multi", "running")
	served := s.servedNetworkDevices(ctx, "multi")
	if len(served) != 1 || served["lan"] != "oldbr" {
		t.Fatalf("missing network invented device: %v", served)
	}
	served["absent-nic"] = "oldbr"
	m := s.migrationNICBridges(ctx, "multi", served)
	if len(m) != 1 || m["52:54:00:AA:00:01"] != "oldbr" {
		t.Fatalf("MAC/missing NIC mapping: %v", m)
	}
	a, b, e := libvirt.MigrationDefinitionsFor(libvirt.MigrateParams{NICBridges: m}, live, persist)
	if e != nil {
		t.Fatal(e)
	}
	if libvirt.InterfaceBridges(a)["52:54:00:aa:00:01"] != "oldbr" || libvirt.InterfaceBridges(b)["52:54:00:aa:00:01"] != "oldbr" || libvirt.InterfaceBridges(a)["52:54:00:aa:00:02"] != "rawbr" {
		t.Fatalf("live/persistent mapping: %s %s", a, b)
	}
}

func TestMigrationNetwork_ArrivalTransfersToObservedOwner(t *testing.T) {
	s, p, v, _, next := moveFixture(t)
	p.fail = map[string]error{}
	ctx := adminCtx()
	if e := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "arrival", HostName: "source", State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "arrival", NetworkName: "lan", MAC: "52:54:00:00:00:ab"}}, nil); e != nil {
		t.Fatal(e)
	}
	x := `<domain><name>arrival</name><devices><interface><mac address="52:54:00:00:00:ab"/><source bridge="oldbr"/></interface></devices></domain>`
	// A stale stopped target definition is not evidence that this attempt arrived.
	v.SetInactiveXML("arrival", x)
	v.SetState("arrival", "stopped")
	if _, e := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "arrival", WantNetworkDevices: true, NetworkArrivalId: "attempt"}); e != nil {
		t.Fatal(e)
	}
	if len(s.networkArrivalUsers(ctx)["oldbr"].running) == 0 {
		t.Fatal("stale stopped target consumed future holder")
	}
	v.SetActiveXML("arrival", x)
	v.SetState("arrival", "running")
	if len(s.networkArrivalUsers(ctx)["oldbr"].running) == 0 {
		t.Fatal("uncommitted target consumed future holder")
	}
	if e := corrosion.TransferVMOwnerFresh(ctx, s.db, "arrival", s.hostName, "running"); e != nil {
		t.Fatal(e)
	}
	if len(s.networkArrivalUsers(ctx)) != 0 {
		t.Fatal("observed committed arrival did not hand off")
	}
	if _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); e == nil {
		t.Fatal("actual running domain ceased being holder")
	}
	v.SetState("arrival", "stopped")
	if _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); e != nil {
		t.Fatalf("stopped arrived domain cannot follow: %v", e)
	}
}
