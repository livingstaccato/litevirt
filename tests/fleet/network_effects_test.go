package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/network"
)

// The real peer RPC must update this node's modeled kernel, before and after
// rebuilding its server. TestMain's process-lifetime tripwire also refuses
// any fallback to the host bridge/arping executables.
func TestFleet_NetworkEffectsFDBSurvivesServerRebuild(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			restartNode(t, c, dst)
		}
		req := &pb.UpdateFDBRequest{Vni: 5178, Mac: "52:54:00:78:00:01", NewVtepIp: "192.0.2.8"}
		if _, err := c.PeerClient(src, dst).UpdateFDB(ctx, req); err != nil {
			t.Fatalf("phase %d add: %v", phase, err)
		}
		if got := dst.Net.FDBDestinations(5178, req.Mac); len(got) != 1 || got[0] != req.NewVtepIp {
			t.Fatalf("phase %d modeled FDB: %v", phase, got)
		}
		req.OldVtepIp, req.NewVtepIp = req.NewVtepIp, "192.0.2.9"
		if _, err := c.PeerClient(src, dst).UpdateFDB(ctx, req); err != nil {
			t.Fatalf("phase %d replace: %v", phase, err)
		}
		if got := dst.Net.FDBDestinations(5178, req.Mac); len(got) != 1 || got[0] != req.NewVtepIp {
			t.Fatalf("phase %d replaced FDB: %v", phase, got)
		}
		req.OldVtepIp, req.NewVtepIp = req.NewVtepIp, ""
		if _, err := c.PeerClient(src, dst).UpdateFDB(ctx, req); err != nil {
			t.Fatal(err)
		}
		if got := dst.Net.FDBDestinations(5178, req.Mac); len(got) != 0 {
			t.Fatalf("phase %d deleted FDB: %v", phase, got)
		}
	}
}

func TestFleet_NetworkEffectsPeerVTEPReplacesStaleRow(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	if err := network.UpsertVTEP(ctx, dst.DB, "effects-vxlan", src.Name, "192.0.2.7", 5178); err != nil {
		t.Fatal(err)
	}
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			restartNode(t, c, dst)
		}
		for _, addr := range []string{"192.0.2.8", "192.0.2.9"} {
			if _, err := c.PeerClient(src, dst).SyncVTEP(ctx, &pb.SyncVTEPRequest{NetworkName: "effects-vxlan", Vni: 5178, VtepIp: addr}); err != nil {
				t.Fatalf("phase %d sync: %v", phase, err)
			}
			if got := dst.Net.FDBDestinations(5178, "00:00:00:00:00:00"); len(got) != 1 || got[0] != addr {
				t.Fatalf("phase %d flood destinations: %v, want only pushed %s despite stale row", phase, got, addr)
			}
		}
	}
}

// The retained name now asserts the incoming target-gateway contract.
func TestFleet_NetworkEffectsMigrationRecordsGARP(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	def := compose.NetworkDef{Type: "bridge", Interface: "mvbr", Subnet: "192.0.2.0/24", DHCP: true}
	cfg, _ := json.Marshal(def)
	if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: "mover", HostName: src.Name, State: "running", Spec: `{"name":"mover","cpu":1,"memory_mib":512}`, CPUActual: 1, MemActual: 512}, []corrosion.InterfaceRecord{{VMName: "mover", NetworkName: "lan", MAC: "52:54:00:00:00:01", IP: "192.0.2.7"}}, nil); err != nil {
		t.Fatal(err)
	}
	reconcileNetworks(t, dst)
	src.Virt.SetState("mover", "running")
	src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error { dst.Virt.SetState(name, "running"); return nil }
	if err := migrateAt(t, c, src, "mover", dst.Name); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "target gateway frame", func() bool { return len(dst.Net.GatewayFrames("mvbr", "192.0.2.1")) == 1 })
	want, _ := network.GatewayARPFrame(network.BridgeMAC("mvbr"), netip.MustParseAddr("192.0.2.1"))
	if got := dst.Net.GatewayFrames("mvbr", "192.0.2.1"); len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("target frame intent: %x", got)
	}
	if len(src.Net.GatewayFrames("mvbr", "192.0.2.1")) != 0 || src.Net.GARPCount("lan", "192.0.2.7") != 0 {
		t.Fatal("source announced the departed guest")
	}
	src.Server.WaitGatewayAnnouncements()
	restartNode(t, c, dst)
	dst.Virt.SetState("mover", "running")
	reconcileNetworks(t, dst)
	if _, err := c.PeerClient(src, dst).AnnounceMigratedGuest(ctx, &pb.AnnounceMigratedGuestRequest{VmName: "mover"}); err != nil {
		t.Fatal(err)
	}
	if got := dst.Net.GatewayFrames("mvbr", "192.0.2.1"); len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("rebuilt server bypassed per-node frame model: %x", got)
	}
}

func TestFleet_GatewayAnnouncementDirectPeerOnly(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "gatebr", Subnet: "192.0.2.0/24", DHCP: true})
	if err := corrosion.UpsertNetwork(ctx, dst.DB, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, dst.DB, corrosion.VMRecord{Name: "g", HostName: dst.Name, State: "running", Spec: "{}"}, []corrosion.InterfaceRecord{{VMName: "g", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatal(err)
	}
	dst.Virt.SetState("g", "running")
	reconcileNetworks(t, dst)
	peer := c.PeerClient(src, dst)
	req := &pb.AnnounceMigratedGuestRequest{VmName: "g"}
	if _, err := peer.AnnounceMigratedGuest(ctx, req); err != nil {
		t.Fatal(err)
	}
	admin := c.SelfClient(dst)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "gateway-admin", Password: "test-fixture-password", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "gateway-admin", Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"authorization", pki.FwdBearerMDKey} {
		call := metadata.AppendToOutgoingContext(ctx, key, "Bearer "+tok.Token)
		if _, err := peer.AnnounceMigratedGuest(call, req); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s accepted as direct peer: %v", key, err)
		}
	}
	if _, err := c.bearerClient(dst, tok.Token).AnnounceMigratedGuest(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("nonpeer bearer accepted: %v", err)
	}

	dir := t.TempDir()
	cert, key := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if e := pki.GenerateClientCert(c.caCert, c.caKey, cert, key, "gateway-client"); e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	tlsCfg, e := pki.PeerTLSConfig(src.PKIDir)
	if e != nil {
		t.Fatal(e)
	}
	tlsCfg.GetClientCertificate = nil
	tlsCfg.Certificates = []tls.Certificate{pair}
	conn, e := grpc.NewClient(fmt.Sprintf("%s:%d", dst.Address, dst.Port), grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	ordinary := pb.NewLiteVirtClient(conn)
	if _, e := ordinary.ListHosts(ctx, &pb.ListHostsRequest{}); e != nil {
		t.Fatalf("ordinary certificate did not authenticate: %v", e)
	}
	if _, e := ordinary.AnnounceMigratedGuest(ctx, req); status.Code(e) != codes.PermissionDenied {
		t.Fatalf("ordinary client certificate accepted: %v", e)
	}
	if got := len(dst.Net.GatewayFrames("gatebr", "192.0.2.1")); got != 1 {
		t.Errorf("refused credential caused host effect: got %d packets", got)
	}
}

func TestFleet_MigrationArrivalCleanupKeepsAttemptThroughAdoption(t *testing.T) {
	for _, adopt := range []bool{false, true} {
		t.Run(fmt.Sprint("adopt=", adopt), func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			src, dst := c.Nodes[0], c.Nodes[1]
			ctx := context.Background()
			for _, n := range c.Nodes {
				setHostCapacity(t, c, n.Name, 64, 65536)
			}
			cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Interface: "arrivalbr", Subnet: "192.0.2.0/24", DHCP: true})
			if e := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); e != nil {
				t.Fatal(e)
			}
			if e := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: "pp1", HostName: src.Name, State: "running", Spec: `{"name":"pp1","cpu":1,"memory_mib":512}`, CPUActual: 1, MemActual: 512}, []corrosion.InterfaceRecord{{VMName: "pp1", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); e != nil {
				t.Fatal(e)
			}
			src.Virt.SetState("pp1", "running")
			prepared, cleaned := make(chan string, 1), make(chan string, 1)
			dst.HookUnary("EnsureDisks", func(ctx context.Context, r any, h grpc.UnaryHandler) (any, error) {
				out, e := h(ctx, r)
				prepared <- r.(*pb.EnsureDisksRequest).NetworkArrivalId
				return out, e
			})
			dst.HookUnary("CleanupMigrationArtifacts", func(ctx context.Context, r any, h grpc.UnaryHandler) (any, error) {
				out, e := h(ctx, r)
				cleaned <- r.(*pb.CleanupMigrationArtifactsRequest).NetworkArrivalId
				return out, e
			})
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			src.Virt.FailMigrateToTarget = func(string, string) error { close(entered); <-release; return errors.New("modeled migration failure") }
			watch := src.WatchStream("MigrateVM")
			handlerJoined, clientJoined := false, false
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			stream, e := c.SelfClient(src).MigrateVM(call, &pb.MigrateVMRequest{VmName: "pp1", TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE})
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() {
				for {
					if _, e := stream.Recv(); e != nil {
						done <- e
						return
					}
				}
			}()
			defer func() {
				unblock()
				cancel()
				if !handlerJoined {
					select {
					case <-watch.Returned:
						handlerJoined = true
					case <-time.After(3 * time.Second):
						t.Error("migration handler did not join")
					}
				}
				if !clientJoined {
					select {
					case <-done:
						clientJoined = true
					case <-time.After(3 * time.Second):
						t.Error("client receive worker did not join")
					}
				}
				f := &storageAbort{c: c, src: src, dst: dst}
				f.requireLockFree(t)
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("migration did not reach runtime")
			}
			var id string
			select {
			case id = <-prepared:
			case <-time.After(3 * time.Second):
				t.Fatal("preparation did not return")
			}
			if id == "" {
				t.Fatal("source did not assign arrival attempt")
			}
			if adopt {
				cancel()
				select {
				case <-watch.Returned:
					handlerJoined = true
				case <-time.After(3 * time.Second):
					t.Fatal("canceled handler not adopted")
				}
			}
			unblock()
			select {
			case e := <-done:
				clientJoined = true
				if e == nil {
					t.Fatal("expected failed migration")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("migration client did not join")
			}
			select {
			case got := <-cleaned:
				if got != id {
					t.Fatalf("cleanup changed attempt %q -> %q", id, got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cleanup did not arrive")
			}
		})
	}
}
