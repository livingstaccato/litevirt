package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

type pingOnly struct {
	pb.UnimplementedLiteVirtServer
}

func (pingOnly) Ping(context.Context, *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{}, nil
}

// The production dial of a cold move's disk stream at the target's migration
// address: the certificate it presents names the CLUSTER address (127.0.0.1
// here), the connection goes to another address (127.0.0.2), and it must still
// verify, because the dial sets the cluster address as the authority. Dropping
// the authority makes the handshake fail, which dialColdPeer reports as a
// fallback.
//
// Mutation: drop grpc.WithAuthority(h.Address) in dialColdPeer - the dial no
// longer answers and a vm.migrate.network_fallback event is recorded.
func TestDialColdPeer_VerifiesTheClusterAddressWhileDialingTheMigrationAddress(t *testing.T) {
	dir := t.TempDir()
	caCrt, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCrt, caKey); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(caCrt, caKey, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "dst", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.PeerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterLiteVirtServer(srv, pingOnly{})
	go srv.Serve(l)
	t.Cleanup(srv.Stop)

	s := testServer(t)
	s.pkiDir = dir
	s.migrationNetwork = "10.20.0.0/24"
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "dst", Address: "127.0.0.1", GRPCPort: l.Addr().(*net.TCPAddr).Port, SSHUser: "root", State: "active", CertSerial: "s",
	}); err != nil {
		t.Fatal(err)
	}
	client, closer, err := s.dialColdPeer(ctx, "dst", "vm1", "127.0.0.2")
	if err != nil {
		t.Fatalf("dialColdPeer: %v", err)
	}
	defer closer()
	if _, err := client.Ping(ctx, &pb.PingRequest{}); err != nil {
		t.Fatalf("the connection does not answer: %v", err)
	}
	evs, _ := corrosion.ListVMEvents(ctx, s.db, "vm1", 10, "")
	for _, e := range evs {
		if e.Type == "vm.migrate.network_fallback" {
			t.Fatalf("the migration-address dial fell back: %s", e.Detail)
		}
	}
}
