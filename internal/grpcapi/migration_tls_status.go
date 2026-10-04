package grpcapi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// peerMigrationTLSStatusTimeout bounds one peer's answer, so one hung host
// cannot hold the whole report.
const peerMigrationTLSStatusTimeout = 10 * time.Second

// SetMigrationTLSStatus sets the hook that reports this host's migration
// credentials (the daemon reads them with pki.InspectMigrationTLS).
func (s *Server) SetMigrationTLSStatus(fn func() *pb.MigrationTLSHostStatus) {
	s.migrationTLSStatus = fn
}

func (s *Server) localMigrationTLSStatus() *pb.MigrationTLSHostStatus {
	row := &pb.MigrationTLSHostStatus{Error: "this host cannot report its migration credentials"}
	if s.migrationTLSStatus != nil {
		row = s.migrationTLSStatus()
	}
	row.Host = s.hostName
	row.AllowUnencryptedStorage = s.allowPlaintextStorageMigration
	return row
}

// MigrationTLSStatus reports every host's migration credentials: this one
// directly, every other host by asking it with local_only set. A host that
// cannot answer is a row with an error, never a failed call.
func (s *Server) MigrationTLSStatus(ctx context.Context, req *pb.MigrationTLSStatusRequest) (*pb.MigrationTLSStatusResponse, error) {
	if req.GetLocalOnly() && s.requirePeerCert(ctx) == nil {
		return &pb.MigrationTLSStatusResponse{Hosts: []*pb.MigrationTLSHostStatus{s.localMigrationTLSStatus()}}, nil
	}
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.GetLocalOnly() {
		return &pb.MigrationTLSStatusResponse{Hosts: []*pb.MigrationTLSHostStatus{s.localMigrationTLSStatus()}}, nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}
	rows := make([]*pb.MigrationTLSHostStatus, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		if h.Name == s.hostName {
			rows[i] = s.localMigrationTLSStatus()
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			rows[i] = s.peerMigrationTLSStatus(ctx, name)
		}(i, h.Name)
	}
	wg.Wait()
	return &pb.MigrationTLSStatusResponse{Hosts: rows}, nil
}

func (s *Server) peerMigrationTLSStatus(ctx context.Context, name string) *pb.MigrationTLSHostStatus {
	ctx, cancel := context.WithTimeout(ctx, peerMigrationTLSStatusTimeout)
	defer cancel()
	failed := func(format string, a ...any) *pb.MigrationTLSHostStatus {
		return &pb.MigrationTLSHostStatus{Host: name, Error: fmt.Sprintf(format, a...)}
	}
	client, conn, err := s.peerClient(ctx, name)
	if err != nil {
		return failed("unreachable: %v", err)
	}
	defer conn.Close()
	resp, err := client.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{LocalOnly: true})
	if status.Code(err) == codes.Unimplemented {
		return failed("its build cannot report migration TLS; upgrade it")
	}
	if err != nil {
		return failed("unreachable: %v", err)
	}
	if len(resp.GetHosts()) != 1 || resp.GetHosts()[0].GetHost() != name {
		return failed("answered for %d host(s), not for itself", len(resp.GetHosts()))
	}
	return resp.GetHosts()[0]
}
