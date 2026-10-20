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

// peerMigrationTLSStatusConcurrency bounds the peers one report asks at once.
const peerMigrationTLSStatusConcurrency = 8

// SetMigrationTLSStatus sets the hook that reports this host's migration
// credentials (the daemon reads them with pki.InspectMigrationTLS).
func (s *Server) SetMigrationTLSStatus(fn func() *pb.MigrationTLSHostStatus) {
	s.migrationTLSStatus = fn
}

// SetMigrationTLSCheck sets the read-only hook that says why this host's
// daemon could not install its migration credentials, without installing
// them (the daemon runs pki.CheckQemuMigrationTLS). nil reports nothing.
func (s *Server) SetMigrationTLSCheck(fn func() error) { s.migrationTLSCheck = fn }

func (s *Server) localMigrationTLSStatus() *pb.MigrationTLSHostStatus {
	row := &pb.MigrationTLSHostStatus{Error: "this host cannot report its migration credentials"}
	if s.migrationTLSStatus != nil {
		row = s.migrationTLSStatus()
	}
	// Say what this daemon would install, not only what its files hold: a
	// refused /etc/pki/qemu or an unresolvable QEMU user must hold a
	// rotation's gate. The check writes nothing; installing stays on the
	// storage-migration and start-up paths.
	if row.GetError() == "" && s.migrationTLSCheck != nil {
		if err := s.migrationTLSCheck(); err != nil {
			row.InstallError = err.Error()
		}
	}
	row.Host = s.hostName
	row.AllowUnencryptedStorage = s.allowPlaintextStorageMigration
	return row
}

// MigrationTLSStatus reports every host's migration credentials: this one
// directly, every other host by asking it with local_only set. A host that
// cannot answer is a row with an error, never a failed call. It is read-only
// on every host, so a peer or a viewer may ask.
func (s *Server) MigrationTLSStatus(ctx context.Context, req *pb.MigrationTLSStatusRequest) (*pb.MigrationTLSStatusResponse, error) {
	if err := s.requirePeerOrRole(ctx, "viewer"); err != nil {
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
	sem := make(chan struct{}, peerMigrationTLSStatusConcurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		if h.Name == s.hostName {
			rows[i] = s.localMigrationTLSStatus()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			rows[i] = s.peerMigrationTLSStatus(ctx, name)
		}(i, h.Name)
	}
	wg.Wait()
	return &pb.MigrationTLSStatusResponse{Hosts: rows}, nil
}

func (s *Server) peerMigrationTLSStatus(ctx context.Context, name string) *pb.MigrationTLSHostStatus {
	ctx, cancel := context.WithTimeout(ctx, peerMigrationTLSStatusTimeout)
	defer cancel()
	client, conn, err := s.peerClient(ctx, name)
	if err != nil {
		return peerStatusRow(name, nil, err)
	}
	defer conn.Close()
	resp, err := client.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{LocalOnly: true})
	return peerStatusRow(name, resp, err)
}

// peerStatusRow is name's row from its answer: the one row it gave for itself,
// or an error row naming why not. A peer never speaks for another host.
func peerStatusRow(name string, resp *pb.MigrationTLSStatusResponse, err error) *pb.MigrationTLSHostStatus {
	failed := func(format string, a ...any) *pb.MigrationTLSHostStatus {
		return &pb.MigrationTLSHostStatus{Host: name, Error: fmt.Sprintf(format, a...)}
	}
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
