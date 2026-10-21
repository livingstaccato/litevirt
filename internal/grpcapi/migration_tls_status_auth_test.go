package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// statusServer is a test server whose migration-TLS hooks count their calls:
// install (the real write into /etc/pki/qemu) and check (read-only).
func statusServer(t *testing.T) (s *Server, installs, checks *int) {
	t.Helper()
	s = testServer(t)
	s.hostName = "node-1"
	installs, checks = new(int), new(int)
	s.SetMigrationTLSStatus(func() *pb.MigrationTLSHostStatus {
		return &pb.MigrationTLSHostStatus{Provisioned: true}
	})
	s.SetMigrationTLS(func() (bool, error) { *installs++; return true, nil })
	s.SetMigrationTLSCheck(func() error { *checks++; return errors.New("cannot tell which user QEMU runs as") })
	return s, installs, checks
}

// Neither form of the call is open to a caller without a role, or to one
// holding only a scoped token (which no role gate can evaluate).
//
// Mutations: drop the gate (R1) — the anonymous fan-out is answered; answer
// local_only before the gate (R2) — the anonymous local_only call is answered.
func TestMigrationTLSStatus_RefusesACallerWithoutARole(t *testing.T) {
	s, _, _ := statusServer(t)
	scoped := context.WithValue(userCtx("op", "operator"), ctxKeyScopePaths, []string{"/projects/x"})
	for name, ctx := range map[string]context.Context{"anonymous": context.Background(), "scoped token": scoped} {
		for _, local := range []bool{false, true} {
			_, err := s.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{LocalOnly: local})
			if c := status.Code(err); c != codes.PermissionDenied && c != codes.Unauthenticated {
				t.Errorf("%s, local_only=%v: err = %v; want refused", name, local, err)
			}
		}
	}
}

// A viewer and a peer are both answered, and the answer never runs the
// installer: the read-only check fills install_error instead. A status call
// is a read; installing stays on the migration and start-up paths.
//
// Mutation: run s.migrationTLS() in localMigrationTLSStatus — installs != 0.
func TestMigrationTLSStatus_IsReadOnlyForViewersAndPeers(t *testing.T) {
	s, installs, checks := statusServer(t)
	for name, ctx := range map[string]context.Context{"viewer": viewerCtx(), "peer": peerCtxFor(t, s, "node-2")} {
		resp, err := s.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{LocalOnly: true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(resp.GetHosts()) != 1 || !strings.Contains(resp.GetHosts()[0].GetInstallError(), "QEMU runs as") {
			t.Errorf("%s: rows = %v; want this host's row with the check's refusal", name, resp.GetHosts())
		}
	}
	if *installs != 0 {
		t.Fatalf("a status call ran the migration-TLS installer %d time(s)", *installs)
	}
	if *checks != 2 {
		t.Errorf("read-only check ran %d time(s); want 2", *checks)
	}
}

// A peer's answer is used only when it is one row, for that peer. Anything
// else is an error row: a peer must not speak for another host.
//
// Mutation: drop the name check from peerStatusRow (R3) — the row for
// node-3 is accepted as node-2's.
func TestPeerStatusRow_RefusesAnAnswerForAnotherHost(t *testing.T) {
	ok := &pb.MigrationTLSStatusResponse{Hosts: []*pb.MigrationTLSHostStatus{{Host: "node-2", Provisioned: true}}}
	if r := peerStatusRow("node-2", ok, nil); r.GetError() != "" || !r.GetProvisioned() {
		t.Fatalf("own answer = %v; want it as is", r)
	}
	for name, tc := range map[string]struct {
		resp *pb.MigrationTLSStatusResponse
		err  error
	}{
		"another host": {&pb.MigrationTLSStatusResponse{Hosts: []*pb.MigrationTLSHostStatus{{Host: "node-3", Provisioned: true}}}, nil},
		"two rows": {&pb.MigrationTLSStatusResponse{Hosts: []*pb.MigrationTLSHostStatus{
			{Host: "node-2"}, {Host: "node-3"}}}, nil},
		"old build":   {nil, status.Error(codes.Unimplemented, "unknown method")},
		"unreachable": {nil, status.Error(codes.Unavailable, "connection refused")},
	} {
		r := peerStatusRow("node-2", tc.resp, tc.err)
		if r.GetHost() != "node-2" || r.GetError() == "" || r.GetProvisioned() {
			t.Errorf("%s: row = %v; want an error row for node-2 and nothing else", name, r)
		}
	}
}
