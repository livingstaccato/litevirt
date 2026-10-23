package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A host that cannot run workloads is refused as a migration target, with
// the host and the role or state named.
//
// Mutations: drop the IsWitness branch of nonWorkloadTargetError, so a witness
// reads as an active host - the witness row goes red; drop the state branch -
// the draining, maintenance and fenced rows go red.
func TestNonWorkloadTargetError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		h       corrosion.HostRecord
		refused bool
		mustSay []string
	}{
		{"worker", corrosion.HostRecord{Name: "w", State: "active", Role: "worker"}, false, nil},
		{"legacy empty role", corrosion.HostRecord{Name: "w", State: "active"}, false, nil},
		{"witness", corrosion.HostRecord{Name: "node-6", State: "active", Role: "witness"}, true, []string{"node-6", "witness"}},
		{"draining", corrosion.HostRecord{Name: "d", State: "draining", Role: "worker"}, true, []string{`"d"`, "not active", "draining"}},
		{"maintenance", corrosion.HostRecord{Name: "m", State: "maintenance"}, true, []string{"not active", "maintenance"}},
		{"fenced", corrosion.HostRecord{Name: "f", State: "fenced"}, true, []string{"not active", "fenced"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := nonWorkloadTargetError(&tc.h)
			if !tc.refused {
				if err != nil {
					t.Fatalf("got %v, want accepted", err)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("got %v, want FailedPrecondition", err)
			}
			for _, w := range tc.mustSay {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("refusal %q does not say %q", err, w)
				}
			}
		})
	}
}

func insertSelfHost(t *testing.T, s *Server, role string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: s.hostName, Address: "10.0.0.1", State: "active", Role: role,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
}

// The target decides for itself: an older source never checks the role, so a
// witness refuses every helper that stages a migration on it, before it creates
// anything. The same calls on a worker are not refused for a role (the control,
// so the refusal is the role and not a failure of the fixture).
//
// Mutations: authorizeMigrationTarget back to authorizeMigrationHelper in
// EnsureDisks, EnsureCloudInit or EnsureFirmwareState - that call goes red.
func TestMigrationTargetHelpers_AWitnessRefusesToStage(t *testing.T) {
	for _, role := range []string{"worker", "witness"} {
		t.Run(role, func(t *testing.T) {
			s, disks := stubTarget(t)
			insertSelfHost(t, s, role)
			if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "src-host", Address: "10.0.0.9", State: "active"}); err != nil {
				t.Fatal(err)
			}
			peer := replicationPeerCtx("src-host")
			stub := filepath.Join(disks, "mig-root.qcow2")
			calls := map[string]func() error{
				"EnsureDisks": func() error {
					_, err := s.EnsureDisks(peer, &pb.EnsureDisksRequest{VmName: "mig", Disks: []*pb.DiskStub{{Path: stub, SizeBytes: 1 << 20}}})
					return err
				},
				"EnsureCloudInit": func() error {
					_, err := s.EnsureCloudInit(peer, &pb.EnsureCloudInitRequest{VmName: "mig"})
					return err
				},
				"EnsureFirmwareState": func() error {
					_, err := s.EnsureFirmwareState(peer, &pb.EnsureFirmwareStateRequest{VmName: "mig", DomainXml: "<domain/>"})
					return err
				},
			}
			for name, call := range calls {
				err := call()
				if role == "witness" {
					if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "witness") || !strings.Contains(err.Error(), s.hostName) {
						t.Errorf("%s on a witness: got %v, want FailedPrecondition naming the host and its role", name, err)
					}
					continue
				}
				if err != nil && strings.Contains(err.Error(), "witness") {
					t.Errorf("%s on a worker mentions a witness: %v", name, err)
				}
			}
			if _, statErr := os.Stat(stub); role == "witness" && statErr == nil {
				t.Fatalf("a witness created the disk stub %s before refusing", stub)
			}
		})
	}
}

// Cleanup and rollback are not staging: a witness must still be able to take
// back what an earlier or older move left on it, so they never ask the role.
func TestMigrationCleanup_IsNotRefusedForAWitness(t *testing.T) {
	s, _ := stubTarget(t)
	insertSelfHost(t, s, "witness")
	_, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{VmName: "mig"})
	if err != nil && strings.Contains(err.Error(), "witness") {
		t.Fatalf("cleanup on a witness refused for its role: %v", err)
	}
}
