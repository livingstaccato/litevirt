package grpcapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The wait at its production bound, on the path every move takes: the caller
// is the VM's owner on this replica, so EnsureDisks neither waits nor fails
// to record its stub (round-13 concern 3: the suite zeroes the bound).
//
// Mutation: wait out the bound whoever the caller is — the call takes the
// full bound, red.
func TestEnsureDisks_AnOwnerCallerIsNotWaitedFor(t *testing.T) {
	setMoveCatchUp(t, 10*time.Second)
	s, disks := stubTarget(t) // "mig" on src-host
	p := filepath.Join(disks, "mig-root.qcow2")

	start := time.Now()
	if r, err := s.EnsureDisks(sourceCtx(t, s, "src-host"), &pb.EnsureDisksRequest{VmName: "mig", Disks: []*pb.DiskStub{{Path: p, SizeBytes: 1 << 20}}}); err != nil || len(r.CreatedPaths) != 1 {
		t.Fatalf("EnsureDisks from the owner = %v, %v; want the stub made", r, err)
	}
	if d := time.Since(start); d >= 5*time.Second {
		t.Fatalf("EnsureDisks from the VM's owner took %v: it waited for a catch-up it did not need", d)
	}
	if !s.madeHere(context.Background(), &s.migrationStubs, "mig", p) {
		t.Fatal("the owner's stub is not recorded")
	}
}
