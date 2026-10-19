package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// sourceCtx is an admin call from cluster host cn, as a move's source makes.
func sourceCtx(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: cn, Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost(%s): %v", cn, err)
	}
	return context.WithValue(adminCtx(), ctxKeyMTLSCommonName, cn)
}

// A move's target whose replica has not yet received the commit that made the
// move's source the VM's owner (round-12 review M1): EnsureDisks waits for it
// before it records the stub, so the record is bound to the move's own mark,
// and the move's cleanup still recognises and removes the stub. Without the
// wait the record carried the previous owner's mark, the commit then changed
// it, and the stub was stranded: refused by every retry, left by every
// cleanup.
//
// Mutation: drop the wait (awaitCallerOwns returns at once) — the cleanup
// leaves the stub, red.
func TestEnsureDisks_WaitsForTheCommitThatMadeItsCallerTheOwner(t *testing.T) {
	setMoveCatchUp(t, 10*time.Second)
	s, disks := stubTarget(t) // "mig" on src-host
	ctx := sourceCtx(t, s, "next-host")
	p := filepath.Join(disks, "mig-root.qcow2")

	committed := make(chan struct{})
	go func() {
		defer close(committed)
		time.Sleep(300 * time.Millisecond)
		_, _ = corrosion.CommitMigrationOwnership(context.Background(), s.db, "mig", "src-host", "next-host", "running", nil)
	}()
	if r, err := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "mig", Disks: []*pb.DiskStub{{Path: p, SizeBytes: 1 << 20}}}); err != nil || len(r.CreatedPaths) != 1 {
		t.Fatalf("EnsureDisks from next-host = %v, %v; want the stub made", r, err)
	}
	<-committed // the commit has arrived here, during the move
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "mig"); vm == nil || vm.HostName != "next-host" {
		t.Fatalf("fixture: mig is on %v, want next-host", vm)
	}
	if _, err := s.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{VmName: "mig", DiskPaths: []string{p}}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("the move's own stub was left after its cleanup (stat: %v): its record no longer names its move", err)
	}
}

// The wait is bounded, and only for a caller that is a cluster host: past the
// bound the stub is made and recorded all the same, and a caller that is no
// cluster host is not waited for.
func TestEnsureDisks_TheCatchUpWaitIsBounded(t *testing.T) {
	setMoveCatchUp(t, 300*time.Millisecond)
	s, disks := stubTarget(t)
	p := filepath.Join(disks, "mig-root.qcow2")

	start := time.Now()
	if r, err := s.EnsureDisks(sourceCtx(t, s, "next-host"), &pb.EnsureDisksRequest{VmName: "mig", Disks: []*pb.DiskStub{{Path: p, SizeBytes: 1 << 20}}}); err != nil || len(r.CreatedPaths) != 1 {
		t.Fatalf("EnsureDisks past the bound = %v, %v; want the stub made", r, err)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("EnsureDisks from a host the replica does not name returned after %v, before the bound", d)
	}
	if !s.madeHere(context.Background(), &s.migrationStubs, "mig", p) {
		t.Fatal("the stub made past the bound is not recorded")
	}

	setMoveCatchUp(t, time.Minute)
	q := filepath.Join(disks, "mig-data.qcow2")
	notAHost := context.WithValue(adminCtx(), ctxKeyMTLSCommonName, "alice")
	done := make(chan error, 1)
	go func() {
		_, err := s.EnsureDisks(notAHost, &pb.EnsureDisksRequest{VmName: "mig", Disks: []*pb.DiskStub{{Path: q, SizeBytes: 1 << 20}}})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("EnsureDisks from a caller that is no cluster host = %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("EnsureDisks waited on a caller that is no cluster host")
	}
}

func setMoveCatchUp(t *testing.T, d time.Duration) {
	t.Helper()
	old := moveCatchUp
	moveCatchUp = d
	t.Cleanup(func() { moveCatchUp = old })
}

// The placement mark changes on a move back to an earlier owner, which the
// owner and owner epoch alone do not (a live move commits without bumping the
// epoch), and on nothing else.
func TestStubMark_ChangesOnEveryMove(t *testing.T) {
	s, _ := stubTarget(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	ctx := context.Background()
	m0, ok := s.stubMark(ctx, "mig")
	if !ok {
		t.Fatal("no mark for mig")
	}
	if err := corrosion.UpdateVMState(ctx, s.db, "mig", "migrating", "to next-host"); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.stubMark(ctx, "mig"); m != m0 {
		t.Fatalf("a state write changed the mark: %q -> %q", m0, m)
	}
	for _, to := range []string{"next-host", "src-host"} {
		from := "src-host"
		if to == "src-host" {
			from = "next-host"
		}
		if ok, err := corrosion.CommitMigrationOwnership(ctx, s.db, "mig", from, to, "running", nil); err != nil || !ok {
			t.Fatalf("commit %s->%s: %v %v", from, to, ok, err)
		}
	}
	if m, _ := s.stubMark(ctx, "mig"); m == m0 {
		t.Fatalf("mark after a live move out and back = %q, the same as before it", m)
	}
}
