package fleet

// A target's record of the disk stubs it made for a migration (the stub
// ledger) names a file as "this host's own stub, which a copy may replace".
// Lab 2 (lab2-drain-c82008fc anomaly 6) found it outliving the move that made
// it: a VM moved A→B→A→B within about 75 minutes had a stray file at its disk
// path on B silently overwritten, where a fresh target refuses it.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// migrateColdBetween cold-migrates os1 from from to to.
func (sc *coldStoppedScenario) migrateColdBetween(from, to *Node) error {
	st, err := sc.c.SelfClient(from).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: to.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// A VM moved to B, back to A, and to B again, with a stray file at its disk
// path on B by then: the third move is refused before the copy, naming the
// file, and the file is left exactly as it was. B made a stub for the first
// move, but that record is the first move's, not a later one's.
//
// Mutation: let a stub record outlive the move that made it (no binding to
// the VM's owner and owner epoch) — the third move replaces the stray, red.
func TestFleet_AStubRecordDoesNotOutliveItsMove(t *testing.T) {
	sc := newColdStoppedScenario(t)
	a, b := sc.src, sc.dst
	// The disk's directory is a disk-artifact root on both hosts (a dir pool
	// at the same path), so the VM can move back and forth.
	for _, n := range []*Node{a, b} {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: filepath.Dir(sc.disk)}})
	}
	if err := sc.migrateColdBetween(a, b); err != nil {
		t.Fatalf("move to %s: %v", b.Name, err)
	}
	if vm := sc.vm(t); vm.HostName != b.Name {
		t.Fatalf("os1 after the first move is on %s, want %s", vm.HostName, b.Name)
	}
	if err := sc.migrateColdBetween(b, a); err != nil {
		t.Fatalf("move back to %s: %v", a.Name, err)
	}
	if vm := sc.vm(t); vm.HostName != a.Name {
		t.Fatalf("os1 after the move back is on %s, want %s", vm.HostName, a.Name)
	}
	stray := sc.file(b, sc.disk)
	if _, err := os.Lstat(stray); !os.IsNotExist(err) {
		t.Fatalf("fixture: %s still holds os1's disk after it moved back (stat: %v)", b.Name, err)
	}
	if err := os.WriteFile(stray, []byte("a stray copy on the target"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := sc.migrateColdBetween(a, b)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "this migration did not create it") {
		t.Fatalf("third move over a stray file = %v, want FailedPrecondition naming the file", err)
	}
	if got, rerr := os.ReadFile(stray); rerr != nil || string(got) != "a stray copy on the target" {
		t.Fatalf("the stray file on %s changed (err %v, %q)", b.Name, rerr, got)
	}
	if vm := sc.vm(t); vm.HostName != a.Name {
		t.Fatalf("os1 after the refused move is on %s, want %s", vm.HostName, a.Name)
	}
}
