package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// seedRestorableVM is a running VM rs on this host with snapshot s1 of the
// given type in the fake and in corrosion.
func seedRestorableVM(t *testing.T, s *Server, typ string) *libvirtfake.Fake {
	t.Helper()
	fake := s.virt.(*libvirtfake.Fake)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "rs", HostName: s.hostName, State: "running",
		Spec: `{"name":"rs","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	rec := corrosion.SnapshotRecord{ID: "rs-s1", VMName: "rs", HostName: s.hostName, Name: "s1", State: "ok", Type: typ}
	if typ == "memory" {
		rec.VMStatePath = filepath.Join(t.TempDir(), "rs-s1.save")
		if err := os.WriteFile(rec.VMStatePath, []byte("ram"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := fake.CreateLiveSnapshot("rs", "s1", rec.VMStatePath, nil); err != nil {
			t.Fatal(err)
		}
		fake.SetSavedImageXML(rec.VMStatePath, "<domain type='kvm'><name>rs</name><devices></devices></domain>")
	} else if _, err := fake.CreateSnapshot("rs", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(adminCtx(), s.db, rec); err != nil {
		t.Fatal(err)
	}
	return fake
}

// A restore takes the VM's domain down and brings it back. On the lab the
// reconciler saw the VM recorded running with no domain in that window and
// restarted it on the old overlay; the restore then reset a file the new
// qemu no longer read, and returned "domain is already running" with the
// guest not restored (snapshot-repro.md, incidental finding 1). Every start
// path takes the VM's start lease, so the restore holds it throughout.
func TestRestoreSnapshot_HoldsTheStartLeaseForTheWholeRevert(t *testing.T) {
	for _, typ := range []string{"disk", "memory"} {
		t.Run(typ, func(t *testing.T) {
			s := lockTestServer(t)
			fake := seedRestorableVM(t, s, typ)
			reverted := false
			fake.OnRevertSnapshot = func(domain, snap string) {
				reverted = true
				// The reconciler's own start path, mid-revert.
				heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now())
				if err != nil {
					t.Errorf("TryVMStartLease: %v", err)
					return
				}
				if heldBy == s.hostName {
					health.ReleaseVMStartLease(adminCtx(), s.db, s.hostName, "rs")
					t.Error("the reconciler took the VM's start lease in the middle of its restore, and would restart it")
				}
			}
			if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
				t.Fatalf("RestoreSnapshot: %v", err)
			}
			if !reverted {
				t.Fatal("the revert did not run")
			}
			heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now())
			if err != nil || heldBy != s.hostName {
				t.Fatalf("after the restore the start lease is held by %q (%v); it must be released", heldBy, err)
			}
		})
	}
}

// A start in progress holds the lease; the restore waits for nothing and is
// refused, naming the holder, before anything is torn down.
func TestRestoreSnapshot_RefusedWhileAStartHoldsTheLease(t *testing.T) {
	s := lockTestServer(t)
	fake := seedRestorableVM(t, s, "disk")
	if heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now()); err != nil || heldBy != s.hostName {
		t.Fatalf("setup: lease %q %v", heldBy, err)
	}
	_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RestoreSnapshot = %v, want FailedPrecondition while a start holds the lease", err)
	}
	for _, e := range fake.EventLog() {
		if e.Op == "revert" || e.Op == "revert-live" {
			t.Fatal("the revert ran while a start held the VM's start lease")
		}
	}
}
