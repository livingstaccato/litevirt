package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubTarget is a migration target with VM "mig" running on another host.
func stubTarget(t *testing.T) (*Server, string) {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVM(t, adminCtx(), s.db, "mig", "src-host", "running")
	insertTestVM(t, adminCtx(), s.db, "other", "src-host", "running")
	return s, filepath.Join(s.dataDir, "disks")
}

func ensure(s *Server, vm string, stubs ...*pb.DiskStub) (*pb.EnsureDisksResponse, error) {
	return s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: vm, Disks: stubs})
}

// A stub EnsureDisks made for a VM is that VM's own: a retry reuses it (and
// reports it, so a failed retry still removes it), at the size asked for now.
// A file it did not make for that VM — another VM's stub included — is refused.
//
// Mutations: drop the ownership check (refuse every existing file) — the retry
// is refused and the test goes red; reuse a stub whatever its size — the
// resized retry keeps 1 MiB and goes red; accept any existing file — the other
// VM's request is not refused and goes red.
func TestEnsureDisks_ReusesItsOwnStubOnly(t *testing.T) {
	s, disks := stubTarget(t)
	p := filepath.Join(disks, "mig-root.qcow2")

	if r, err := ensure(s, "mig", &pb.DiskStub{Path: p, SizeBytes: 1 << 20}); err != nil || len(r.CreatedPaths) != 1 {
		t.Fatalf("first EnsureDisks = %v, %v; want the stub created", r, err)
	}
	r, err := ensure(s, "mig", &pb.DiskStub{Path: p, SizeBytes: 2 << 20})
	if err != nil || len(r.GetCreatedPaths()) != 1 || r.CreatedPaths[0] != p {
		t.Fatalf("retry EnsureDisks = %v, %v; want this host's own stub reused and reported", r, err)
	}
	if info, err := qcow2.Info(p); err != nil || info.VirtualSize != 2<<20 {
		t.Fatalf("reused stub = %+v, %v; want it at the 2 MiB asked for now", info, err)
	}
	if _, err := ensure(s, "other", &pb.DiskStub{Path: p, SizeBytes: 2 << 20}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("another VM's EnsureDisks over the stub = %v, want FailedPrecondition", err)
	}
}

// A file that was on the target before the migration is refused and left
// untouched, even where its size is exactly the one asked for.
func TestEnsureDisks_RefusesAFileItDidNotCreate(t *testing.T) {
	s, disks := stubTarget(t)
	p := filepath.Join(disks, "mig-root.qcow2")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)

	_, err := ensure(s, "mig", &pb.DiskStub{Path: p, SizeBytes: 1 << 20})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("EnsureDisks over an existing file = %v, want FailedPrecondition", err)
	}
	after, serr := os.Stat(p)
	if serr != nil || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the existing file was replaced or rewritten (err %v)", serr)
	}
}

// A call that fails part-way leaves nothing behind: the stubs it had created
// are removed and forgotten.
//
// Mutation: drop undo() on the create failure — the first stub stays and the
// test goes red.
func TestEnsureDisks_FailurePartWayLeavesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory; the scenario needs the create to fail")
	}
	s, disks := stubTarget(t)
	first := filepath.Join(disks, "mig-root.qcow2")
	// A directory the second stub cannot be created in. The path passes the
	// up-front checks (it does not exist), so the failure comes after the
	// first stub was made.
	ro := filepath.Join(disks, "ro")
	if err := os.MkdirAll(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	if _, err := ensure(s, "mig",
		&pb.DiskStub{Path: first, SizeBytes: 1 << 20},
		&pb.DiskStub{Path: filepath.Join(ro, "mig-data.qcow2"), SizeBytes: 1 << 20},
	); err == nil {
		t.Fatal("EnsureDisks succeeded; the scenario needs the second stub to fail")
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("the first stub was left behind by the failed call (stat err %v)", err)
	}
	if s.migrationStubs.owns("mig", first) {
		t.Fatal("the removed stub is still recorded as this host's")
	}
}

// The cleanup after a failed migration removes only a stub this host created
// for the VM — never a file that was already here, whatever the source names —
// and nothing at all of a VM that lives on this host.
//
// Mutations: drop the ownership check — "file already here" is removed and
// goes red; drop the lives-here check — the stub of a VM whose row names this
// host is removed and goes red.
func TestCleanupMigrationArtifacts_LeavesFilesItDidNotCreate(t *testing.T) {
	t.Run("file already here", func(t *testing.T) {
		s, disks := stubTarget(t)
		kept := filepath.Join(disks, "mig-root.qcow2")
		if err := os.MkdirAll(disks, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kept, []byte("disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
			VmName: "mig", DiskPaths: []string{kept},
		}); err != nil {
			t.Fatalf("CleanupMigrationArtifacts: %v", err)
		}
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("a disk this host did not create was removed: %v", err)
		}
	})
	t.Run("vm lives here", func(t *testing.T) {
		s, disks := stubTarget(t)
		s.virt = libvirtfake.New()
		p := filepath.Join(disks, "mig-root.qcow2")
		if _, err := ensure(s, "mig", &pb.DiskStub{Path: p, SizeBytes: 1 << 20}); err != nil {
			t.Fatal(err)
		}
		// The migration landed after all: the row now names this host.
		if err := s.db.Execute(adminCtx(), `UPDATE vms SET host_name = ? WHERE name = 'mig'`, s.hostName); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
			VmName: "mig", DiskPaths: []string{p},
		}); err != nil {
			t.Fatalf("CleanupMigrationArtifacts: %v", err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the disk of a VM that lives here was removed: %v", err)
		}
	})
}

// The cleanup removes a stub this host made for the VM even when the source
// does not name it — the source's EnsureDisks call was cut, so it never
// learned what was made — but only while nothing has written to it since: a
// recorded path a copy or a guest has written is a disk now.
//
// Mutations: take only the paths the source names — "untouched" is left and
// goes red; take every recorded path whatever has written to it — "written
// since" is removed and goes red.
func TestCleanupMigrationArtifacts_RemovesItsUnnamedStubsUntouchedSinceMade(t *testing.T) {
	for _, tc := range []struct {
		name        string
		writtenTo   bool
		wantRemoved bool
	}{
		{"untouched", false, true},
		{"written since", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, disks := stubTarget(t)
			p := filepath.Join(disks, "mig-root.qcow2")
			if _, err := ensure(s, "mig", &pb.DiskStub{Path: p, SizeBytes: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			if tc.writtenTo {
				later := time.Now().Add(time.Minute)
				if err := os.Chtimes(p, later, later); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
				VmName: "mig", RemoveCloudInit: true,
			}); err != nil {
				t.Fatalf("CleanupMigrationArtifacts: %v", err)
			}
			_, err := os.Stat(p)
			if removed := os.IsNotExist(err); removed != tc.wantRemoved {
				t.Fatalf("stub removed = %v (stat err %v), want %v", removed, err, tc.wantRemoved)
			}
		})
	}
}

// The unnamed-stub sweep reads the file it is about to remove: under a
// per-host disk root (SetHostDiskRootForTest, the fleet's seam) that is
// hostDiskFile(p), not p. Reading p skipped every unnamed stub there, so no
// fleet test could reach the sweep for a cold copy.
//
// Mutation: Lstat the recorded path again — the stub is left; red.
func TestCleanupMigrationArtifacts_SweepReadsTheFileItRemoves(t *testing.T) {
	s, disks := stubTarget(t)
	s.SetHostDiskRootForTest(t.TempDir())
	p := filepath.Join(disks, "mig-root.qcow2")
	f := s.hostDiskFile(p)
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(f, old, old); err != nil {
		t.Fatal(err)
	}
	s.migrationStubs.add("mig", p)
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{VmName: "mig"}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatalf("the unnamed stub under the host disk root was left (stat: %v)", err)
	}
}
