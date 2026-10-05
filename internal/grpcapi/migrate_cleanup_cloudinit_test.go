package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// stageGenisoimage puts a stand-in genisoimage first on PATH: EnsureCloudInit
// shells out to it, and test hosts need not ship the binary. It writes a
// marker to the -output path, which is all these tests read.
func stageGenisoimage(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"-output\" ]; then printf made > \"$2\"; shift; fi\n  shift\ndone\n"
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatalf("stage genisoimage: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// liveISO writes the VM's cloud-init ISO as a file this host already had.
func liveISO(t *testing.T, s *Server, vm string) (string, []byte) {
	t.Helper()
	iso := lv.CloudInitISOPath(s.dataDir, vm)
	if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("live seed of " + vm)
	if err := os.WriteFile(iso, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return iso, body
}

// cleanupISO sends the cleanup a failed migration's source sends: RemoveCloudInit.
func cleanupISO(t *testing.T, s *Server, vm string) {
	t.Helper()
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: vm, RemoveCloudInit: true,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
}

func assertISOKept(t *testing.T, iso string, want []byte, why string) {
	t.Helper()
	got, err := os.ReadFile(iso)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the cloud-init ISO was removed or changed (err %v): %s", err, why)
	}
}

// A cleanup is never allowed to delete the cloud-init ISO of a VM that lives
// on this host — its row names this host, or its domain is defined here. The
// guest boots from that ISO; deleting it breaks the VM's next boot. A cleanup
// can reach such a host: a migration back to the host the VM already runs on,
// an adopted cut-over, a duplicated cleanup that arrives after the VM landed.
//
// The disk stubs already obeyed this rule; the ISO did not.
//
// In both cases this host generated the ISO itself (EnsureCloudInit) and
// still holds the record, so the ownership check alone would remove it.
//
// Mutation: drop the vm-lives-here guard on the ISO — both subtests go red.
func TestCleanupMigrationArtifacts_KeepsTheCloudInitISOOfAVMThatLivesHere(t *testing.T) {
	stageGenisoimage(t)
	t.Run("row names this host", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		insertTestVM(t, adminCtx(), s.db, "home", s.hostName, "running")
		// This host generated it — as a migration target that then became the
		// VM's home — so only the vm-lives-here rule can keep it.
		if _, err := s.EnsureCloudInit(adminCtx(), &pb.EnsureCloudInitRequest{VmName: "home"}); err != nil {
			t.Fatalf("EnsureCloudInit: %v", err)
		}
		iso := lv.CloudInitISOPath(s.dataDir, "home")
		cleanupISO(t, s, "home")
		assertISOKept(t, iso, []byte("made"), "the VM's row names this host")
	})
	t.Run("domain defined here", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		fake := libvirtfake.New()
		s.virt = fake
		// The row still names the source (the cut-over has not committed),
		// but the guest is running here.
		insertTestVM(t, adminCtx(), s.db, "landed", "src-host", "running")
		if _, err := s.EnsureCloudInit(adminCtx(), &pb.EnsureCloudInitRequest{VmName: "landed"}); err != nil {
			t.Fatalf("EnsureCloudInit: %v", err)
		}
		fake.SetState("landed", "running")
		iso := lv.CloudInitISOPath(s.dataDir, "landed")
		cleanupISO(t, s, "landed")
		assertISOKept(t, iso, []byte("made"), "the VM's domain is defined here")
	})
}

// An ISO this host did not create as a migration target is not the cleanup's
// to remove, even for a VM that lives elsewhere: EnsureCloudInit found it
// already there (a residency the replicated row no longer reflects, or a
// restart that forgot the record) and left it alone, so the cleanup does too.
// A leaked ISO costs a few KiB; a deleted live one costs the guest its seed.
//
// Mutation: drop the ownership check on the ISO — the ISO is deleted and the
// test goes red.
func TestCleanupMigrationArtifacts_KeepsACloudInitISOItDidNotCreate(t *testing.T) {
	stageGenisoimage(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVM(t, adminCtx(), s.db, "mig", "src-host", "running")
	iso, body := liveISO(t, s, "mig")

	// The migration asks for it; it is already there, so nothing is created.
	if _, err := s.EnsureCloudInit(adminCtx(), &pb.EnsureCloudInitRequest{VmName: "mig"}); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	cleanupISO(t, s, "mig")
	assertISOKept(t, iso, body, "this host did not create it for the migration")
}

// The case the cleanup exists for still works: an ISO EnsureCloudInit created
// here for a VM that lives elsewhere is removed after the migration failed,
// and a second cleanup is harmless.
//
// Mutations: never remove the ISO, or do not record it in EnsureCloudInit —
// it stays and the test goes red; keep the record after removing it — the
// later file is deleted and the test goes red.
func TestCleanupMigrationArtifacts_RemovesTheCloudInitISOItCreated(t *testing.T) {
	stageGenisoimage(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVM(t, adminCtx(), s.db, "mig", "src-host", "running")
	if _, err := s.EnsureCloudInit(adminCtx(), &pb.EnsureCloudInitRequest{VmName: "mig"}); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	iso := lv.CloudInitISOPath(s.dataDir, "mig")
	if _, err := os.Stat(iso); err != nil {
		t.Fatalf("EnsureCloudInit made no ISO: %v", err)
	}
	cleanupISO(t, s, "mig")
	if _, err := os.Stat(iso); !os.IsNotExist(err) {
		t.Fatalf("the ISO this host created for the failed migration was left behind (stat err %v)", err)
	}
	cleanupISO(t, s, "mig")

	// Once removed it is forgotten: an ISO that appears at the path later
	// (the VM recreated here, say) is not this cleanup's.
	iso, body := liveISO(t, s, "mig")
	cleanupISO(t, s, "mig")
	assertISOKept(t, iso, body, "a later file at the path is not the stub that was removed")
}
