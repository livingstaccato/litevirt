package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Native zfs/ceph send/receive in ReplicateVolume, restored and secured: the
// destination is a NEW dataset/image the daemon names under the target pool,
// never the pool and never an existing one; the receive is never forced; every
// argv keeps "--" before its positionals; the copy carries its owner record.

// fakeCLI puts a fake zfs and rbd on PATH. Each call is appended to log as one
// line; "list"/"info" succeed only for a name listed in exists; send/export
// emit bytes; recv/import read them.
func fakeCLI(t *testing.T, exists ...string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	existsPath := filepath.Join(dir, "exists")
	if err := os.WriteFile(existsPath, []byte(strings.Join(exists, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
echo "$(basename "$0") $*" >> ` + logPath + `
last=""; for a in "$@"; do last="$a"; done
case "$1" in
  list|info) grep -qxF -- "$last" ` + existsPath + ` && exit 0; exit 1 ;;
  send|export) echo stream ;;
  recv|import) cat >/dev/null ;;
esac
# rbd puts auth options first; find the subcommand.
for a in "$@"; do
  case "$a" in
    info) grep -qxF -- "$last" ` + existsPath + ` && exit 0; exit 1 ;;
    export) echo stream; exit 0 ;;
    import) cat >/dev/null; exit 0 ;;
  esac
done
exit 0
`
	for _, bin := range []string{"zfs", "rbd"} {
		if err := os.WriteFile(filepath.Join(dir, bin), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath
}

func calls(t *testing.T, logPath string) []string {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// nativeVM is project A's VM "vm1" with its root disk on a block pool of
// driver, and a target pool "copies" of the same driver whose source is
// target.
func nativeVM(t *testing.T, driver, diskPath, target string) (*Server, context.Context) {
	t.Helper()
	s := testServer(t)
	s.hostName = "test-host"
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"copies": {Driver: driver, Source: target}})
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped", Project: "a", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: diskPath,
			SizeBytes: 1 << 20, StorageType: driver, StorageVolume: "src"}}); err != nil {
		t.Fatal(err)
	}
	return s, grantUser(t, s, "alice", "/projects/a", "Operator")
}

func TestReplicateVolume_NativeZFSWorksIntoAFreshDataset(t *testing.T) {
	log := fakeCLI(t)
	s, alice := nativeVM(t, "zfs", "/dev/zvol/tank/vm1-root", "backup/copies")
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"}, rec); err != nil {
		t.Fatalf("native zfs ReplicateVolume: %v", err)
	}
	dst := rec.Sent[len(rec.Sent)-1].TargetPath
	if !strings.HasPrefix(dst, "backup/copies/vm1-root-copy-") {
		t.Fatalf("destination %q, want a new dataset under the pool's", dst)
	}
	var recv, set int
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "zfs recv") {
			recv++
			if c != "zfs recv -- "+dst {
				t.Errorf("receive argv %q, want %q (never -F, always --)", c, "zfs recv -- "+dst)
			}
		}
		if strings.HasPrefix(c, "zfs set") {
			set++
			if !strings.HasPrefix(c, "zfs set -- litevirt:") || !strings.HasSuffix(c, " "+dst) {
				t.Errorf("record argv %q", c)
			}
		}
		if strings.Contains(c, " -F") {
			t.Errorf("a forced zfs operation ran: %q", c)
		}
	}
	if recv != 1 || set != 3 {
		t.Errorf("recv=%d set=%d, want 1 receive and the 3-field owner record", recv, set)
	}
}

func TestReplicateVolume_NativeCephWorksIntoAFreshImage(t *testing.T) {
	log := fakeCLI(t)
	s, alice := nativeVM(t, "ceph", "rbd:rbd/vm1-root", "copies")
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"}, rec); err != nil {
		t.Fatalf("native ceph ReplicateVolume: %v", err)
	}
	dst := rec.Sent[len(rec.Sent)-1].TargetPath
	if !strings.HasPrefix(dst, "copies/vm1-root-copy-") {
		t.Fatalf("destination %q, want a new image in the target pool", dst)
	}
	var imported bool
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "rbd import") {
			imported = true
			if c != "rbd import -- - "+dst {
				t.Errorf("import argv %q, want %q", c, "rbd import -- - "+dst)
			}
		}
		if strings.HasPrefix(c, "rbd import-diff") {
			t.Errorf("a full copy applied a diff onto an existing image: %q", c)
		}
	}
	if !imported {
		t.Error("no rbd import ran")
	}
}

// An admin may name the destination, but an existing dataset or image is
// refused before anything is sent — a copy never replaces one.
func TestReplicateVolume_NativeNeverReplacesAnExistingDestination(t *testing.T) {
	for _, tc := range []struct{ driver, disk, target, existing, leaf string }{
		{"zfs", "/dev/zvol/tank/vm1-root", "backup/copies", "backup/copies/db-root", "db-root"},
		{"ceph", "rbd:rbd/vm1-root", "copies", "copies/db-root", "db-root"},
	} {
		t.Run(tc.driver, func(t *testing.T) {
			log := fakeCLI(t, tc.existing)
			s, _ := nativeVM(t, tc.driver, tc.disk, tc.target)
			err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: tc.leaf},
				&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
			if status.Code(err) != codes.AlreadyExists {
				t.Errorf("native copy onto an existing destination: got %v, want AlreadyExists", err)
			}
			for _, c := range calls(t, log) {
				if strings.Contains(c, " recv") || strings.Contains(c, " import") || strings.Contains(c, " send") || strings.Contains(c, " export") {
					t.Errorf("something was sent or received toward an existing destination: %q", c)
				}
			}
		})
	}
}

// A project Operator still cannot name the destination at all.
func TestReplicateVolume_NativeTargetIsAdminOnly(t *testing.T) {
	log := fakeCLI(t)
	s, alice := nativeVM(t, "zfs", "/dev/zvol/tank/vm1-root", "backup/copies")
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: "db-root"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator naming a native destination: got %v, want PermissionDenied", err)
	}
	if c := calls(t, log); len(c) > 0 && c[0] != "" {
		t.Errorf("zfs was run for a refused request: %v", c)
	}
}
