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
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"copies": {Driver: driver, Source: target},
		"src":    {Driver: driver, Source: "srcpool"},
	})
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
	// Imported under a fresh name of its own, then renamed into place.
	var incoming string
	var renamed bool
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "rbd import-diff") {
			t.Errorf("a full copy applied a diff onto an existing image: %q", c)
			continue
		}
		if rest, ok := strings.CutPrefix(c, "rbd import -- - "); ok {
			incoming = rest
			if !strings.HasPrefix(rest, dst+".litevirt-incoming-") {
				t.Errorf("import argv %q, want a fresh name beside %q", c, dst)
			}
		}
		if strings.HasPrefix(c, "rbd rename") {
			renamed = true
			if c != "rbd rename -- "+incoming+" "+dst {
				t.Errorf("rename argv %q, want %q", c, "rbd rename -- "+incoming+" "+dst)
			}
		}
	}
	if incoming == "" || !renamed {
		t.Errorf("import into %q, renamed=%v: want an import then a rename into place", incoming, renamed)
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

// I-4: a ceph copy between two clusters runs the source side (snapshot,
// export) with the SOURCE pool's conf and keyring, and the destination side
// (info, import, image-meta) with the destination's.
func TestReplicateVolume_NativeCephUsesEachSidesOwnCredentials(t *testing.T) {
	log := fakeCLI(t)
	s := testServer(t)
	s.hostName = "test-host"
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"src":    {Driver: "ceph", Source: "rbd", Options: map[string]string{"conf": "/etc/ceph/a.conf", "keyring": "/etc/ceph/a.keyring", "id": "a"}},
		"copies": {Driver: "ceph", Source: "copies", Options: map[string]string{"conf": "/etc/ceph/b.conf", "keyring": "/etc/ceph/b.keyring", "id": "b"}},
	})
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped", Project: "a", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: "rbd:rbd/vm1-root",
			SizeBytes: 1 << 20, StorageType: "ceph", StorageVolume: "src"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("cross-cluster native ceph copy: %v", err)
	}
	srcCreds := "rbd --id a --conf /etc/ceph/a.conf --keyring /etc/ceph/a.keyring "
	dstCreds := "rbd --id b --conf /etc/ceph/b.conf --keyring /etc/ceph/b.keyring "
	seen := map[string]bool{}
	for _, c := range calls(t, log) {
		for _, sub := range []string{"snap create", "export", "snap rm"} {
			if strings.Contains(c, " "+sub+" ") {
				seen[sub] = true
				if !strings.HasPrefix(c, srcCreds) {
					t.Errorf("source-side %q ran as %q, want the source pool's credentials", sub, c)
				}
			}
		}
		for _, sub := range []string{"info", "import", "image-meta", "rename"} {
			if strings.Contains(c, " "+sub+" ") {
				seen[sub] = true
				if !strings.HasPrefix(c, dstCreds) {
					t.Errorf("destination-side %q ran as %q, want the destination pool's credentials", sub, c)
				}
			}
		}
	}
	for _, sub := range []string{"snap create", "export", "snap rm", "info", "import", "image-meta", "rename"} {
		if !seen[sub] {
			t.Errorf("no rbd %s ran", sub)
		}
	}
}

// m3: the per-call source snapshot is destroyed after a zfs copy.
func TestReplicateVolume_NativeZFSRemovesItsSnapshot(t *testing.T) {
	log := fakeCLI(t)
	s, alice := nativeVM(t, "zfs", "/dev/zvol/tank/vm1-root", "backup/copies")
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}); err != nil {
		t.Fatal(err)
	}
	var snap, destroyed string
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "zfs snapshot -- tank/vm1-root@litevirt-2") {
			snap = strings.TrimPrefix(c, "zfs snapshot -- ")
		}
		if strings.HasPrefix(c, "zfs destroy -- tank/vm1-root@litevirt-2") {
			destroyed = strings.TrimPrefix(c, "zfs destroy -- ")
		}
	}
	if snap == "" || snap != destroyed {
		t.Errorf("snapshot %q, destroyed %q: the per-call snapshot must be destroyed", snap, destroyed)
	}
}

// m3: a full ceph copy whose import fails removes only the image it created —
// never the destination name, which an image created in between may hold.
func TestReplicateVolume_NativeCephFailedImportNeverRemovesTheDestination(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
echo "$(basename "$0") $*" >> ` + logPath + `
for a in "$@"; do
  case "$a" in
    info) exit 1 ;;
    export) echo stream; exit 0 ;;
    import) cat >/dev/null; echo "rbd: image exists" >&2; exit 1 ;;
  esac
done
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "rbd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	s, _ := nativeVM(t, "ceph", "rbd:rbd/vm1-root", "copies")
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: "db-root"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
	if err == nil {
		t.Fatal("a failed import reported success")
	}
	for _, c := range calls(t, logPath) {
		if strings.Contains(c, " rm ") && strings.HasSuffix(c, " copies/db-root") {
			t.Errorf("the destination name was removed after a failed import: %q", c)
		}
	}
}

// m2: a pool-less ceph disk names its cluster and identity in its own path;
// the copy's source side runs with those, never the destination's.
func TestReplicateVolume_NativeCephPoolLessSourceUsesItsPathCredentials(t *testing.T) {
	log := fakeCLI(t)
	s := testServer(t)
	s.hostName = "test-host"
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"copies": {Driver: "ceph", Source: "copies", Options: map[string]string{"conf": "/etc/ceph/b.conf", "keyring": "/etc/ceph/b.keyring", "id": "b"}},
	})
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped", Project: "a", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "rbd:rbd/vm1-root:conf=/etc/ceph/a.conf:keyring=/etc/ceph/a.keyring:id=a", SizeBytes: 1 << 20, StorageType: "ceph"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("native ceph copy of a pool-less disk: %v", err)
	}
	srcCreds := "rbd --id a --conf /etc/ceph/a.conf --keyring /etc/ceph/a.keyring "
	seen := false
	for _, c := range calls(t, log) {
		if strings.Contains(c, " snap create ") || strings.Contains(c, " export ") {
			seen = true
			if !strings.HasPrefix(c, srcCreds) {
				t.Errorf("source-side call %q, want the credentials the disk's path names", c)
			}
		}
	}
	if !seen {
		t.Error("no source-side call ran")
	}
}
