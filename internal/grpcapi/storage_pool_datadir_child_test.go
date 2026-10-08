package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/storage"
)

func storageDataDirOwned() []string { return storage.DataDirOwned() }

// lab-recheck-5 FAILs 2 and 3. Main (3e4ba50b) let an admin put a dir pool at
// <data_dir>/<x> — `lv pool create rc5pool --driver dir --target
// /var/lib/litevirt/rc5pool`, which then held a VM disk and an uploaded ISO.
// After the hardening the whole data directory was refused, so that pool was
// "refused … nothing lists, reads or writes it — recreate the pool", and a
// new one there could not be made. Only the daemon's own state there is
// refused now (storage.dataDirOwned); another child is an ordinary host path,
// which still needs storage.hostpath (admin) to name.

// A main-era pool record at <data_dir>/rc5pool lists, takes writes, takes an
// upload, and a VM in its project boots an ISO from it — with no recreate.
//
// Red against 1c105363: checkPoolForWrite → `pool "rc5pool" is refused
// ("…/rc5pool" is inside the daemon's data directory …; only its disks/,
// pools/ and mounts/ hold pools): nothing lists, reads or writes it —
// recreate the pool`.
func TestPoolDataDirChild_AMainEraPoolThereWorksAgain(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	dir := filepath.Join(s.dataDir, "rc5pool")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePoolFile(t, filepath.Join(dir, "rc5-poolvm-root.qcow2"), "a main-era disk")
	registerPool(t, s, "rc5pool", "dir", "", dir, "acme")
	ref, ok := s.resolvePool(t.Context(), "rc5pool")
	if !ok {
		t.Fatal("the pool does not resolve")
	}
	if err := s.checkPoolForWrite(t.Context(), "rc5pool", ref); err != nil {
		t.Fatalf("the main-era pool at <data_dir>/rc5pool is refused: %v", err)
	}
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "rc5pool"}); err != nil {
		t.Fatalf("listing it: %v", err)
	}
	if err := uploadAs(adminCtx(), s, "rc5pool", "rc5-pool-upload.iso", isoBody); err != nil {
		t.Fatalf("an upload into it: %v", err)
	}
	if _, err := s.CreateVM(pat, isoCreate("inst", "rc5pool/rc5-pool-upload.iso", "acme")); err != nil {
		t.Fatalf("CreateVM with the pool's ISO: %v", err)
	}
	if _, err := s.PrepareHardwareForStart(t.Context(), vmRecord(t, s, "inst")); err != nil {
		t.Fatalf("start with the pool's ISO: %v", err)
	}
}

// An admin may create a pool there again; anyone without storage.hostpath may
// not name it; and the daemon's own state there is refused to an admin too.
//
// Red against 1c105363 (admin case): InvalidArgument `"…/rc5pool2" is inside
// the daemon's data directory …; only its disks/, pools/ and mounts/ hold
// pools`.
func TestPoolDataDirChild_CreateThereIsAnAdminsHostPath(t *testing.T) {
	s := newPoolTestServer(t)
	target := filepath.Join(s.dataDir, "rc5pool2")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if _, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{
		Name: "p", Driver: "dir", Target: target, Project: "acme",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a project operator naming <data_dir>/rc5pool2: got %v, want PermissionDenied", err)
	}
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "rc5pool2", Driver: "dir", Target: target,
	}); err != nil {
		t.Fatalf("an admin creating a dir pool at <data_dir>/rc5pool2: %v", err)
	}

	owned := []string{"", "pki", "vms", "state.db", "state.db-wal", "images", "imports", "imports/staging",
		"import-placements", "iso-identity", "audit-seeded-assert", "split_brain_activated.voter_config_v1",
		"pools", "mounts", "disks/.replicas", "disks/uploads", ".pool-uploads.json-1"}
	for _, name := range storageDataDirOwned() {
		owned = append(owned, name, filepath.Join(name, "sub"))
	}
	for _, name := range owned {
		t.Run("owned/"+name, func(t *testing.T) {
			p := filepath.Join(s.dataDir, name)
			if err := os.MkdirAll(p, 0o755); err != nil && !os.IsExist(err) {
				t.Fatal(err)
			}
			_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "q", Driver: "dir", Target: p})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("an admin aiming a pool at %s: got %v, want InvalidArgument", p, err)
			}
		})
	}
}
