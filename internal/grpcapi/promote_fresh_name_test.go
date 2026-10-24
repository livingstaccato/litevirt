package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// promotedFiles is every file in poolDir a promotion of vm could have built.
func promotedFiles(t *testing.T, poolDir, vm string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(poolDir, vm+"-promoted-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A disk kept by `lv rm --keep-disks` after an earlier promotion from the
// same replica names, as its missing backing base, the path that promotion
// built: <vm>-promoted-<replica stem>.qcow2. A new promotion from that
// replica must not build there — the file would become the kept overlay's
// base and the kept disk would silently read the promoted data. It builds
// under a name no file has had, and goes ahead (it does not refuse, as other
// writers of a kept disk's path do).
//
// Red on a63cd2835: the promotion builds at the kept overlay's base path.
// Mutation "old name" (freshPromotedPath without its random part) — red.
func TestPromote_NeverBuildsAtAKeptOverlaysMissingBase(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	replica := seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	oldPath := filepath.Join(poolDir, "db-promoted-"+strings.TrimSuffix(replica, ".raw")+".qcow2")
	kept := filepath.Join(t.TempDir(), "db-root-kept.qcow2")
	if err := qcow2.CreateWithBackingFormat(kept, oldPath, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s.recordKeptDisks(adminCtx(), "db", []KeptDisk{{Path: kept, Disk: "root", Host: s.hostName,
		Reason: "kept by lv rm --keep-disks"}})

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	if _, err := os.Lstat(oldPath); !os.IsNotExist(err) {
		t.Errorf("the kept overlay's missing base %s was created (err=%v): the kept disk now reads the promoted data", oldPath, err)
	}
	if info, err := qcow2.Info(kept); err != nil || info.BackingFile != oldPath {
		t.Errorf("the kept overlay's header = %+v (%v), want its backing still %s", info, err, oldPath)
	}
	root := diskRowsOf(t, s, "db")["root"]
	if root.HostName != s.hostName || root.Path == oldPath || filepath.Dir(root.Path) != poolDir ||
		!strings.HasPrefix(filepath.Base(root.Path), "db-promoted-") {
		t.Fatalf("root row = %+v, want a promoted live disk in %s at another path than %s", root, poolDir, oldPath)
	}
	if fi, err := os.Lstat(root.Path); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the promoted VM's live disk %s: %v", root.Path, err)
	}
}

// Failover never blocks on the record of kept disks: a promotion goes ahead
// while kept-disks.json cannot be read, building where no file has been.
//
// Mutation "promote consults kept disks" (a keptPathRefusal of the live disk
// before the build) — red.
func TestPromote_GoesAheadWhileKeptDisksCannotBeRead(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	keptUnknown(t, s, "registry")

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	root := diskRowsOf(t, s, "db")["root"]
	if root.HostName != s.hostName || filepath.Dir(root.Path) != poolDir {
		t.Fatalf("root row = %+v, want it promoted into %s", root, poolDir)
	}
	if _, err := os.Stat(root.Path); err != nil {
		t.Errorf("the promoted live disk: %v", err)
	}
}
