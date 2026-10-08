package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// What claims a file at an imported disk's name is what records it — a disk
// row, an image, a pool's upload or replica record (storage_pool_confine.go),
// or a replica area's record (replica_records.go) — never a VM's name alone.

// A replica a pool record names is not an orphan, whatever its name and
// whether or not any VM is named like it.
func TestImportVM_APoolRecordedReplicaAtTheDisksNameIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp")
	plantOld(t, dst, "old's replica")
	if err := s.recordPoolReplica(context.Background(), "default", replicaKey{VM: "old", Disk: "root", Project: "default"}, dst); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp", dst, "old's replica")
}

// A user's upload a pool record names is not an orphan.
func TestImportVM_ARecordedUploadAtTheDisksNameIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp")
	plantOld(t, dst, "pat's upload")
	if err := s.recordPoolUpload(context.Background(), "default", "acme", "pat@local", dst); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp", dst, "pat's upload")
}

// A replica in a pool's replica area is the same file as the one at the
// disk's name (a hard link): it is recorded, not an orphan.
func TestImportVM_AFileAReplicaAreaRecordNamesIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp")
	rec := newReplicaRecord("acme", "web", "root", "web/default", "20261006-120000", "qcow2")
	area, err := publishRecordedReplica(context.Background(), filepath.Dir(dst), rec, func(tmp string) error {
		return os.WriteFile(tmp, []byte("web's replica"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(area, dst); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(dst, old, old); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp", dst, "web's replica")
}

// A quiet file nothing records is an orphan even when a VM's name prefixes
// it: the VM's name is not a record. It is moved aside and kept.
func TestImportVM_AnUnrecordedFileNamedLikeALiveVMIsAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "web-x")
	plantOld(t, dst, "nobody's")
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web", HostName: "other-host", Spec: "{}", State: "stopped", Project: "default",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := importAs(s, t, "web-x"); err != nil {
		t.Fatalf("a re-import over an unrecorded file named like VM web's: %v", err)
	}
	keptAside(t, dst, "nobody's")
}

// A replica exactly as a VM disk's runs name theirs (<vm>-<disk>-<stamp>),
// from before replicas were recorded, is that disk's replica (isReplicaFor),
// not an orphan.
func TestImportVM_ALegacyReplicaAtTheDisksNameIsNotAnOrphan(t *testing.T) {
	s, _ := orphanFixture(t, "web")
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web", HostName: "other-host", Spec: "{}", State: "stopped", Project: "default",
	}, nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "data", HostName: "other-host", Path: "/elsewhere/web-data.qcow2"}}); err != nil {
		t.Fatal(err)
	}
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Where an import "web" of a disk "data-20261006-120000" would write.
	dst := filepath.Join(poolDir, "web-data-20261006-120000.qcow2")
	plantOld(t, dst, "web's data replica")
	if refs, err := s.importPathReferences(context.Background(), dst, mustLstat(t, dst)); err != nil || refs == "" {
		t.Errorf("web's legacy replica of disk data: references %q (%v), want web's", refs, err)
	}
}

// A sibling that a record names is not a flow still writing beside the disk:
// a dead import's leftover is moved aside beside a fresh recorded replica.
func TestImportVM_ARecordedFreshSiblingIsNotAFlow(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	plantDeadLeftover(t, s, dst, "crashed", false)
	sib := filepath.Join(filepath.Dir(dst), "web-root-20261006-120000.qcow2")
	if err := os.WriteFile(sib, []byte("a replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPoolReplica(context.Background(), "default", replicaKey{VM: "web", Disk: "root", Project: "default"}, sib); err != nil {
		t.Fatal(err)
	}
	if err := importAs(s, t, "web"); err != nil {
		t.Fatalf("a re-import over a dead leftover beside a recorded replica: %v", err)
	}
	keptAside(t, dst, "crashed")
}

func mustLstat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}
