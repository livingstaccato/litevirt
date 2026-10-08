package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// C-A, restore (final-rereview-integrate-3.md; integrate-4 concern 4): a VM
// main (3e4ba50b) promoted with --no-localize from a replica in the default
// pool on <data_dir>/disks is restored in place from a backup of its disk.
//
// On main this worked: a stopped VM's backup is its disk file
// (backup_snapshot.go pushBackup → PushFile at 3e4ba50b), the overlay whose
// header names the replica, and RestoreFromBackup wrote it back over the
// file target_path named — a bare name under <data_dir>/disks
// (backup_snapshot.go:606-660 at 3e4ba50b) — so the restored overlay named
// its replica again and the VM started on it. This build restores over a
// VM's own disk only with in_place (a bare target_path no longer replaces a
// file), which rebuilds a disk-file backup onto the disk's own backing, and
// accepts as that backing the main-era replica on the same bounds its start
// does (diskChain.legacyPromoted).

// mainPromotedRestoreVM is project a's stopped VM "pv" as main's promote
// --no-localize of VM "web" disk "root" left it in the default pool (local,
// no target: <data_dir>/disks): the replica <web>-root-<ts>.<format> (no
// record) and the overlay pv-promoted-web-root-<ts>.qcow2 on it, holding
// content, declared as format, recorded with StorageVolume "default" and no
// backing_disk (promote.go:887-910, :976-979 at 3e4ba50b).
func mainPromotedRestoreVM(t *testing.T, f *restoreFixture, format string) (disk, replica string, content []byte) {
	t.Helper()
	registerPool(t, f.s, "default", "local", "", "", "")
	disks := filepath.Join(f.s.dataDir, "disks")
	name := strings.TrimSuffix(mainQcow2ReplicaName("web", "root", promotedAt), ".qcow2") + "." + format
	replica = filepath.Join(disks, name)
	if format == "qcow2" {
		runQemuImg(t, "create", "-q", "-f", "qcow2", replica, "1M")
	} else if err := os.WriteFile(replica, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	disk = filepath.Join(disks, mainPromotedName("pv", name))
	content = bytes.Repeat([]byte("main promoted "), 1<<20/14)
	content = append(content, make([]byte, 1<<20-len(content))...)
	overlayWithData(t, disk, replica, format, content)
	backedVM(t, f, "pv", disk, corrosion.DiskRecord{StorageType: "local", StorageVolume: "default"})
	return disk, replica, content
}

// Both formats of replica, from a backup this build took (its base identity
// recorded) and from one main took (no content format, no base identity: a
// disk-file backup by its manifest, on a replica that never changes).
//
// Red against e287bc8b for the qcow2 replica: "the disk's backing … has no
// record of its format"; the raw replica passed already.
func TestRestoreInPlace_AMainPromotedVMInTheDefaultPool(t *testing.T) {
	needQemuImg(t)
	for _, format := range []string{"qcow2", "raw"} {
		for _, backup := range []string{"this-build", "main"} {
			t.Run(format+"/"+backup, func(t *testing.T) {
				f := newRestoreFixture(t)
				f.s.virt = libvirtfake.New()
				disk, replica, content := mainPromotedRestoreVM(t, f, format)
				const ts = "2026-10-08T10:00:00Z"
				if backup == "main" {
					pushVMWithIdentity(t, f, "pv", disk, ts, "", "", nil)
				} else {
					pushVM(t, f, "pv", disk, ts, pbsstore.ContentDiskFile, "")
				}
				// The disk has changed since: an empty overlay on the replica again.
				if err := os.Remove(disk); err != nil {
					t.Fatal(err)
				}
				runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", replica, "-F", format, disk)
				if err := inPlace(f, "pv", ts); err != nil {
					t.Fatalf("in-place restore of a main-era --no-localize VM on a %s replica in the default pool: %v", format, err)
				}
				requireRestoredOnto(t, disk, replica, content)
				f.assertVictimIntact(t)
			})
		}
	}
}

// The restore accepts the replica on the start's bounds, no wider: a replica
// another project uploaded, or one another project's VM row claims, is
// refused as a backing, and the disk is left as it was.
func TestRestoreInPlace_AMainPromotedReplicaKeepsTheStartsBounds(t *testing.T) {
	needQemuImg(t)
	for _, c := range []string{"another-projects-upload", "claimed-by-another-projects-row"} {
		t.Run(c, func(t *testing.T) {
			f := newRestoreFixture(t)
			f.s.virt = libvirtfake.New()
			disk, replica, _ := mainPromotedRestoreVM(t, f, "qcow2")
			const ts = "2026-10-08T11:00:00Z"
			pushVM(t, f, "pv", disk, ts, pbsstore.ContentDiskFile, "")
			switch c {
			case "another-projects-upload":
				if err := f.s.recordPoolUpload(t.Context(), "default", "b", "bob", replica); err != nil {
					t.Fatal(err)
				}
			case "claimed-by-another-projects-row":
				if err := corrosion.InsertVM(t.Context(), f.s.db,
					corrosion.VMRecord{Name: "other", HostName: f.s.hostName, State: "stopped", Project: "b"}, nil,
					[]corrosion.DiskRecord{{VMName: "other", DiskName: "root", HostName: f.s.hostName, Path: replica,
						StorageType: "local", StorageVolume: "default"}}); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(disk)
			if err := inPlace(f, "pv", ts); err == nil {
				t.Fatalf("%s: the in-place restore was accepted", c)
			}
			if after, _ := os.ReadFile(disk); !bytes.Equal(after, before) {
				t.Fatalf("%s: the refused restore changed the disk", c)
			}
		})
	}
}

// Only the promotion's layout stands in for a record. An unrecorded qcow2
// base of another name in a pool the project may use is not a replica that
// cannot change: a backup that did not record its base identity is not
// restored onto it, as before.
//
// Mutation: accept any unrecorded base in the legacy branch — red.
func TestRestoreInPlace_AnUnrecordedPoolBaseIsNotTakenForAReplica(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	pool := t.TempDir()
	registerPool(t, f.s, "dr", "dir", "", pool, "")
	base := filepath.Join(pool, "golden.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", base, "1M")
	disk := filepath.Join(pool, "pv-root.qcow2")
	overlayWithData(t, disk, base, "qcow2", make([]byte, 1<<20))
	backedVM(t, f, "pv", disk, corrosion.DiskRecord{StorageType: "dir", StorageVolume: "dr"})
	const ts = "2026-10-08T12:00:00Z"
	pushVMWithIdentity(t, f, "pv", disk, ts, "", "", nil)
	if err := inPlace(f, "pv", ts); err == nil {
		t.Fatal("an in-place restore onto an unrecorded pool base, from a backup without its base identity, was accepted")
	}
}
