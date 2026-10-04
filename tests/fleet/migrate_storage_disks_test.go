// Fleet scenario for WHICH disks a migrate --with-storage hands libvirt to
// copy.
//
// --with-storage turns on libvirt's non-shared-disk copy and names the disks
// to copy in migrate_disks. A disk on shared storage (nfs, ceph, iscsi) is the
// same file on both hosts, so copying it mirrors the disk onto itself: the
// target's block mirror writes into the very file the source guest is
// running on. Only a host-local disk is copied.

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// migrateNote is the note of the one libvirt migration n started.
func migrateNote(t *testing.T, n *Node) string {
	t.Helper()
	var notes []string
	for _, e := range n.Virt.EventLog() {
		if e.Op == "migrate" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) != 1 {
		t.Fatalf("libvirt migrations started = %d (%v), want 1", len(notes), notes)
	}
	return notes[0]
}

// A storage migration copies the host-local disk and leaves the shared one
// alone; with no host-local disk at all it copies nothing, so libvirt is not
// asked for a storage copy (an empty migrate_disks means every disk).
//
// Mutation: put every disk with a target device in migrate_disks again (the
// old loop) — the mixed case lists vdb and goes red. Keep the storage copy on
// when no disk is host-local — the shared-only case goes red.
func TestFleet_StorageMigrationCopiesOnlyHostLocalDisks(t *testing.T) {
	for _, tc := range []struct {
		name            string
		local           bool
		wantWithStorage bool
		wantDisks       string
	}{
		{"local and shared", true, true, "disks=vda"},
		{"shared only", false, false, "disks="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			defer c.Stop()
			src, dst := c.Nodes[0], c.Nodes[1]

			var disks []corrosion.DiskRecord
			if tc.local {
				// Under the target's disks dir, the root EnsureDisks may create a stub in.
				disks = append(disks, corrosion.DiskRecord{
					VMName: "pp1", DiskName: "root", HostName: src.Name,
					Path:      filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"),
					SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
				})
			}
			disks = append(disks, corrosion.DiskRecord{
				VMName: "pp1", DiskName: "data", HostName: src.Name,
				Path:      filepath.Join(c.tmpRoot, "nfs", "pp1-data.qcow2"),
				SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vdb",
			})
			spec, err := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
			if err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(context.Background(), src.DB, corrosion.VMRecord{
				Name: "pp1", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
			}, nil, disks); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			src.Virt.SetState("pp1", "running")

			if err := migrateWithStorageAt(t, c, src, "pp1", dst.Name); err != nil {
				t.Fatalf("migrate --with-storage: %v", err)
			}
			note := migrateNote(t, src)
			// The disk list is followed by the TLS fields; the trailing space pins
			// where it ends, so "disks=vda" cannot pass as "disks=vda,vdb".
			want := fmt.Sprintf("with_storage=%t %s ", tc.wantWithStorage, tc.wantDisks)
			if !strings.Contains(note, " "+want) {
				t.Fatalf("libvirt migration = %q, want it to contain %q", note, want)
			}
		})
	}
}
