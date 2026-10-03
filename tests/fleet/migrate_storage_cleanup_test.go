// Fleet scenario for the cleanup after a failed migrate --with-storage.
//
// Before the copy starts the source asks the target to make sure every disk
// path exists (EnsureDisks), which creates a stub where there is none and
// skips a path that already holds a file. When the copy fails the source asks
// the target to remove what it pre-created. That cleanup named every disk path,
// so it also removed a file EnsureDisks had skipped — one this attempt never
// made. In drill D1 (main-8d1e56dc) that file was the disk Layer-3 settle had
// kept on node-1 when pp1 was migrated back to it.
//
// Multi-node by construction: the skip happens on the target, the cleanup
// list is built on the source, and they meet over real gRPC.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// migrateWithStorageAt is migrateAt with --with-storage.
func migrateWithStorageAt(t *testing.T, c *Cluster, at *Node, vmName, targetHost string) error {
	t.Helper()
	st, err := c.SelfClient(at).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: vmName, TargetHost: targetHost, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// A failed storage migration removes the stub it created on the target, and
// never a disk file the target already had.
//
// Mutation: hand the cleanup every disk path again (not only the created
// ones) — the "existing disk" subtest goes red with the file deleted. Drop
// the cleanup altogether — the "stub" subtest goes red with the stub left.
func TestFleet_FailedStorageMigrationRemovesOnlyTheStubsItCreated(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing bool
	}{
		{"existing disk", true},
		{"stub", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			defer c.Stop()
			ctx := context.Background()
			src, dst := c.Nodes[0], c.Nodes[1]

			// Host-local disks keep the same path on every host; here that path is
			// under the target's disks dir, the root EnsureDisks may write in.
			path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
			var before os.FileInfo
			if tc.existing {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := qcow2.Create(path, 20<<30, nil); err != nil {
					t.Fatal(err)
				}
				fi, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				before = fi
			}

			spec, err := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
			if err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
				Name: "pp1", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
			}, nil, []corrosion.DiskRecord{{
				VMName: "pp1", DiskName: "root", HostName: src.Name, Path: path,
				SizeBytes: 20 << 30, StorageType: "local", TargetDev: "vda",
			}}); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			src.Virt.SetState("pp1", "running")
			src.Virt.FailMigrateToTarget = func(string, string) error {
				return errors.New("operation failed: migration of disk vda failed: Source and target image have different sizes")
			}

			if err := migrateWithStorageAt(t, c, src, "pp1", dst.Name); err == nil {
				t.Fatal("the migration succeeded; the scenario needs it to fail")
			}

			after, err := os.Stat(path)
			if tc.existing {
				if err != nil {
					t.Fatalf("the disk the target already had is gone after the failed migration: %v", err)
				}
				if !os.SameFile(before, after) {
					t.Fatal("the disk the target already had was replaced after the failed migration")
				}
				return
			}
			if err == nil {
				t.Fatal("the stub this migration created on the target was left behind")
			}
		})
	}
}
