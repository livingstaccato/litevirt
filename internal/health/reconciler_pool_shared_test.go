package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// colonelpanik/litevirt#258 fix round 4: the reconciler's shared-disk
// transfer gate uses the one definition of "shared" (corrosion.
// DiskOnSharedStorage), so a disk whose storage type says local but whose
// pool's driver is nfs — on this host, or on the old owner the proof's fence
// names — is gated like one typed nfs: a transfer without a proof-grade fence of the old owner
// is refused (storage_unverified), never started on a path the old owner may
// still be writing.
//
// Mutation "storage type only" (the gate uses VMHasWritableSharedDisk) — red.
func TestStartPendingVM_PoolSharedDiskRejectWithoutProofGradeFence(t *testing.T) {
	for _, c := range []struct {
		name, poolHost string
		sshFence       bool // the proof binds the old owner's SSH fence
	}{
		{"pool on this host, no fence bound", "node-a", false},
		{"pool on the old owner, its fence ssh", "node-old", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			diskPath := filepath.Join(t.TempDir(), "vm1.img")
			if err := os.WriteFile(diskPath, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, db,
				corrosion.VMRecord{Name: "vm1", HostName: "node-old", Spec: "{}", State: "running"}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-old",
					Path: diskPath, StorageType: "local", SizeBytes: 1 << 30, StorageVolume: "nas"}},
			); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
				HostName: c.poolHost, Name: "nas", Driver: "nfs", Source: "nas:/vm", State: "active"}); err != nil {
				t.Fatal(err)
			}
			epoch := ""
			if c.sshFence {
				if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
					ID: "fssh", HostName: "node-old", Method: "ssh", Result: "fenced"}); err != nil {
					t.Fatal(err)
				}
				epoch = corrosion.FenceEpochRef{Host: "node-old", FenceID: "fssh", TS: time.Now().UTC().Format(time.RFC3339)}.String()
			}
			stageReschedule(t, ctx, db, "vm1", epoch)

			r, fake, refused := sharedDiskReconciler(t, db)
			fresh, _ := corrosion.GetVM(ctx, db, "vm1")
			r.startPendingVM(ctx, *fresh)

			if startedOrDefined(fake, "vm1") {
				t.Fatal("a pool-shared disk's transfer without a proof-grade fence must NOT start")
			}
			if !hasReason(*refused, ReasonStorageUnverified) {
				t.Errorf("want a storage_unverified refusal, got %v", *refused)
			}
		})
	}
}

// A genuinely host-local disk (its pool's driver is dir) is not gated: its
// transfer still needs no proof-grade fence, as on main.
func TestStartPendingVM_HostLocalPoolDiskNotGated(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	diskPath := filepath.Join(t.TempDir(), "vm1.img")
	if err := os.WriteFile(diskPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a",
			Path: diskPath, StorageType: "local", SizeBytes: 1 << 30, StorageVolume: "default"}},
	); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "node-a", Name: "default", Driver: "dir", Source: "/var/lib/litevirt", State: "active"}); err != nil {
		t.Fatal(err)
	}
	stageReschedule(t, ctx, db, "vm1", "")

	r, _, refused := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)
	if hasReason(*refused, ReasonStorageUnverified) {
		t.Errorf("a host-local disk's transfer was refused as shared: %v", *refused)
	}
}
