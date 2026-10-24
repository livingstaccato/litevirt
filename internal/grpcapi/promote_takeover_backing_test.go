package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A promotion that takes the VM over under its own name re-homes the existing
// disk row, so it has to record the backing it built as a renamed promotion's
// fresh row does: the replica under a --no-localize overlay, and no backing
// at all for a localized copy. The source row here is a linked clone's, whose
// backing_disk names its template disk on the host the VM left.
//
// With the source row's backing kept, the promoted VM does not restart (its
// overlay names a raw replica that is not the backing_disk recorded for it),
// and nothing on record holds the replica it reads, so it is deleted as pool
// content.
//
// The root and a data disk: the takeover re-homes each row separately.
//
// Mutation "takeover writes no backing" (either SetDiskBacking of the
// takeover branch removed, leaving that row's backing_disk/backing_image as
// the source row had them) — red: the row, the restart and the delete.
func TestPromote_ATakeoverRecordsTheBackingItBuilt(t *testing.T) {
	for _, noLocalize := range []bool{true, false} {
		name := "localized"
		if noLocalize {
			name = "no-localize"
		}
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			poolDir := setPromoteVMRows(t, s, "db", []corrosion.DiskRecord{
				{DiskName: "data1", HostName: "dead-host", Path: "/dead/db-data1.qcow2", SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vdb", Bus: "virtio"},
			})
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "dr", Driver: "local", Target: poolDir})
			if err := s.db.Execute(context.Background(),
				`UPDATE vm_disks SET backing_disk = '/dead/tmpl-' || disk_name || '.qcow2', backing_image = 'base.qcow2' WHERE vm_name = 'db'`); err != nil {
				t.Fatal(err)
			}
			taken := stamp(10 * time.Minute)
			replicas := map[string]string{}
			for _, disk := range []string{"root", "data1"} {
				replicas[disk] = filepath.Join(replicaOwnerDir(poolDir, "", "db"),
					seedReplica(t, poolDir, "", "db", disk, taken, "raw", 1<<20))
			}
			stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}
			if err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: noLocalize}, stream); err != nil {
				t.Fatalf("PromoteReplica: %v", err)
			}

			rows := diskRowsOf(t, s, "db")
			for _, disk := range []string{"root", "data1"} {
				row := rows[disk]
				want := ""
				if info, err := qcow2.Info(row.Path); err == nil {
					want = info.BackingFile
				}
				if noLocalize && want != replicas[disk] {
					t.Fatalf("%s: the --no-localize overlay's backing = %q, want the replica %q", disk, want, replicas[disk])
				}
				if row.BackingDisk != want || row.BackingImage != "" {
					t.Errorf("%s row backing_disk = %q, backing_image = %q; want %q and none (the live disk's own backing)",
						disk, row.BackingDisk, row.BackingImage, want)
				}
			}

			if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "db"}); err != nil {
				t.Errorf("RestartVM of the promoted VM: %v", err)
			}

			if !noLocalize {
				return
			}
			for _, disk := range []string{"root", "data1"} {
				_, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{
					PoolName: "dr", Filename: filepath.Base(replicas[disk]), ReplicaVm: "db"})
				if status.Code(err) != codes.FailedPrecondition {
					t.Errorf("delete of the replica %s reads = %v, want FailedPrecondition", disk, err)
				}
				if _, err := os.Stat(replicas[disk]); err != nil {
					t.Errorf("the replica %s reads is gone: %v", disk, err)
				}
			}
		})
	}
}

// Review NB-3: a takeover whose first attempt started the domain and died
// before it persisted the rows is adopted by the retry, which records the
// backing of the live disk the domain runs from — the replica under its
// --no-localize overlay — over the source row's.
//
// Mutation "takeover writes no backing" (the root's SetDiskBacking removed)
// — red.
func TestPromote_AnAdoptedTakeoverRecordsTheBackingItBuilt(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	if err := s.db.Execute(context.Background(),
		`UPDATE vm_disks SET backing_disk = '/dead/tmpl-root.qcow2', backing_image = 'base.qcow2' WHERE vm_name = 'db'`); err != nil {
		t.Fatal(err)
	}
	replica := filepath.Join(replicaOwnerDir(poolDir, "", "db"),
		seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20))
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(name string) error {
		f.SetState(name, libvirtfake.StateRunning) // qemu is up; the daemon dies
		panic("crash")
	}
	crashPromote(t, s, req)
	f.FailStartDomain = nil
	built := promotedFiles(t, poolDir, "db")
	if len(built) != 1 {
		t.Fatalf("the crashed attempt left %v, want exactly its one live disk", built)
	}

	promoteSet(t, s, req)

	root := diskRowsOf(t, s, "db")["root"]
	if root.Path != built[0] {
		t.Fatalf("root row path = %q, want the adopted domain's disk %q", root.Path, built[0])
	}
	if root.BackingDisk != replica || root.BackingImage != "" {
		t.Errorf("root row backing_disk = %q, backing_image = %q; want the replica %q and none", root.BackingDisk, root.BackingImage, replica)
	}
}
