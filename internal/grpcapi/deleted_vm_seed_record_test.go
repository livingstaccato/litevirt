package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lab2-D2-recheck2 anomaly 3: the record a live move's commit keeps of the
// removed seed's instance-id (<vm>.iso.removed) outlived `lv rm` on every
// host the VM had moved away from. The deleted-VM pass drops it, for a
// deleted VM and only when it was kept for that VM's uuid: the deleting
// owner's request (removeDeletedVMLeftoversHere) and the host's own sweep
// when it becomes active.
//
// Mutations: drop the call from the sweep — "gone" keeps its record (sweep);
// drop the call from the request — "gone" keeps it (request); drop the uuid
// match — "other" loses its record. "live" is kept by the tombstone check
// alone as well as the live-row check (a name has one row).
func TestDeletedVM_RemovesItsRemovedSeedRecord(t *testing.T) {
	for _, how := range []string{"sweep", "request"} {
		t.Run(how, func(t *testing.T) {
			s := testServerWithLocks(t)
			s.virt = libvirtfake.New()
			s.dataDir = t.TempDir()
			ctx := adminCtx()
			if err := os.MkdirAll(filepath.Join(s.dataDir, "cloudinit"), 0o700); err != nil {
				t.Fatal(err)
			}
			vms := map[string]string{"gone": "uuid-gone", "other": "uuid-other", "live": "uuid-live"}
			owners := map[string]string{"gone": "uuid-gone", "other": "uuid-someone-else", "live": "uuid-live"}
			for name, uuid := range vms {
				if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: "owner-host", State: "stopped",
					Spec: `{"name":"` + name + `","uuid":"` + uuid + `"}`}, nil, nil); err != nil {
					t.Fatal(err)
				}
				if err := cloudinit.RecordRemovedSeed(lv.CloudInitISOPath(s.dataDir, name), owners[name], name); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"gone", "other"} {
				if err := corrosion.DeleteVM(ctx, s.db, name); err != nil {
					t.Fatal(err)
				}
			}
			if how == "sweep" {
				// The host becomes active with a replica it can trust.
				if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
					t.Fatal(err)
				}
				s.db.MarkReplicaCaughtUpForTests("peer")
				s.DeletedVMMarkerSweepTick(ctx)
			} else {
				for _, name := range []string{"gone", "other", "live"} {
					_, _ = s.removeDeletedVMLeftoversHere(ctx, &pb.CleanupMigrationArtifactsRequest{VmName: name}, nil)
				}
			}
			for name, want := range map[string]bool{"gone": false, "other": true, "live": true} {
				_, err := os.Stat(lv.CloudInitISOPath(s.dataDir, name) + ".removed")
				if got := err == nil; got != want {
					t.Errorf("%s: record present = %v, want %v", name, got, want)
				}
			}
		})
	}
}
