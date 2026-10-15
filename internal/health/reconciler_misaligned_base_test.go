package health

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A rescheduled VM whose backing image qemu would refuse as corrupt (an lv
// image build of a disk over 512 MiB from before that was fixed) is not
// retried every pass: the refusal is permanent, so the proof fails and the
// VM leaves pending with the reason. That holds whether the image is
// refused building the overlay here, or on arrival when a peer pushes it
// (where only the refusal's text crosses gRPC).
//
// Mutation: classify either refusal transient again — its subtest finds
// the VM re-armed pending.
func TestStartPendingVM_MisalignedBaseIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		pull func(store *image.Store, name string) error
	}{
		{"overlay build refuses the base", func(store *image.Store, name string) error {
			p := store.ImagePath(name)
			if err := qcow2.Create(p, 1<<30, nil); err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			l1 := binary.BigEndian.Uint64(b[40:48])
			binary.BigEndian.PutUint64(b[l1:l1+8], 0x10200|1<<63) // off a 64 KiB boundary
			return os.WriteFile(p, b, 0o644)
		}},
		{"arrival refuses the pushed image", func(*image.Store, string) error {
			return errors.New(`rpc error: code = InvalidArgument desc = ImportImage on host-a failed: image "base": ` +
				qcow2.ErrMisaligned.Error() + `: L1[0] names an L2 table at 0x10200`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			dataDir := t.TempDir()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm-mis", HostName: "host-b", State: "running",
				Spec: `{"name":"vm-mis","cpu":1,"memory_mib":512}`,
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			store := image.NewStore(dataDir)
			if err := store.Init(); err != nil {
				t.Fatalf("store.Init: %v", err)
			}
			if err := corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
				VMName: "vm-mis", DiskName: "root", HostName: "host-a",
				Path: store.DiskPath("vm-mis", "root"), BackingImage: "base",
			}); err != nil {
				t.Fatalf("InsertDisk: %v", err)
			}
			proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
				TargetName: "vm-mis", DestHost: "host-a", Coordinator: "host-c"}
			if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm-mis", "host-a"); err != nil {
				t.Fatalf("WriteVMRescheduleProof: %v", err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("host-a", dataDir, db, fake)
			r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
			r.SetAutoPullImage(func(_ context.Context, name string) error { return tc.pull(store, name) })

			r.ReconcileOnce(ctx)

			if startedOrDefined(fake, "vm-mis") {
				t.Fatal("the VM started on a base qemu refuses")
			}
			vm, err := corrosion.GetVM(ctx, db, "vm-mis")
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %v", err)
			}
			if vm.State != "error" {
				t.Fatalf("VM = %q / %q, want error: a refusal no retry mends must not re-arm pending", vm.State, vm.StateDetail)
			}
			pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
			if pr.Status != corrosion.ProofFailed || !strings.Contains(pr.ResultDetail, "not cluster-aligned") {
				t.Fatalf("proof = %q / %q, want failed with the misalignment named", pr.Status, pr.ResultDetail)
			}
		})
	}
}
