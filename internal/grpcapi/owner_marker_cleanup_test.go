package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Nothing in production ever removed <dataDir>/vms/<name>/owner_epoch: there is
// no RemoveVMOwnerEpochMarker at all, and the container equivalent has zero
// callers. So a marker outlives the VM it names.
//
// On name reuse that is not merely untidy. assignOwnerEpochAtCreate deliberately
// declines to write a marker when its graduation fails, because marker>0 against
// a row at 0 is a mismatch convergeOwnerEpochMarker returns early on and never
// repairs, which assertRuntimeOwnership reads as marker_epoch_mismatch and which
// refuses that VM's legitimate sole-holder re-key for good. A stale marker from
// a PREVIOUS VM of the same name produces exactly that state through a door the
// function cannot close.
func TestDeleteVM_RemovesTheOwnerEpochMarker(t *testing.T) {
	for _, tc := range []struct {
		name       string
		keepDisks  bool
		withDomain bool // a live domain takes the MAIN delete path; without one
		// DeleteVM takes the stale-record path and returns early, so both have to
		// drop the marker and each needs its own case.
	}{
		{"stale record, ordinary", false, false},
		{"stale record, keep-disks", true, false},
		{"live domain, ordinary", false, true},
		{"live domain, keep-disks", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			if tc.withDomain {
				fake.SetState("vm1", libvirtfake.StateRunning)
			}
			ctx := adminCtx()
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
				Name: "vm1", HostName: "test-host", State: "stopped",
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			// The VM had reached generation 5 through earlier ownership moves.
			if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 5); err != nil {
				t.Fatalf("WriteVMOwnerEpochMarker: %v", err)
			}

			if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{
				Name: "vm1", KeepDisks: tc.keepDisks,
			}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}

			if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); ok {
				t.Fatalf("the owner-epoch marker (%d) outlived the VM it names; reusing the "+
					"name lands a fresh row at epoch 0 beside a marker above it — the "+
					"mismatch convergence never repairs", epoch)
			}
		})
	}
}
