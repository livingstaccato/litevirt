package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/network"
)

// NB-4: a live firmware move lands the guest paused and resumes it only in
// Release (resumeReleased). Its NICs' VLANs live on the taps the target made,
// so they go on there before that resume (readyGuestHere): the access NIC
// never runs on the target's VLAN 1.
//
// Mutation: resumeReleased calling ArmNICsFor instead of readyGuestHere — red.
func TestFleet_FwLive_PutsTheAccessVLANOnBeforeTheRelease(t *testing.T) {
	sc := fwliveSetup(t, false)
	ctx := context.Background()
	spec, err := json.Marshal(&pb.VMSpec{Name: fwwVM, Cpu: 1, MemoryMib: 256, SecureBoot: true, Tpm: true, Firmware: "uefi", Uuid: fwwUUID,
		Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:fe:00:30", Trunk: []int32{30}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.src.DB.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?`, string(spec), sc.src.DB.NowTS(), fwwVM); err != nil {
		t.Fatal(err)
	}
	(&accVLANBridge{on: true}).wire(sc.dst)
	sc.c.WaitConverged(t, convergeTimeout)
	if err := sc.migrate(t); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	assertVLANBeforeRun(t, sc.dst, fwwVM, "bridge="+network.FlatBridgeName("accnet")+" mac=52:54:00:fe:00:30 vlan=30")
}
