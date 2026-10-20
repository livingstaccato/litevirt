package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// m-5: a LUNHolders answer counts only from the host that was asked. Another
// member answering at a stale or reused address is not that host.
//
// Mutation: drop the answered_by check — this goes red.
func TestCreateVM_ISCSI_AnAnswerFromAnotherHostDoesNotCount(t *testing.T) {
	s := lunTestServer(t)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer-host", Address: "10.0.0.10", State: "active"}); err != nil {
		t.Fatal(err)
	}
	decideForeign(t, s, mustLUNKey(t, "10.0.0.1", "0"), 0, "far", "peer-host")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &lunPeer{answeredBy: "someone-else"}, func() {}, nil
	}
	_, err := s.CreateVM(adminCtx(), lunVM("b", "lun0"))
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "someone-else") {
		t.Fatalf("an answer from another host: got %v, want Unavailable naming it", err)
	}
}

// m-1: a rebuild holds its LUNs from before its teardown until its create
// returns, so no other create can take them in between; its own create
// takes the hold over.
//
// Mutation: do not register the hold in the preflight — the LUN reads as
// gone during the teardown and this goes red.
func TestRebuildVM_ISCSI_HoldsTheLUNAcrossTheTeardown(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	spec := lunVM("a", "lun0").Spec
	hctx, release, err := s.preflightLUNs(ctx, spec, vmRecord(t, s, "a"), s.hostName)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer release(recreateFailed)
	// The teardown: the row is gone, the domain undefined.
	if err := corrosion.DeleteVM(ctx, s.db, "a"); err != nil {
		t.Fatal(err)
	}
	_ = s.virt.DestroyDomain("a")
	_ = s.virt.UndefineDomain("a", false)
	resp, err := s.LUNHolders(peerCtxFor(t, s, "peer-host"), &pb.LUNHoldersRequest{Luns: []string{mustLUNKey(t, "10.0.0.1", "0")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Holders) != 1 || !resp.Holders[0].InFlight || resp.Holders[0].VmName != "a" {
		t.Fatalf("during the rebuild's teardown the LUN is held by %v, want the rebuild of a in flight", resp.Holders)
	}
	if _, err := s.CreateVM(hctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("the rebuild's own create under its hold: %v", err)
	}
}

// N-3: a create that fails after its allocation was decided resolves it
// itself: the checkpoint moves past it, and no later walker has to.
//
// Mutation: leave a failed create's allocation for later walkers — this goes
// red.
func TestCreateVM_ISCSI_AFailedCreateResolvesItsAllocation(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	dev := d.lun("0", 64<<20)
	f, err := os.OpenFile(d.files[dev], os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0x55, 0xaa}, 510); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := s.CreateVM(adminCtx(), lunImageVM("a", "lun0", false)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("image onto a non-blank LUN: %v", err)
	}
	if g, err := corrosion.GetLUNResolved(context.Background(), s.db, mustLUNKey(t, "10.0.0.1", "0")); err != nil || g < 1 {
		t.Fatalf("checkpoint after the failed create = %d (%v), want past its allocation 0", g, err)
	}
}
