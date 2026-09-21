package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The read-back after a minting commit is the one read that decides whether a
// freshly minted generation is ever marked, and its failure is deliberately
// silent. Running it on the CALLER's context means a client ^C or an expired
// RPC deadline — after the commit has already landed — reliably drops the
// markers for a generation that exists, with nothing reaching anyone.
//
// That is precisely the reasoning assignOwnerEpochAtCreate gives for detaching
// its own context: "the row is already committed and the guest is already
// running by the time this runs, so a client ^C … must not decide whether the
// VM is provable". The sibling path did not do it.
func TestPublishVMRunningMinted_ACancelledCallerStillMarks(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	// Cancelled before the call: the commit below ignores ctx, standing in for a
	// commit that already landed before the caller went away.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := publishVMRunningMinted(ctx, fake, dir, "node1", "vm1",
		func(rctx context.Context) (*corrosion.VMRecord, error) {
			// A real read honours its context — corrosion.GetVM does. If the
			// chokepoint hands it the caller's cancelled one, it fails here.
			if err := rctx.Err(); err != nil {
				return nil, err
			}
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", OwnerEpoch: 7}, nil
		},
		func(context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("publishVMRunningMinted: %v", err)
	}

	epoch, ok, _ := fake.GetDomainOwnerEpoch("vm1")
	if !ok {
		t.Fatal("no domain marker was stamped after a minting commit whose caller had gone " +
			"away — the commit HAS landed, so this VM is running at a generation nothing " +
			"names, and the failure is silent by design")
	}
	if epoch != 7 {
		t.Errorf("domain marker = %d, want 7", epoch)
	}
	if e, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); !ok || e != 7 {
		t.Errorf("file marker = %d (present=%v), want 7", e, ok)
	}
}
