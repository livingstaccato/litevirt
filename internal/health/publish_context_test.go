package health

import (
	"context"
	"testing"
	"time"

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
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "running", OwnerEpoch: 7}, nil
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

// Detaching was right; a 30-second detached budget was not.
//
// Everything after the commit is one row read plus two small marker writes. The
// caller waits for all of it synchronously, so a wedged store now pins the
// caller's goroutine for the whole budget AFTER its own context is already
// cancelled — and for CutoverVM that goroutine is holding two per-VM locks. The
// previous behaviour failed fast on the caller's cancellation; the fix must not
// trade that for a multi-second stall.
func TestPublishVMRunningMinted_DoesNotStallTheCallerOnAWedgedRead(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is already gone

	// Run it OFF the test goroutine and race it against a hard ceiling. Calling
	// it inline and measuring afterwards could only ever report a bound that was
	// enforced: the mutation that actually breaks the bound — dropping the
	// timeout from the detached context — makes the read block forever, so the
	// test HUNG until the go test deadline killed the whole package instead of
	// failing here with a reason. A test whose failure mode is a package-wide
	// timeout names no defect.
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		e := publishVMRunningMinted(ctx, fake, dir, "node1", "vm1",
			func(rctx context.Context) (*corrosion.VMRecord, error) {
				<-rctx.Done() // a store that never answers
				return nil, rctx.Err()
			},
			func(context.Context) error { return nil })
		done <- result{e, time.Since(start)}
	}()

	var got result
	select {
	case got = <-done:
	case <-time.After(markAfterCommitTimeout + 5*time.Second):
		t.Fatalf("the publish had not returned %v after the commit; the post-commit budget is "+
			"not bounding the wait at all, and the caller is holding two per-VM locks for it",
			markAfterCommitTimeout+5*time.Second)
	}
	err, elapsed := got.err, got.elapsed

	if err != nil {
		t.Fatalf("a failed read-back is reported, not returned: %v", err)
	}
	// Measured against the constant, not a hand-picked number. An 8-second
	// threshold here was looser than the 5-second budget it was guarding, so it
	// would have passed unchanged if the budget went back up to 7 — it admitted
	// exactly the multi-second stall this test's own comment says the fix must
	// not trade for.
	//
	// What is bounded is the ctx-aware work: the read-back. The two marker
	// writes take no context (SetDomainOwnerEpoch and the file write are
	// blocking calls), so a wedged libvirt is NOT bounded by this budget and the
	// caller still waits on it holding its locks.
	//
	// That residual is real and unclosed. An earlier note here said closing it
	// required moving the marking off the caller's goroutine entirely; that was
	// a false dichotomy. The DOMAIN half could be bounded on its own while the
	// durable file marker stays synchronous — writeBothMarkers already treats
	// "file landed, domain failed" as a successful publish (res.landed is an
	// OR), so a timed-out domain write needs no new contract.
	//
	// It is still not done here, for a narrower reason: an abandoned libvirt
	// write can land after a later publish has set a higher generation, walking
	// the domain marker backwards. That direction is the conservative one for
	// every reader today, but this is a dual-run guard, and the last change made
	// to one on a review suggestion turned a refusal into a permission. It wants
	// its own decision, not a timeout fix carrying it in.
	// TWO assertions, because either alone is defeatable. Measuring only against
	// the constant makes the threshold move with the budget, so raising the
	// budget back to 30s passes; asserting only a fixed number leaves it unclear
	// whether the budget is enforced at all or the read merely returned early.
	if elapsed > markAfterCommitTimeout+time.Second {
		t.Fatalf("the caller was held for %v against a %v budget — the budget is not bounding "+
			"the post-commit wait at all", elapsed, markAfterCommitTimeout)
	}
	// The budget itself has to stay small: it IS the caller's wait, taken while
	// CutoverVM holds two per-VM locks. An 8-second threshold here was looser
	// than the 5-second budget it guarded, so it admitted exactly the
	// multi-second stall this test's comment says the fix must not trade for.
	if markAfterCommitTimeout > 5*time.Second {
		t.Errorf("markAfterCommitTimeout is %v; everything after the commit is one row read "+
			"and two small marker writes, and the caller waits for all of it while holding "+
			"locks", markAfterCommitTimeout)
	}
}
