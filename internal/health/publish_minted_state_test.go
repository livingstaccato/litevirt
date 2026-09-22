package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// PublishVMRunning gates on state != "running" before touching markers, and
// writeBothMarkers' own doc leans on that: "Only ever called for a RUNNING
// publish, which is why the domain write takes running=true".
//
// The minted twin had no such gate. CutoverVM deliberately accepts a -next VM in
// state "stopped" and routes its ReplaceVM through the minted path, so a stopped
// cutover reached writeBothMarkers and fired SetDomainOwnerEpoch(name, epoch,
// true) — a LIVE metadata write against an inactive domain, which libvirt
// rejects — then still wrote a RUNTIME file marker asserting a generation owns a
// runtime that does not exist.
func TestPublishVMRunningMinted_AStoppedCommitWritesNoRuntimeMarkers(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateShutdown)

	committed := false
	err := publishVMRunningMinted(context.Background(), fake, dir, "node1", "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "stopped", OwnerEpoch: 7}, nil
		},
		func(context.Context) error { committed = true; return nil })
	if err != nil {
		t.Fatalf("a stopped minting commit must still succeed: %v", err)
	}
	if !committed {
		t.Fatal("the commit did not run")
	}

	if epoch, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
		t.Errorf("a LIVE domain marker (%d) was stamped for a STOPPED transition; libvirt "+
			"rejects that write on an inactive domain, and it asserts a generation owns a "+
			"runtime that is not there", epoch)
	}
	if epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Errorf("a RUNTIME file marker (%d) was written for a STOPPED transition", epoch)
	}
}

// The running case is unchanged: markers are still written.
//
// This and the stopped case above are the WHOLE test of the gate. There was a
// third, TestPublishVMRunningMinted_TheGateFollowsTheCommittedState, written
// when the helper still took a `state` argument: it passed a stale "stopped"
// with a committed row of "running" and asserted the markers followed the row.
// Removing the parameter made it unable to fail — with no caller value left to
// disagree, it was this test with a longer name, and deleting the gate entirely
// left it green. It is gone rather than kept for coverage.
func TestPublishVMRunningMinted_ARunningCommitStillMarks(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	if err := publishVMRunningMinted(context.Background(), fake, dir, "node1", "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "running", OwnerEpoch: 7}, nil
		},
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if epoch, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || epoch != 7 {
		t.Errorf("domain marker = %d (present=%v), want 7", epoch, ok)
	}
	if epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); !ok || epoch != 7 {
		t.Errorf("file marker = %d (present=%v), want 7", epoch, ok)
	}
}

// A non-running minting transition must LEAVE the marker alone.
//
// The first attempt at this had the publish path DELETE a stale marker here.
// That was the wrong place: row.State comes from a retried read taken up to
// markAfterCommitTimeout after the commit, so a concurrent writer can move the
// row inside that window — the same untrustworthiness the caller's value had,
// pointing the other way. Skipping a write on a wrong answer is a no-op
// convergence repairs; deleting on one strips a live VM of its proof. A stale
// marker from a replacement is cleared by finishVMReplaceRuntime, off the
// journaled accepted state, which cannot race.
func TestPublishVMRunningMinted_ANonRunningCommitLeavesAnExistingMarkerAlone(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateShutdown)

	if err := WriteVMOwnerEpochMarker(dir, "vm1", 4); err != nil {
		t.Fatalf("seed the marker: %v", err)
	}

	if err := publishVMRunningMinted(context.Background(), fake, dir, "node1", "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "stopped", OwnerEpoch: 9}, nil
		},
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("publish: %v", err)
	}

	epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1")
	if !ok || epoch != 4 {
		t.Errorf("marker = %d (present=%v), want 4 — a read-back that says stopped is not "+
			"proof the VM is stopped, and this path must not destroy a marker on it", epoch, ok)
	}
}
