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
	err := publishVMRunningMinted(context.Background(), fake, dir, "node1", "vm1", "stopped",
		func(context.Context) (*corrosion.VMRecord, error) {
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", OwnerEpoch: 7}, nil
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
func TestPublishVMRunningMinted_ARunningCommitStillMarks(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	if err := publishVMRunningMinted(context.Background(), fake, dir, "node1", "vm1", "running",
		func(context.Context) (*corrosion.VMRecord, error) {
			return &corrosion.VMRecord{Name: "vm1", HostName: "node1", OwnerEpoch: 7}, nil
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
