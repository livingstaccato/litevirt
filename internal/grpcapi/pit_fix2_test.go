package grpcapi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

func caughtUp() (bool, string) { return true, "" }

// N1(a): a disk deleted on purpose takes its overlay and binding with it, so
// a disk later re-created at the same path never meets it.
//
// Mutation "overlay outlives its disk": deleteDiskAtRecordedLocation does not
// remove the overlay — red.
func TestDeleteDisk_TakesItsOverlayWithIt(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	windowOverlay(t, live)
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	disks[0].StorageType = "local" // a disk outside any pool: the local driver deletes it
	if err := s.deleteDiskAtRecordedLocation(context.Background(), &disks[0]); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, p := range []string{pitoverlay.Path(live), pitoverlay.SidecarPath(live)} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s outlived its deleted disk (%v)", p, err)
		}
	}
}

// N1(c): an overlay whose base was written since it was taken (a build that
// knows nothing of overlays restarted the VM on the base) is never committed
// over the newer data, nor dropped: the VM is held, named in an event.
//
// Mutation "binding ignored": healPITOverlay's offline branch commits without
// CommitOffline's verdict check (matches or half-written) — red.
func TestHeal_ABaseWrittenSinceIsNeverOverwritten(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	time.Sleep(10 * time.Millisecond)
	// A write to the base: it is no longer the frozen one.
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x33 0 512", live).CombinedOutput(); err != nil {
		t.Fatalf("write the base: %v %s", err, out)
	}

	if err := runRepl(t, s, time.Now()); err == nil {
		t.Fatal("a copy went on with an overlay it could not verify")
	}
	if holdsTheWindowsWrite(t, live) {
		t.Fatal("the stale overlay was committed over a base written since")
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the held overlay was moved or removed")
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), vmEventPITOverlayHeld) {
		t.Errorf("no hold event: %v", pitEventTypes(t, s, "web"))
	}
}

// N1(b): an in-place restore settles the overlay before it writes over the
// disk, so the old overlay can never be committed over restored contents.
//
// Mutation "restore ignores the overlay": inPlaceRestoreLocked does not call
// healPITOverlay — red.
func TestInPlaceRestore_SettlesTheOverlayFirst(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	if _, err := s.inPlaceRestoreLocked(context.Background(), "web", "root"); err != nil {
		t.Fatalf("inPlaceRestoreLocked: %v", err)
	}
	if pitoverlay.Present(live) {
		t.Fatal("the overlay is still beside the disk the restore will write")
	}
}

// N1(b): an import writing a new disk sets aside an overlay left at its path.
func TestImport_SetsAsideAStaleOverlay(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	windowOverlay(t, live)
	if err := s.setAsideStaleOverlay(context.Background(), "web", "root", live, ""); err != nil {
		t.Fatal(err)
	}
	if pitoverlay.Present(live) {
		t.Fatal("the stale overlay is still there")
	}
	if aside, _ := filepath.Glob(pitoverlay.Path(live) + ".orphan-*"); len(aside) == 0 {
		t.Fatal("it was not kept")
	}
}

// N3: the start-up sweep waits for the replica to catch up.
//
// Mutation "no wait": the caughtUp loop is removed — red.
func TestSweep_WaitsForTheReplicaToCatchUp(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	prev := pitSweepPoll
	pitSweepPoll = time.Millisecond
	defer func() { pitSweepPoll = prev }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.SweepPITOverlays(ctx, func() (bool, string) { return false, "behind" })
	if !pitoverlay.Present(live) {
		t.Fatal("the sweep touched a disk before the replica caught up")
	}
}

// N3: a VM whose row has moved to another host is left to its owner.
//
// Mutation "no ownership re-check": sweepPITOverlaysOf skips the re-read —
// red.
func TestSweep_LeavesAVMReHomedElsewhere(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	vms, _ := corrosion.ListVMs(context.Background(), s.db, "", s.hostName)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET host_name = 'other-host' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	for i := range vms { // as listed before the replica caught up
		s.sweepPITOverlaysOf(context.Background(), vms[i].Name)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the sweep settled a disk of a VM another host owns")
	}
}

// N3: a disk on a shared pool whose domain is not defined here is left alone
// (and reported): another host may be running it.
//
// Mutation "shared disk touched": sweepPITOverlaysOf skips the shared/defined
// check — red.
func TestSweep_LeavesASharedDiskWhoseDomainIsNotDefinedHere(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt = libvirtfake.New() // no domain defined here
	windowOverlay(t, live)
	if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET storage_type = 'nfs' WHERE vm_name = 'web'`); err != nil {
		t.Fatal(err)
	}
	s.SweepPITOverlays(context.Background(), caughtUp)
	if !pitoverlay.Present(live) {
		t.Fatal("the sweep settled a shared disk this host does not define")
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_left") {
		t.Errorf("not reported: %v", pitEventTypes(t, s, "web"))
	}
}

// N5: libvirt failing to report a domain's state is "unknown", never
// "inactive": nothing is committed offline and no stranded alert is raised.
//
// Mutation "error is inactive": domainActivity returns inactive on a state
// error — red.
func TestHeal_AnUnknownDomainStateTouchesNothing(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailDomainStateReason = func(string) error { return errors.New("libvirtd busy") }
	windowOverlay(t, live)
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	if err := s.healPITOverlay(context.Background(), vm, &disks[0]); err == nil {
		t.Fatal("heal proceeded without knowing whether the domain runs")
	}
	if !pitoverlay.Present(live) || holdsTheWindowsWrite(t, live) {
		t.Fatal("the overlay was committed while the domain state was unknown")
	}
	if slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_stranded") {
		t.Error("a false stranded alert was raised")
	}
}
