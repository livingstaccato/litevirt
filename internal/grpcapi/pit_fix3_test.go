package grpcapi

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// onOverlay puts the fake domain on disk's overlay, as a layer-2 window does.
func onOverlay(s *Server, snap *fakePITSnapshotter, disk string) {
	snap.mu.Lock()
	defer snap.mu.Unlock()
	if snap.onOverlay == nil {
		snap.onOverlay = map[string]bool{}
	}
	snap.onOverlay[pitoverlay.Path(disk)] = true
}

// R2: a live commit whose "committing" state cannot be recorded never starts:
// the VM stays on its untouched base plus overlay, reported, and a later
// settle retries.
//
// Mutation "commit unrecorded": commitPITOverlay ignores a MarkCommitting
// error — red.
func TestCommit_NotStartedWhenItCannotBeRecorded(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	windowOverlay(t, live)
	onOverlay(s, snap, live)
	prev := pitMarkCommitting
	pitMarkCommitting = func(string) error { return errors.New("ENOSPC") }
	defer func() { pitMarkCommitting = prev }()

	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	if err := s.healPITOverlay(context.Background(), vm, &disks[0]); err == nil {
		t.Fatal("heal went on without recording the commit")
	}
	if slices.Contains(snap.calls, "commit") {
		t.Fatal("the block-commit started although its committing state was not recorded")
	}
	if !pitoverlay.Present(live) || !slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_stranded") {
		t.Error("the window was not kept open and reported")
	}
}

// R2: a window whose overlay cannot be bound to its disk is not committed by
// the copy; it stays open, reported, and the next settle binds and commits it.
//
// Mutation "window unbound": copyViaExternalSnapshot ignores a Bind error —
// red.
func TestCopy_AnUnboundWindowIsNotCommittedThenRetried(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	prev := pitBind
	pitBind = func(string, pitoverlay.Owner) error { return errors.New("EIO") }
	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	pitBind = prev
	if slices.Contains(snap.calls, "commit") {
		t.Fatalf("an unbound window was committed: %v", snap.calls)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the open window's overlay is gone")
	}
	// Bind works again: the next settle binds the running window and commits it.
	snap.calls = nil
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	if err := s.healPITOverlay(context.Background(), vm, &disks[0]); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !slices.Contains(snap.calls, "commit") || pitoverlay.Present(live) {
		t.Errorf("the retry did not commit the window: calls %v", snap.calls)
	}
}

// Nit: a commit that pivoted before the daemon died, leaving the (now
// committed) overlay, is recognised — the VM runs on its disk, the binding
// says committing, the disk is the one the commit began on — and removed
// without a hold or an alarm.
//
// Mutation "already committed held": that branch is removed — red.
func TestHeal_AnAlreadyCommittedOverlayIsRemovedQuietly(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{}) // the domain is on its disk
	windowOverlay(t, live)
	if err := pitoverlay.MarkCommitting(live); err != nil {
		t.Fatal(err)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	if err := s.healPITOverlay(context.Background(), vm, &disks[0]); err != nil {
		t.Fatalf("heal: %v", err)
	}
	if pitoverlay.Present(live) || slices.Contains(pitEventTypes(t, s, "web"), vmEventPITOverlayHeld) {
		t.Error("an already-committed overlay was held instead of removed")
	}
}

// R2 (failure mode): the hold, and the admin's way out of it. Without
// --confirm nothing happens; with it the overlay is committed, audited, and
// the hold clears from InspectVM. A non-admin cannot.
//
// Mutation "resolve without admin": ResolvePITOverlay skips its admin check —
// red. Mutation "confirm ignored": the !confirm branch is removed — red.
func TestResolvePITOverlay_CommitsAHeldOverlayOnlyWhenAnAdminConfirms(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	// The base written since: the overlay cannot be verified, the VM is held.
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x33 0 512", live).CombinedOutput(); err != nil {
		t.Fatalf("write the base: %v %s", err, out)
	}
	if err := runRepl(t, s, time.Now()); err == nil {
		t.Fatal("a copy went on past an unverified overlay")
	}
	pbVM, _ := s.vmToProto(context.Background(), "web")
	if !strings.Contains(pbVM.GetPitOverlayHeld(), "lv resolve-pit-overlay web root") {
		t.Fatalf("inspect pit_overlay_held = %q, want the hold and the command", pbVM.GetPitOverlayHeld())
	}

	req := &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "commit"}
	if _, err := s.ResolvePITOverlay(userCtx("op", "operator"), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a non-admin resolve = %v, want PermissionDenied", err)
	}
	resp, err := s.ResolvePITOverlay(adminCtx(), req)
	if err != nil || resp.GetDone() || !pitoverlay.Present(live) {
		t.Fatalf("unconfirmed resolve = %+v, %v; nothing may be done", resp, err)
	}
	req.Confirm = true
	if resp, err = s.ResolvePITOverlay(adminCtx(), req); err != nil || !resp.GetDone() {
		t.Fatalf("confirmed resolve = %+v, %v", resp, err)
	}
	if pitoverlay.Present(live) {
		t.Error("the committed overlay is still there")
	}
	pbVM, _ = s.vmToProto(context.Background(), "web")
	if pbVM.GetPitOverlayHeld() != "" {
		t.Errorf("the hold did not clear: %q", pbVM.GetPitOverlayHeld())
	}
}

// R3: the start-up sweep's readiness trusts a cluster of one, which has no
// peer to catch up with and would otherwise never sweep.
//
// Mutation "caught-up only": pitSweepReady returns caughtUp directly — red.
func TestSweepReady_ACLusterOfOneIsTrusted(t *testing.T) {
	s, _, _ := pitServer(t)
	ready := s.pitSweepReady(context.Background(), func() (bool, string) { return false, "no peer exchange yet" })
	if ok, why := ready(); !ok {
		t.Fatalf("a single-host cluster is not ready to sweep: %s", why)
	}
}

// R5: lv rm of a VM whose disk it keeps settles that disk's overlay first,
// so the kept disk holds the overlay's writes.
//
// Mutation "kept disk unsettled": DeleteVM does not call
// settleKeptPITOverlays — red.
func TestDeleteVM_SettlesAKeptDisksOverlay(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	_, _ = s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "web", KeepDisks: true})
	if pitoverlay.Present(live) || !holdsTheWindowsWrite(t, live) {
		t.Fatal("the kept disk was left without its overlay's writes")
	}
}
