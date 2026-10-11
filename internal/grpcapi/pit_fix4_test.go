package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/randid"
)

// Round 4 of the colonelpanik/litevirt#256 review.

func healWeb(t *testing.T, s *Server) error {
	t.Helper()
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "web")
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	return s.healPITOverlay(context.Background(), vm, &disks[0])
}

func writeBase(t *testing.T, disk, cmd string) {
	t.Helper()
	time.Sleep(10 * time.Millisecond)
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", cmd, disk).CombinedOutput(); err != nil {
		t.Fatalf("qemu-io %s: %v %s", cmd, err, out)
	}
}

func regionHolds(t *testing.T, qcow string, b byte) bool {
	t.Helper()
	got := rawContent(t, qcow)
	if len(got) < 131072 {
		return false
	}
	for _, c := range got[65536:131072] {
		if c != b {
			return false
		}
	}
	return true
}

func heldCondition(t *testing.T, s *Server, vm, disk string) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, pitHoldEvaluator, pitHoldCode, "disk", vm+"/"+disk)
	if err != nil {
		t.Fatal(err)
	}
	return row, found
}

// stoppedWithStaleOverlay is a VM off, whose overlay cannot be verified: the
// base was written after the window was taken.
func stoppedWithStaleOverlay(t *testing.T) (*Server, string) {
	t.Helper()
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	writeBase(t, live, "write -P 0x33 0 512")
	return s, live
}

// N1: the window's token is on the disk, durably, BEFORE the snapshot opens
// the window, and the binding records that very token.
//
// Mutation "no token" (copyViaExternalSnapshot opens no window token) — red.
func TestCopy_TheWindowTokenIsOnTheDiskBeforeTheSnapshot(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	probe := filepath.Join(filepath.Dir(live), ".probe")
	_ = os.WriteFile(probe, nil, 0o600)
	if err := unix.Setxattr(probe, "user.probe", []byte("x"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{commitErr: errExample("pivot refused")} // keep the window, and its binding, open
	var atSnap string
	snap.atSnapshot = func(p string) {
		buf := make([]byte, 128)
		if n, err := unix.Getxattr(p, "user.litevirt.pit_window", buf); err == nil {
			atSnap = string(buf[:n])
		}
	}
	s.SetPointInTimeSnapshotter(snap)
	_ = runRepl(t, s, time.Now())
	if atSnap == "" {
		t.Fatal("the disk carried no window token when the snapshot opened the window")
	}
	b, err := pitoverlay.BindingOf(live)
	if err != nil || b.Token != atSnap {
		t.Fatalf("binding %+v (%v) does not record the token %q the disk carried", b, err, atSnap)
	}
}

type errExample string

func (e errExample) Error() string { return string(e) }

// N3: a live commit records the pivot before it lands (the libvirt side runs
// beforePivot), so a crash right after it is recognised.
//
// Mutation "no pivot record" (commitPITOverlay passes no beforePivot) — red.
func TestCommit_RecordsThePivotBeforeItLands(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if snap.pivotsRecorded != 1 {
		t.Fatalf("pivots recorded before landing: %d, want 1", snap.pivotsRecorded)
	}
	if pitoverlay.Present(live) {
		t.Error("the committed overlay is still there")
	}
}

// N3 / N1: the VM found running on its disk while the binding says a commit
// was under way, with no pivot recorded, ran on the disk without the
// overlay. It is held and marked diverged, so that once the VM is stopped
// the overlay is still never committed over the disk's newer writes.
//
// Mutation "diverged not recorded" — red (the stopped VM's settle commits).
func TestHeal_AVMOnItsDiskMidCommitIsHeldEvenOnceStopped(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{}) // the domain runs on its disk
	windowOverlay(t, live)
	if err := pitoverlay.MarkCommitting(live); err != nil {
		t.Fatal(err)
	}
	if err := healWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("heal = %v, want the VM held", err)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the overlay was removed")
	}
	writeBase(t, live, "write -P 0x33 65536 65536") // the guest, on its disk
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	if err := healWeb(t, s); err == nil {
		t.Fatal("the stopped VM's overlay was settled")
	}
	if !regionHolds(t, live, 0x33) {
		t.Fatal("the overlay was committed over the writes the VM made on its disk")
	}
}

// N2: the dry run gives the verdict and what each action would do.
//
// Mutation "no verdict in the dry run" — red.
func TestResolvePITOverlay_TheDryRunGivesTheVerdict(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	if err := pitoverlay.MarkCommitting(live); err != nil { // a commit was cut short
		t.Fatal(err)
	}
	resp, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root"})
	if err != nil || resp.GetDone() {
		t.Fatalf("dry run = %+v, %v", resp, err)
	}
	if resp.GetVerdict() != "half-written" || !strings.Contains(resp.GetIfDiscard(), "REFUSED") ||
		strings.Contains(resp.GetIfCommit(), "REFUSED") || !strings.Contains(resp.GetRecommendation(), "--commit") {
		t.Fatalf("dry run: verdict %q, commit %q, discard %q, recommendation %q",
			resp.GetVerdict(), resp.GetIfCommit(), resp.GetIfDiscard(), resp.GetRecommendation())
	}
	if resp.GetCurrent() == "" || resp.GetBackingFile() == "" {
		t.Errorf("the dry run does not show the disk's identity now (%q) or the backing file (%q)", resp.GetCurrent(), resp.GetBackingFile())
	}
}

// N2: --commit is refused unless the verdict says a commit is safe;
// --force-commit is the expert's override.
//
// Mutation "commit whatever the verdict" — red.
func TestResolvePITOverlay_ACommitNeedsASafeVerdictOrForce(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	req := &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "commit", Confirm: true}
	if _, err := s.ResolvePITOverlay(adminCtx(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit of an unverified overlay = %v, want refused", err)
	}
	if !pitoverlay.Present(live) || holdsTheWindowsWrite(t, live) {
		t.Fatal("the refused commit touched the disk or the overlay")
	}
	req.ForceCommit = true
	resp, err := s.ResolvePITOverlay(adminCtx(), req)
	if err != nil || !resp.GetDone() || !holdsTheWindowsWrite(t, live) {
		t.Fatalf("forced commit = %+v, %v", resp, err)
	}
}

// N2: the overlay of a pivot that landed is already in the disk: a commit is
// refused (it would overwrite the guest's newer writes), a discard is the
// cleanup.
//
// Mutation "commit of a pivoted overlay allowed" — red.
func TestResolvePITOverlay_APivotedOverlayIsDiscardedNeverCommitted(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	for _, f := range []func(string) error{pitoverlay.MarkCommitting, pitoverlay.MarkPivoting, pitoverlay.MarkCommitted} {
		if err := f(live); err != nil {
			t.Fatal(err)
		}
	}
	writeBase(t, live, "write -P 0x33 65536 65536") // the guest, after the pivot
	req := &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "commit", Confirm: true}
	if _, err := s.ResolvePITOverlay(adminCtx(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit of a merged overlay = %v, want refused", err)
	}
	req.Action = "discard"
	if resp, err := s.ResolvePITOverlay(adminCtx(), req); err != nil || !resp.GetDone() {
		t.Fatalf("discard = %+v, %v", resp, err)
	}
	if !regionHolds(t, live, 0x33) || pitoverlay.Present(live) {
		t.Fatal("the guest's writes after the pivot were not kept, or the overlay stayed")
	}
}

// N2: discarding the overlay of a half-written disk leaves it inconsistent:
// refused without --accept-torn-disk, and the refusal says so and names the
// alternative.
//
// Mutation "discard of a torn disk allowed" — red.
func TestResolvePITOverlay_DiscardingAHalfWrittenDiskNeedsTheFlag(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	windowOverlay(t, live)
	if err := pitoverlay.MarkCommitting(live); err != nil {
		t.Fatal(err)
	}
	req := &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "discard", Confirm: true}
	_, err := s.ResolvePITOverlay(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept-torn-disk") ||
		!strings.Contains(err.Error(), "backup") {
		t.Fatalf("discard of a half-written disk = %v, want refused naming the flag and the restore", err)
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the refused discard removed the overlay")
	}
	req.AcceptTornDisk = true
	if resp, err := s.ResolvePITOverlay(adminCtx(), req); err != nil || !resp.GetDone() || pitoverlay.Present(live) {
		t.Fatalf("discard with --accept-torn-disk = %+v, %v", resp, err)
	}
}

// N2: the hold says what to do for its verdict, never a blind "commit".
//
// Mutation "the hold recommends commit-or-discard blindly" — red.
func TestHold_TheMessageRecommendsTheVerdictsAction(t *testing.T) {
	s, _ := stoppedWithStaleOverlay(t)
	err := healWeb(t, s)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("heal = %v, want held", err)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "verdict unknown") || strings.Contains(msg, "--commit|--discard") ||
		strings.Contains(msg, "--commit --confirm") || !strings.Contains(msg, "lv resolve-pit-overlay web root") {
		t.Fatalf("hold message %q: want the verdict and its advice, never a blind commit", msg)
	}
}

// N4: a hold is a degraded (warning) health condition per held disk, and
// `lv inspect` reads it from that durable row — not from the event tail,
// which newer events push it out of and another disk's events cleared. It
// resolves when the hold clears.
//
// Mutations "no condition" and "inspect reads the event tail" — red.
func TestHold_IsADurableConditionPerDiskUntilItClears(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	_ = healWeb(t, s)
	row, found := heldCondition(t, s, "web", "root")
	if !found || row.Lifecycle == corrosion.ConditionResolved || row.Severity != corrosion.SeverityWarning {
		t.Fatalf("held condition = %+v (found %v), want an open warning", row, found)
	}
	ctx := context.Background()
	_ = corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{ID: randid.New(), VMName: "web", HostName: s.hostName,
		Type: "disk.pit_overlay_committed", Result: "ok", Severity: "info", Detail: "data: another disk's overlay"})
	for i := 0; i < 150; i++ {
		_ = corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{ID: randid.New(), VMName: "web", HostName: s.hostName,
			Type: "vm.noise", Result: "ok", Severity: "info", Detail: "noise"})
	}
	pbVM, _ := s.vmToProto(ctx, "web")
	if !strings.Contains(pbVM.GetPitOverlayHeld(), "root") {
		t.Fatalf("inspect lost the hold: %q", pbVM.GetPitOverlayHeld())
	}
	resp, err := s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{VmName: "web", DiskName: "root", Action: "discard", Confirm: true})
	if err != nil || !resp.GetDone() || pitoverlay.Present(live) {
		t.Fatalf("discard = %+v, %v", resp, err)
	}
	if row, _ := heldCondition(t, s, "web", "root"); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("the condition did not resolve with the hold: %+v", row)
	}
	if pbVM, _ := s.vmToProto(ctx, "web"); pbVM.GetPitOverlayHeld() != "" {
		t.Errorf("inspect still shows a cleared hold: %q", pbVM.GetPitOverlayHeld())
	}
}

// N5: a hold notifies once when it begins, then at most daily — not on every
// operation that meets it.
//
// Mutation "notify on every hold" — red.
func TestHold_NotifiesOnceThenAtMostDaily(t *testing.T) {
	s, _ := stoppedWithStaleOverlay(t)
	seen := seenNotifications(s)
	count := func() (n, ev int) {
		for _, x := range *seen {
			if x.Kind == "replication.pit_overlay_held" {
				n++
			}
		}
		for _, e := range pitEventTypes(t, s, "web") {
			if e == vmEventPITOverlayHeld {
				ev++
			}
		}
		return
	}
	for i := 0; i < 3; i++ {
		_ = healWeb(t, s)
	}
	if n, ev := count(); n != 1 || ev != 1 {
		t.Fatalf("three operations on one hold: %d notifications, %d events; want 1 and 1", n, ev)
	}
	row, _ := heldCondition(t, s, "web", "root")
	var ev map[string]any
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	ev["notified_at"] = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(ev)
	row.Evidence = string(b)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, row); err != nil {
		t.Fatal(err)
	}
	_ = healWeb(t, s)
	if n, _ := count(); n != 2 {
		t.Fatalf("a hold a day old: %d notifications, want a second one", n)
	}
}

// Ruling 6: no layer-2 overlay on a volatile filesystem (tmpfs, or devtmpfs
// beside a /dev block disk): the copy goes on to the next layer.
//
// Mutation "placement unchecked" — red.
func TestCopy_NoOverlayOnAVolatileFilesystem(t *testing.T) {
	recordQemuImg(t)
	s, dir, _ := pitServer(t)
	defer pitoverlay.SetVolatileOKForTest(false)()
	defer pitoverlay.SetDirFSTypeForTest(pitoverlay.FSTmpfs)()
	s.SetBackupSource(failingBackupSource{})
	snap := &fakePITSnapshotter{}
	s.SetPointInTimeSnapshotter(snap)
	if err := runRepl(t, s, time.Now()); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	if slices.Contains(snap.calls, "snapshot") {
		t.Fatal("an overlay was snapshotted onto tmpfs")
	}
	if recs := replicaRecordsOf(t, dir, "web"); len(recs) != 1 || !recs[0].NotPointInTime {
		t.Fatalf("records %+v: want the last layer's marked copy", recs)
	}
}

// Nit: an import that sets aside an overlay whose disk it also moved aside
// says where that disk went, so the pair can be found again.
//
// Mutation "the base's new name left out" — red.
func TestImport_TheSetAsideNamesWhereItsDiskWent(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	windowOverlay(t, live)
	aside := live + ".orphan-1234"
	if err := s.setAsideStaleOverlay(context.Background(), "web", "root", live, aside); err != nil {
		t.Fatal(err)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "web", 10, "")
	for _, e := range evs {
		if e.Type == "disk.pit_overlay_set_aside" && strings.Contains(e.Detail, aside) {
			return
		}
	}
	t.Fatalf("the set-aside does not say the disk went to %s: %+v", aside, evs)
}

// N3: a live commit that runs long keeps renewing its attempt stamp, so its
// own base writes stay within the bound however long it takes.
//
// Mutation "the live commit does not keep its stamp fresh" — red.
func TestCommit_ALiveCommitKeepsItsStampFresh(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	prevEvery := pitoverlay.RefreshEvery
	pitoverlay.RefreshEvery = 20 * time.Millisecond
	defer func() { pitoverlay.RefreshEvery = prevEvery }()
	snap := &fakePITSnapshotter{commitTakes: 400 * time.Millisecond}
	s.SetPointInTimeSnapshotter(snap)
	windowOverlay(t, live)
	onOverlay(s, snap, live)
	var began, atPivot int64
	prevMark, prevPivot := pitMarkCommitting, pitMarkPivoting
	pitMarkCommitting = func(d string) error {
		err := prevMark(d)
		b, _ := pitoverlay.BindingOf(d)
		began = b.CommitAttemptNs
		return err
	}
	pitMarkPivoting = func(d string) error {
		b, _ := pitoverlay.BindingOf(d)
		atPivot = b.CommitAttemptNs
		return prevPivot(d)
	}
	defer func() { pitMarkCommitting, pitMarkPivoting = prevMark, prevPivot }()
	if err := healWeb(t, s); err != nil {
		t.Fatalf("heal: %v", err)
	}
	if began == 0 || atPivot-began < int64(250*time.Millisecond) {
		t.Fatalf("the stamp moved %v during a 400ms commit; want it renewed while the commit ran", time.Duration(atPivot-began))
	}
}
