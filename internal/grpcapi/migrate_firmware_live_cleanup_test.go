package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// The source cleanup of a live firmware move (spec §6.7, §7 S1) and the 24 h
// retained bundle sweep (§4, DECISION 4-E), driven on the fwlRig.

// srcPermallPath is the source's permall file.
func (r *fwlRig) srcPermallPath() string {
	return filepath.Join(r.srcStore.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")
}

// retained is the attempt's retained bundle path on the source.
func (r *fwlRig) retained(attempt string) string {
	r.t.Helper()
	p, err := r.src.fwRecords().RetainedPath(fwlVM, attempt)
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

// retainedAttempt is the attempt of the one retained bundle on the source.
func (r *fwlRig) retainedAttempt() string {
	r.t.Helper()
	ents, err := os.ReadDir(filepath.Join(r.src.dataDir, fwmig.RetainedDir))
	if err != nil {
		r.t.Fatalf("no retained bundle directory: %v", err)
	}
	var tars []string
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tar" {
			tars = append(tars, e.Name())
		}
	}
	if len(tars) != 1 {
		r.t.Fatalf("retained bundles %v, want one", tars)
	}
	n := tars[0]
	return n[len(n)-len(".tar")-36 : len(n)-len(".tar")]
}

// requireBundleHoldsSourceState: the bundle at p restores the source's state
// byte for byte (into a fresh store, so nothing here is touched).
func requireBundleHoldsSourceState(t *testing.T, p string, wantPermall bool) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("retained bundle: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("retained bundle mode %v, want 0600", fi.Mode().Perm())
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fresh := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	if err := fresh.ReadFirmwareBundle(f, fwlVM, fwLiveUUID); err != nil {
		t.Fatalf("the retained bundle does not restore: %v", err)
	}
	if b, _ := os.ReadFile(fresh.NvramPath(fwlVM)); !bytes.Equal(b, fwlNvram) {
		t.Errorf("retained NVRAM %q, want the source's", b)
	}
	if !wantPermall {
		return
	}
	if b, _ := os.ReadFile(filepath.Join(fresh.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")); !bytes.Equal(b, fwlPermall) {
		t.Errorf("retained permall %q, want the source's", b)
	}
}

// requireCleanedUp: the move is finished on the source — marker gone, the
// leftover undefined, the source state wiped, the retained bundle holding it,
// the cleanup condition resolved — and the guest runs on the target.
func (r *fwlRig) requireCleanedUp(why string) {
	r.t.Helper()
	if m, ok := r.marker(); ok {
		r.t.Errorf("%s: marker left (%s)", why, m.Phase)
	}
	if st, ok := r.srcFake.RawState(fwlVM); ok {
		r.t.Errorf("%s: the source domain is still defined (%s)", why, st)
	}
	if fwtExists(r.srcPermallPath()) || fwtExists(r.srcStore.NvramPath(fwlVM)) {
		r.t.Errorf("%s: the source's firmware state was not wiped", why)
	}
	requireBundleHoldsSourceState(r.t, r.retained(r.retainedAttempt()), !r.sbOnly)
	requireNoFwmigCondition(r.t, r.src, condFwmigCleanupFailed)
	if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		r.t.Errorf("%s: target domain %q, want running", why, st)
	}
	if vm := r.row(); vm.HostName != "dst-host" || vm.State != "running" {
		r.t.Errorf("%s: row %s on %s, want running on dst-host", why, vm.State, vm.HostName)
	}
}

// requireCleanupStopped: the cleanup stopped (S1) — marker cleaning, the
// source state whole, its condition open — and the guest runs on the target.
func (r *fwlRig) requireCleanupStopped(why string) {
	r.t.Helper()
	requireMarker(r.t, r, fwmig.PhaseCleaning, "")
	requireFwmigCondition(r.t, r.src, condFwmigCleanupFailed)
	if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		r.t.Errorf("%s: target domain %q, want running", why, st)
	}
	if vm := r.row(); vm.HostName != "dst-host" || vm.State != "running" {
		r.t.Errorf("%s: row %s on %s, want running on dst-host", why, vm.State, vm.HostName)
	}
}

// T-22: §6.7's order. The marker goes to cleaning, the retained bundle is
// written, then the leftover definition is undefined (its state still whole
// at that moment), then the state is wiped, then the marker removed.
//
// Mutations: wipe first; undefine before the bundle — red.
func TestCleanupSource_BundleThenUndefineThenWipe(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	var at struct {
		called  bool
		marker  fwmig.Marker
		bundle  bool
		permall []byte
		nvram   []byte
	}
	r.onUndefineLeftover = func() {
		at.called = true
		at.marker, _ = r.marker()
		_, err := os.Stat(r.retained(at.marker.Attempt))
		at.bundle = err == nil
		at.permall, _ = os.ReadFile(r.srcPermallPath())
		at.nvram, _ = os.ReadFile(r.srcStore.NvramPath(fwlVM))
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v (steps %v)", err, r.log.get())
	}
	if !at.called {
		t.Fatal("the leftover definition was never undefined")
	}
	if at.marker.Phase != fwmig.PhaseCleaning {
		t.Errorf("at the undefine the marker is %s, want cleaning", at.marker.Phase)
	}
	if !at.bundle {
		t.Error("the leftover was undefined before the retained bundle was written")
	}
	if !bytes.Equal(at.permall, fwlPermall) || !bytes.Equal(at.nvram, fwlNvram) {
		t.Errorf("at the undefine the source state is permall %q nvram %q: wiped before the undefine", at.permall, at.nvram)
	}
	r.requireCleanedUp("after the cleanup")
	if a := r.retainedAttempt(); a != at.marker.Attempt {
		t.Errorf("retained bundle of attempt %s, want the move's %s", a, at.marker.Attempt)
	}
}

// T-22, Secure Boot only: no permall anywhere, and the bundle holds the NVRAM.
func TestCleanupSource_SecureBootOnly(t *testing.T) {
	r := newFwlRig(t, fwlOpts{sbOnly: true})
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v (steps %v)", err, r.log.get())
	}
	r.requireCleanedUp("after the cleanup of an SB-only VM")
}

// T-22: a retained bundle that cannot be written stops the cleanup — nothing
// undefined, nothing wiped, the marker cleaning, the condition raised (§7 S1)
// — and the move itself, which landed, still reports success.
//
// Mutation: continue after the bundle error — red.
func TestCleanupSource_BundleFailureStops(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	// A file where the bundle directory goes: MkdirAll fails, as root too.
	r.write(filepath.Join(r.src.dataDir, fwmig.RetainedDir), []byte("not a directory"))
	undefined := false
	r.onUndefineLeftover = func() { undefined = true }
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	r.requireCleanupStopped("after a bundle failure")
	if undefined {
		t.Error("the leftover was undefined without a retained bundle")
	}
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
	}
	r.requireSourceIntact("after a bundle failure")
}

// §7 S1, retried: once the cause is gone, the next pass finishes the cleanup
// and resolves its condition.
//
// Mutation: retry nothing (or only released markers) — red.
func TestCleanupSource_S1RetriedAfterBundleFailure(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	blocker := filepath.Join(r.src.dataDir, fwmig.RetainedDir)
	r.write(blocker, []byte("not a directory"))
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	r.requireCleanupStopped("after a bundle failure")
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.requireCleanedUp("after the retry")
}

// §7 S1, step 3: an undefine that fails stops the cleanup with the bundle
// written and the state whole; the retry finishes it.
//
// Mutation: wipe after a failed undefine — red.
func TestCleanupSource_S1UndefineFailureKeepsState(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.FailUndefinePreserv = func(string) error { return errors.New("injected undefine failure") }
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	r.requireCleanupStopped("after an undefine failure")
	r.requireSourceIntact("after an undefine failure")
	m, _ := r.marker()
	requireBundleHoldsSourceState(t, r.retained(m.Attempt), true)
	r.srcFake.FailUndefinePreserv = nil
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.requireCleanedUp("after the retry")
}

// §8.1 cleaning: a cleanup that died part way through its wipe (the bundle
// written, the leftover undefined, the NVRAM gone) resumes at its first undone
// step: the bundle is not rewritten from what is left.
//
// Mutation: rewrite the bundle whenever the cleanup runs — red.
func TestCleanupSource_ResumesAtFirstUndoneStep(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.FailUndefinePreserv = func(string) error { return errors.New("injected undefine failure") }
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	m := requireMarker(t, r, fwmig.PhaseCleaning, "")
	r.srcFake.FailUndefinePreserv = nil
	before, err := os.ReadFile(r.retained(m.Attempt))
	if err != nil {
		t.Fatal(err)
	}
	// The crash: undefined, and the wipe got as far as the NVRAM.
	if err := r.srcFake.UndefineFirmwareMoveLeftover(fwlVM, fwLiveUUID, m.Attempt); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.srcStore.NvramPath(fwlVM)); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if after, _ := os.ReadFile(r.retained(m.Attempt)); !bytes.Equal(after, before) {
		t.Fatal("the retained bundle was rewritten from a partly wiped state")
	}
	r.requireCleanedUp("after the resumed cleanup")
}

// Step 2 writes the bundle only from the state the cutover recorded: a source
// state that changed since (here its NVRAM) stops the cleanup with nothing
// removed — it may be the only copy of what changed.
//
// Mutation: drop the hash check before the bundle — red.
func TestCleanupSource_StateChangedSinceCutoverStops(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	changed := []byte("an NVRAM written after the cutover")
	r.src.fwLive.stepHook = func(step string) {
		r.log.add(step)
		if step == "cleanup" {
			r.write(r.srcStore.NvramPath(fwlVM), changed)
		}
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	r.requireCleanupStopped("after the source state changed")
	if b, _ := os.ReadFile(r.srcStore.NvramPath(fwlVM)); !bytes.Equal(b, changed) {
		t.Errorf("source NVRAM %q, want the changed one kept", b)
	}
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
	}
	m, _ := r.marker()
	if fwtExists(r.retained(m.Attempt)) {
		t.Error("a bundle was written from a state the cutover did not record")
	}
}

// A marker in released (the cleanup never began, e.g. the cleaning write
// failed) is cleaned up by the retry too.
//
// Mutation: retry only cleaning markers — red.
func TestCleanupSource_RetryTakesReleasedMarker(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	old := liveFirmwareSourceCleanup
	liveFirmwareSourceCleanup = nil
	t.Cleanup(func() { liveFirmwareSourceCleanup = old })
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	requireMarker(t, r, fwmig.PhaseReleased, "")
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.requireCleanedUp("after the retry of a released marker")
}

// The retry leaves every other phase alone: a parked move is not cleaned up.
//
// Mutation: retry any marker — red.
func TestCleanupSource_RetryLeavesParkedMoves(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.dstFake.OnRunning = func(string) {
		r.write(r.dstStore.NvramPath(fwlVM), []byte("a variable the guest wrote at once"))
	}
	fwvFast(t, 5*time.Millisecond, 100*time.Millisecond)
	_ = r.migrate()
	requireMarker(t, r, fwmig.PhaseNvramUnconfirmed, fwmig.PhaseCommitted)
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	requireMarker(t, r, fwmig.PhaseNvramUnconfirmed, fwmig.PhaseCommitted)
	r.requireSourceIntact("after a retry pass over a parked move")
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined", st, ok)
	}
	if ents, _ := os.ReadDir(filepath.Join(r.src.dataDir, fwmig.RetainedDir)); len(ents) != 0 {
		t.Errorf("the cleanup began on a parked move: retained %v", ents)
	}
}

// ── The retained sweep (T-27) ──

const (
	rsAttemptA = "aaaaaaaa-0000-4000-8000-00000000000a"
	rsAttemptB = "bbbbbbbb-0000-4000-8000-00000000000b"
	rsAttemptC = "cccccccc-0000-4000-8000-00000000000c"
	rsAttemptD = "dddddddd-0000-4000-8000-00000000000d"
)

// rsFile writes path with an mtime age ago.
func rsFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func rsRetained(t *testing.T, s *Server, vm, attempt string) string {
	t.Helper()
	p, err := s.fwRecords().RetainedPath(vm, attempt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func rsMarker(vm, attempt string, phase fwmig.Phase) fwmig.Marker {
	return fwmig.Marker{VM: vm, Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: "2026-10-16T00:00:00Z", Attempt: attempt},
		Target: "dst-host", Route: fwmig.RouteTunnelled, Phase: phase, TPM: true, UEFI: true, Since: time.Now().UTC()}
}

// T-27: a bundle is removed once it is 24 h old, a younger one kept; a
// crashed write's temp goes too; the quarantine is never read or touched,
// however old; a file the sweep does not recognise is left.
//
// Mutations: sweep the quarantine too; ignore the age — red.
func TestRetainedSweep_24hNeverQuarantine(t *testing.T) {
	s := testServerWithLocks(t)
	old, young := rsRetained(t, s, "os1", rsAttemptA), rsRetained(t, s, "os1", rsAttemptB)
	rsFile(t, old, 25*time.Hour)
	rsFile(t, young, 23*time.Hour)
	temp := rsRetained(t, s, "os1", rsAttemptC) + ".tmp-123456"
	rsFile(t, temp, 25*time.Hour)
	junk := filepath.Join(s.dataDir, fwmig.RetainedDir, "not-a-bundle.tar")
	rsFile(t, junk, 48*time.Hour)
	q, err := s.fwRecords().QuarantinePath("os1", rsAttemptD)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"nvram.fd", "reason.txt", "fwmig-inflight-os1.json", "swtpm/tpm2/tpm2-00.permall"} {
		rsFile(t, filepath.Join(q, f), 30*24*time.Hour)
	}
	qBundle := filepath.Join(q, "os1-"+rsAttemptD+".tar")
	rsFile(t, qBundle, 30*24*time.Hour)

	s.FirmwareRetainedSweepOnce(context.Background(), time.Now())

	if fwtExists(old) {
		t.Error("a 25 h old retained bundle was kept")
	}
	if !fwtExists(young) {
		t.Error("a 23 h old retained bundle was removed")
	}
	if fwtExists(temp) {
		t.Error("a crashed write's 25 h old temp was kept")
	}
	if !fwtExists(junk) {
		t.Error("a file the sweep does not recognise was removed")
	}
	for _, f := range []string{"nvram.fd", "reason.txt", "fwmig-inflight-os1.json", "swtpm/tpm2/tpm2-00.permall"} {
		if !fwtExists(filepath.Join(q, f)) {
			t.Errorf("the quarantine's %s was removed", f)
		}
	}
	if !fwtExists(qBundle) {
		t.Error("a bundle-named file in the quarantine was removed")
	}
}

// T-27: the retained bundle is the recovery copy. However old, it stays while
// a marker of its attempt names it (in progress or parked) or an owed DISCARD
// of its attempt is recorded; a marker of another attempt does not keep it.
//
// Mutations: ignore markers; ignore parked markers; ignore owed discards — red.
func TestRetainedSweep_KeepsWhileReferenced(t *testing.T) {
	s := testServerWithLocks(t)
	rec := s.fwRecords()
	byMarker := rsRetained(t, s, "os1", rsAttemptA)
	byPark := rsRetained(t, s, "os2", rsAttemptB)
	byOwed := rsRetained(t, s, "os3", rsAttemptC)
	free := rsRetained(t, s, "os4", rsAttemptD)
	for _, p := range []string{byMarker, byPark, byOwed, free} {
		rsFile(t, p, 72*time.Hour)
	}
	if err := rec.PutMarker(rsMarker("os1", rsAttemptA, fwmig.PhaseCleaning)); err != nil {
		t.Fatal(err)
	}
	parked, err := rsMarker("os2", rsAttemptB, fwmig.PhaseCleaning).Park(fwmig.PhaseTargetUnreachable)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.PutMarker(parked); err != nil {
		t.Fatal(err)
	}
	if err := rec.PutOwedDiscard(fwmig.OwedDiscard{VM: "os3", Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: "2026-10-16T00:00:00Z",
		Attempt: rsAttemptC}, Target: "dst-host", Since: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	// os4 has a marker, of a later attempt: it does not name the bundle.
	if err := rec.PutMarker(rsMarker("os4", rsAttemptA, fwmig.PhasePrepared)); err != nil {
		t.Fatal(err)
	}

	s.FirmwareRetainedSweepOnce(context.Background(), time.Now())

	if !fwtExists(byMarker) {
		t.Error("a bundle its attempt's marker names was removed")
	}
	if !fwtExists(byPark) {
		t.Error("a bundle its attempt's parked marker names was removed")
	}
	if !fwtExists(byOwed) {
		t.Error("a bundle its attempt's owed DISCARD names was removed")
	}
	if fwtExists(free) {
		t.Error("a 72 h old bundle no record names was kept")
	}
}

// A marker that cannot be read may name any attempt: the sweep removes
// nothing while one exists.
//
// Mutation: skip the unreadable marker — red.
func TestRetainedSweep_UnreadableMarkerKeepsAll(t *testing.T) {
	s := testServerWithLocks(t)
	p := rsRetained(t, s, "os1", rsAttemptA)
	rsFile(t, p, 72*time.Hour)
	bad := filepath.Join(s.dataDir, fwmig.InflightDir, "os9.json")
	if err := os.MkdirAll(filepath.Dir(bad), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.FirmwareRetainedSweepOnce(context.Background(), time.Now())
	if !fwtExists(p) {
		t.Fatal("a bundle was removed while a marker could not be read")
	}
}

// The sweep does not wait on a VM's lock (a move in progress holds it): that
// VM's bundles wait for the next pass.
//
// Mutation: take the lock blocking — the test times out, red.
func TestRetainedSweep_SkipsLockedVM(t *testing.T) {
	s := testServerWithLocks(t)
	p := rsRetained(t, s, "os1", rsAttemptA)
	rsFile(t, p, 72*time.Hour)
	unlock := s.lockVM("os1")
	done := make(chan struct{})
	go func() {
		s.FirmwareRetainedSweepOnce(context.Background(), time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		unlock()
		t.Fatal("the sweep waited on the VM's lock")
	}
	unlock()
	if !fwtExists(p) {
		t.Fatal("the bundle of a VM whose lock was held was removed")
	}
	s.FirmwareRetainedSweepOnce(context.Background(), time.Now())
	if fwtExists(p) {
		t.Fatal("the bundle was kept once the lock was free")
	}
}

// ── D2-12b re-review m-A ──

// The adopter's M1p (the client went away, then the migration failed and
// left the source guest paused, the target holding nothing): the guest is
// resumed first, and its VFs go back into the resumed guest.
//
// Mutation: reattach before the adopter's M1p resume — red.
func TestAdoptedFirmwareMigration_M1pResumedGuestGetsItsVFs(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	fs := newPCIUnbindRecordingFS()
	t.Cleanup(vfio.SetFS(fs))
	const vf = "0000:41:10.0"
	if err := corrosion.UpsertPCIDevice(adminCtx(), r.src.db, corrosion.PCIDeviceRecord{
		HostName: "src-host", Address: vf, Type: "net", VendorID: "8086", VMName: fwlVM}); err != nil {
		t.Fatal(err)
	}
	fs.setVF(vf)
	fs.setBound(vf)
	if err := r.srcFake.AttachHostdev(fwlVM, vf); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	proceed := make(chan struct{})
	r.srcFake.FailMigrateToTarget = func(string, string) error {
		cancel() // the client goes away mid-copy
		<-proceed
		r.srcFake.SetState(fwlVM, libvirtfake.StatePaused)
		return errors.New("injected failure that left the guest paused")
	}
	err := r.src.MigrateVM(&pb.MigrateVMRequest{VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE},
		&mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v, want the adopted move's DeadlineExceeded", err)
	}
	close(proceed)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := r.marker(); !ok && r.row().State == "running" {
			break
		}
		if time.Now().After(deadline) {
			m, ok := r.marker()
			t.Fatalf("the adopted M1p was not settled: marker %+v (%v), row %s, aborts %v", m, ok, r.row().State, r.aborts())
		}
		time.Sleep(10 * time.Millisecond)
	}
	requireAbortModes(t, r, modePre)
	if st, _ := r.srcFake.RawState(fwlVM); st != libvirtfake.StateRunning {
		t.Fatalf("source domain %q, want resumed", st)
	}
	if !guestHasHostdev(t, r.src, fwlVM, vf) {
		t.Fatal("the resumed guest runs without its VF")
	}
}
