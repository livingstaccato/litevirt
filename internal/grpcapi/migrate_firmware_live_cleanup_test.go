package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// Review I-2 (ruling): the retry takes only cleaning markers. A released
// marker is left to restart recovery (D2-13), which re-sends Release or checks
// the target first (§8.1, §17 D-5 released + target fenced): its source state
// and definition stay whole.
//
// Mutation: retry released markers too — red.
func TestCleanupSource_RetryLeavesReleasedMarker(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	old := liveFirmwareSourceCleanup
	liveFirmwareSourceCleanup = nil
	t.Cleanup(func() { liveFirmwareSourceCleanup = old })
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	requireMarker(t, r, fwmig.PhaseReleased, "")
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	requireMarker(t, r, fwmig.PhaseReleased, "")
	r.requireSourceIntact("after a retry pass over a released marker")
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
	}
	if ents, _ := os.ReadDir(filepath.Join(r.src.dataDir, fwmig.RetainedDir)); len(ents) != 0 {
		t.Errorf("the cleanup began on a released marker: retained %v", ents)
	}
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

// ── Fix round 1 ──

// stoppedAtUndefine runs a move whose cleanup stops at the undefine (S1), the
// bundle written; the injected failure is then cleared.
func (r *fwlRig) stoppedAtUndefine() fwmig.Marker {
	r.t.Helper()
	r.srcFake.FailUndefinePreserv = func(string) error { return errors.New("injected undefine failure") }
	if err := r.migrate(); err != nil {
		r.t.Fatalf("the move landed, but reported %v", err)
	}
	m := requireMarker(r.t, r, fwmig.PhaseCleaning, "")
	r.srcFake.FailUndefinePreserv = nil
	return m
}

// cleanupCondition is the open cleanup condition of os1 on r's source.
func (r *fwlRig) cleanupCondition() (corrosion.HealthCondition, bool) {
	r.t.Helper()
	c, found, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigCleanupFailed, "vm", fwlVM)
	if err != nil {
		r.t.Fatal(err)
	}
	return c, found && c.Lifecycle != corrosion.ConditionResolved
}

// Review I-1: the retained bundle's 24 h start at the wipe, not at its write.
// A cleanup that stopped for three days after writing the bundle, then
// finished, leaves a bundle the sweep keeps for 24 h after the wipe.
//
// Mutation: drop the touch after the wipe — red.
func TestCleanupSource_RetainedWindowStartsAtTheWipe(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.stoppedAtUndefine()
	p := r.retained(m.Attempt)
	long := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(p, long, long); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.requireCleanedUp("after the resumed cleanup")
	wiped := time.Now()
	r.src.FirmwareRetainedSweepOnce(context.Background(), wiped)
	if !fwtExists(p) {
		t.Fatal("the bundle was removed at the wipe: its 24 h ran from its write")
	}
	r.src.FirmwareRetainedSweepOnce(context.Background(), wiped.Add(23*time.Hour))
	if !fwtExists(p) {
		t.Fatal("the bundle was removed 23 h after the wipe")
	}
	r.src.FirmwareRetainedSweepOnce(context.Background(), wiped.Add(25*time.Hour))
	if fwtExists(p) {
		t.Fatal("the bundle was kept 25 h after the wipe")
	}
}

// Review m-8: a resumed cleanup checks the bundle already there against the
// marker's hashes, not its size: one that does not hold the cutover's state
// stops the cleanup with nothing undefined or wiped.
//
// Mutation: accept any regular non-empty bundle — red.
func TestCleanupSource_ResumeRefusesBundleNotMatchingTheMarker(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.stoppedAtUndefine()
	other := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	r.write(other.NvramPath(fwlVM), []byte("some other VM's vars"))
	r.write(filepath.Join(other.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall"), fwlPermall)
	f, err := os.Create(r.retained(m.Attempt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.WriteFirmwareBundle(fwlVM, fwLiveUUID, f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.requireCleanupStopped("with a bundle that does not hold the cutover's state")
	r.requireSourceIntact("with a bundle that does not hold the cutover's state")
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
	}
}

// Review m-5: the TPM half of step 2's check. A permall that changed since
// the cutover stops the cleanup with nothing written or removed.
//
// Mutation: drop the permall hash check — red.
func TestCleanupSource_TPMStateChangedSinceCutoverStops(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	changed := []byte("TPM state written after the cutover")
	r.src.fwLive.stepHook = func(step string) {
		r.log.add(step)
		if step == "cleanup" {
			r.write(r.srcPermallPath(), changed)
		}
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	r.requireCleanupStopped("after the source TPM state changed")
	if b, _ := os.ReadFile(r.srcPermallPath()); !bytes.Equal(b, changed) {
		t.Errorf("source permall %q, want the changed one kept", b)
	}
	m, _ := r.marker()
	if fwtExists(r.retained(m.Attempt)) {
		t.Error("a bundle was written from a state the cutover did not record")
	}
}

// Review m-6: a source state that changed after the cutover never heals by
// itself; the condition says so and names the operator's step, not "retried
// once the cause is fixed".
//
// Mutation: give the hash mismatch the generic action — red.
func TestCleanupSource_StateChangedConditionNamesTheOperatorStep(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.src.fwLive.stepHook = func(step string) {
		r.log.add(step)
		if step == "cleanup" {
			r.write(r.srcStore.NvramPath(fwlVM), []byte("an NVRAM written after the cutover"))
		}
	}
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	c, open := r.cleanupCondition()
	if !open {
		t.Fatal("no cleanup condition")
	}
	for _, w := range []string{"changed after the cutover", "an operator", "D-5"} {
		if !strings.Contains(c.Evidence, w) {
			t.Errorf("evidence %s lacks %q", c.Evidence, w)
		}
	}
	if strings.Contains(c.Evidence, "once the cause is fixed") {
		t.Errorf("evidence %s promises a retry that cannot heal it", c.Evidence)
	}
}

// Review m-1: a cleanup stuck on the same cause writes its condition once,
// not on every pass; a new cause writes it again.
//
// Mutations: raise on every pass; never rewrite on a new cause — red.
func TestCleanupSource_StoppedConditionWrittenOnChangeOnly(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.FailUndefinePreserv = func(string) error { return errors.New("injected undefine failure") }
	if err := r.migrate(); err != nil {
		t.Fatalf("the move landed, but reported %v", err)
	}
	first, open := r.cleanupCondition()
	if !open {
		t.Fatal("no cleanup condition")
	}
	for i := 0; i < 3; i++ {
		r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	}
	again, _ := r.cleanupCondition()
	if again.ObserveCount != first.ObserveCount {
		t.Fatalf("the same cause was written %d more times", again.ObserveCount-first.ObserveCount)
	}
	r.srcFake.FailUndefinePreserv = func(string) error { return errors.New("another undefine failure") }
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	changed, _ := r.cleanupCondition()
	if changed.ObserveCount == first.ObserveCount || !strings.Contains(changed.Evidence, "another undefine failure") {
		t.Fatalf("a new cause was not written: %+v", changed)
	}
}

// Review m-2: a cleanup condition left open for a VM with no marker (a crash
// after the marker went) is resolved by the next retry pass.
//
// Mutation: leave such a condition — red.
func TestCleanupSource_RetryResolvesConditionWithoutMarker(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
		Code: condFwmigCleanupFailed, VM: fwlVM, Attempt: rsAttemptA, Source: "src-host", Target: "dst-host", Detail: "left by a crash"}); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if _, open := r.cleanupCondition(); open {
		t.Fatal("the cleanup condition of a VM with no marker is still open")
	}
}

// Review m-2, the order: the condition is resolved before the marker goes, so
// a crash in between leaves a marker (and the retry) rather than an open
// critical condition with nothing to resolve it.
//
// Mutation: resolve after the marker removal — red.
func TestCleanupSource_ResolvesBeforeUnmark(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.stoppedAtUndefine()
	var atRemoval struct {
		open bool
		seen bool
	}
	cleanupRemoveMarkerHook = func() {
		_, atRemoval.open = r.cleanupCondition()
		atRemoval.seen = true
	}
	t.Cleanup(func() { cleanupRemoveMarkerHook = nil })
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if !atRemoval.seen {
		t.Fatal("the marker removal was not reached")
	}
	if atRemoval.open {
		t.Fatal("the condition was still open when the marker was removed")
	}
	r.requireCleanedUp("after the resumed cleanup")
}

// Review m-4: one marker that cannot be read does not stop the retry pass
// over the others. The guard still refuses the undefine and the wipe while
// any record on the host cannot be read (its uuid scan reads them all, D2-6),
// so os1's cleanup is retried and stops at the guard, with the condition
// naming the unreadable record; once it is repaired the next pass finishes.
//
// Mutation: give up the pass on the unreadable marker — red.
func TestCleanupSource_RetryReachesOthersPastUnreadableMarker(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.stoppedAtUndefine()
	bad := filepath.Join(r.src.dataDir, fwmig.InflightDir, "aaa.json")
	r.write(bad, []byte("{"))
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	c, open := r.cleanupCondition()
	if !open || !strings.Contains(c.Evidence, "aaa.json") {
		t.Fatalf("os1's cleanup was not retried past the unreadable marker: %+v", c)
	}
	requireMarker(t, r, fwmig.PhaseCleaning, "")
	r.requireSourceIntact("while a record cannot be read")
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	r.requireCleanedUp("once the record was repaired")
}

// Review m-5: an owed-DISCARD record that cannot be read may name any
// attempt: the sweep removes nothing while one exists.
//
// Mutation: skip the unreadable owed-discard record — red.
func TestRetainedSweep_UnreadableOwedDiscardKeepsAll(t *testing.T) {
	s := testServerWithLocks(t)
	p := rsRetained(t, s, "os1", rsAttemptA)
	rsFile(t, p, 72*time.Hour)
	bad := filepath.Join(s.dataDir, fwmig.DiscardOwedDir, "os9-"+rsAttemptB+".json")
	if err := os.MkdirAll(filepath.Dir(bad), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.FirmwareRetainedSweepOnce(context.Background(), time.Now())
	if !fwtExists(p) {
		t.Fatal("a bundle was removed while an owed-discard record could not be read")
	}
}

// Review n-1: a cleanup that stops before it can record the cleaning phase
// leaves its marker released, which the cleanup retry does not take. Its
// condition must not promise the cleanup retry; it says the move is finished
// on the target and that the firmware move recovery, which checks the target
// first, resumes the cleanup.
//
// Mutation: give a released stop the generic action — red.
func TestCleanupSource_ReleasedStopDoesNotPromiseMinuteRetry(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	old := liveFirmwareSourceCleanup
	liveFirmwareSourceCleanup = nil
	t.Cleanup(func() { liveFirmwareSourceCleanup = old })
	if err := r.migrate(); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	m := requireMarker(t, r, fwmig.PhaseReleased, "")
	// A marker that cannot be written (it does not validate): the cleaning
	// phase is never recorded.
	bad := m
	bad.Since = time.Time{}
	if err := r.src.fwmigCleanupSource(context.Background(), bad); err == nil {
		t.Fatal("the cleanup went on without recording the cleaning phase")
	}
	requireMarker(t, r, fwmig.PhaseReleased, "")
	r.requireSourceIntact("after a stop at the cleaning phase")
	c, open := r.cleanupCondition()
	if !open {
		t.Fatal("no cleanup condition")
	}
	if strings.Contains(c.Evidence, "the cleanup is retried each minute") || !strings.Contains(c.Evidence, "stays released") ||
		!strings.Contains(c.Evidence, "recovery checks the target") {
		t.Fatalf("the condition of a released stop promises the cleanup retry, or does not say the marker stays released and the recovery takes it: %s", c.Evidence)
	}
}

// Review n-2: a cause whose text names the bundle's temp file (a write or
// sync of a fresh os.CreateTemp file each pass) is the same cause on every
// pass: the condition is written once.
//
// Mutation: keep the random temp name in the detail — red.
func TestCleanupSource_StoppedConditionIgnoresTempName(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	m := r.stoppedAtUndefine()
	tmp := r.retained(m.Attempt) + ".tmp-"
	ctx := context.Background()
	_ = r.src.liveFirmwareCleanupStopped(ctx, m, "write the retained bundle", &os.PathError{Op: "write", Path: tmp + "1234567", Err: errors.New("no space left on device")})
	first, open := r.cleanupCondition()
	if !open {
		t.Fatal("no cleanup condition")
	}
	for _, n := range []string{"7654321", "99"} {
		_ = r.src.liveFirmwareCleanupStopped(ctx, m, "write the retained bundle", &os.PathError{Op: "write", Path: tmp + n, Err: errors.New("no space left on device")})
	}
	again, _ := r.cleanupCondition()
	if again.ObserveCount != first.ObserveCount {
		t.Fatalf("the same cause on a fresh temp file was written %d more times: %s", again.ObserveCount-first.ObserveCount, again.Evidence)
	}
	if !strings.Contains(again.Evidence, ".tar.tmp-*") || !strings.Contains(again.Evidence, "no space left on device") {
		t.Errorf("the detail lost the cause or the temp file's pattern: %s", again.Evidence)
	}
}

// Review n-3: the touch at the wipe never moves the bundle's time back. A
// clock behind at the touch keeps the later time already there; a clock that
// is right moves an older time to now.
//
// Mutation: set now whatever the file has — red.
func TestTouchRetainedBundle_NeverMovesBack(t *testing.T) {
	p := filepath.Join(t.TempDir(), "os1-"+rsAttemptA+".tar")
	now := time.Now()
	rsFile(t, p, -48*time.Hour) // written 48 h "ahead" of a clock that is behind
	want := now.Add(48 * time.Hour)
	if err := touchRetainedBundle(p, now); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := fi.ModTime().Sub(want); d < -time.Second || d > time.Second {
		t.Fatalf("mtime %v after a touch at %v, want the later %v kept", fi.ModTime(), now, want)
	}
	rsFile(t, p, 72*time.Hour)
	if err := touchRetainedBundle(p, now); err != nil {
		t.Fatal(err)
	}
	if fi, _ = os.Stat(p); !fi.ModTime().Equal(now) && fi.ModTime().Sub(now).Abs() > time.Second {
		t.Fatalf("mtime %v after a touch at %v of a 72 h old bundle, want now", fi.ModTime(), now)
	}
}
