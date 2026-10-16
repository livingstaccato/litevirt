package grpcapi

// The source cleanup of a live firmware move (spec §6.7, fwmigCleanupSource)
// and the 24 h retained bundle sweep (§4, DECISION 4-E).
//
// The cleanup runs once the target released the guest and confirmed its NVRAM
// (marker released): the guest runs there, ownership is committed, and the
// target's copy is the current one. It keeps the source's copy first, as the
// retained bundle, and only then undefines the leftover definition and wipes
// the state. Any step that fails stops it with everything after kept (§7 S1):
// the marker stays cleaning, its start veto in force, and the next pass
// resumes at the first undone step.
//
// The retained bundle is the recovery copy. The sweep removes it 24 h after
// it was written, and never while a marker (in progress or parked) or an owed
// DISCARD names its attempt. It never reads fwmig-quarantine/.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Timing of the retained sweep; vars so tests can shorten them.
var (
	// firmwareRetainedKeep is how long a retained bundle is kept (DECISION 4-E).
	firmwareRetainedKeep = 24 * time.Hour
	// firmwareRetainedSweepInterval is how often the sweep looks, and how
	// often a stopped cleanup is retried (§7 S1).
	firmwareRetainedSweepInterval = time.Minute
)

func init() { liveFirmwareSourceCleanup = liveFirmwareCleanupAfterRelease }

// liveFirmwareCleanupAfterRelease is the cleanup as the move calls it, right
// after Release. The move itself landed: a cleanup that stops raised its
// condition and is retried, so it is not the move's error.
func liveFirmwareCleanupAfterRelease(s *Server, ctx context.Context, m fwmig.Marker) error {
	if err := s.fwmigCleanupSource(ctx, m); err != nil {
		slog.Warn("live firmware move: released, but the source cleanup stopped; it is retried", "vm", m.VM, "attempt", m.Attempt, "error", err)
	}
	return nil
}

// fwmigCleanupSource is §6.7, from a released marker or, resumed at its first
// undone step, a cleaning one. The caller holds the VM's lock.
//
//  1. Marker cleaning.
//  2. The retained bundle, written durably from the state the cutover
//     recorded; skipped when the attempt's bundle is already there.
//  3. UndefineFirmwareMoveLeftover (state kept); skipped when no domain of
//     the name is defined.
//  4. WipeFirmwareMoveSource (the guard requires the bundle).
//  5. The marker removed.
//
// A failed step raises firmware_migration_cleanup_failed and returns its
// error; no later step is taken (§7 S1).
func (s *Server) fwmigCleanupSource(ctx context.Context, m fwmig.Marker) error {
	ctx = context.WithoutCancel(ctx)
	switch m.Phase {
	case fwmig.PhaseReleased:
		m.Phase = fwmig.PhaseCleaning
		if err := s.fwRecords().PutMarker(m); err != nil {
			return s.liveFirmwareCleanupStopped(ctx, m, "record the cleaning phase", err)
		}
	case fwmig.PhaseCleaning:
	default:
		return fmt.Errorf("VM %q: the source cleanup of live firmware migration %s runs from released or cleaning, not %s", m.VM, m.Attempt, m.Phase)
	}
	if err := s.writeRetainedFirmwareBundle(m); err != nil {
		return s.liveFirmwareCleanupStopped(ctx, m, "write the retained bundle", err)
	}
	if err := s.undefineLiveFirmwareLeftover(m); err != nil {
		return s.liveFirmwareCleanupStopped(ctx, m, "undefine the leftover definition", err)
	}
	if err := s.fw().WipeFirmwareMoveSource(m.VM, m.UUID, m.Attempt); err != nil {
		return s.liveFirmwareCleanupStopped(ctx, m, "wipe the source state", err)
	}
	if err := s.fwRecords().RemoveMarker(m.VM); err != nil {
		return s.liveFirmwareCleanupStopped(ctx, m, "remove the marker", err)
	}
	_ = s.resolveFirmwareMigrationCondition(ctx, condFwmigCleanupFailed, m.VM)
	retained, _ := s.fwRecords().RetainedPath(m.VM, m.Attempt)
	slog.Info("live firmware move: source cleaned up; its firmware state is retained for 24 h",
		"vm", m.VM, "attempt", m.Attempt, "target", m.Target, "retained", retained)
	s.recordVMEvent(ctx, m.VM, "vm.migrate.firmware", "ok", fmt.Sprintf(
		"live firmware migration %s to %s finished; the source's firmware state is kept in %s for 24 h", m.Attempt, m.Target, retained))
	return nil
}

// liveFirmwareCleanupStopped is §7 S1: the condition raised, the source state
// kept, the marker as it is (cleaning), retried by the next pass.
func (s *Server) liveFirmwareCleanupStopped(ctx context.Context, m fwmig.Marker, step string, cause error) error {
	retained, _ := s.fwRecords().RetainedPath(m.VM, m.Attempt)
	detail := fmt.Sprintf("the source cleanup could not %s: %v", step, cause)
	if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
		Code: condFwmigCleanupFailed, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
		Hashes: map[string]string{"src_permall_sha256": m.SrcPermallSHA256, "src_nvram_sha256": m.SrcNvramSHA256},
		Paths:  []string{retained, s.fw().SwtpmDir(m.UUID), s.fw().NvramPath(m.VM)},
		Detail: detail,
		Action: "the VM runs on the target; the source's firmware state is kept, and the cleanup is retried each minute once the cause is fixed",
	}); cerr != nil {
		slog.Warn("live firmware move: raise the condition", "vm", m.VM, "code", condFwmigCleanupFailed, "error", cerr)
	}
	slog.Error("live firmware move: the source cleanup stopped; the source state is kept", "vm", m.VM, "attempt", m.Attempt, "step", step, "error", cause)
	return fmt.Errorf("VM %q: live firmware migration %s: %s", m.VM, m.Attempt, detail)
}

// writeRetainedFirmwareBundle is §6.7 step 2. A bundle of the attempt already
// there is the one an earlier pass wrote (it is renamed into place only once
// synced) and is kept as it is: what is left of the source state may be
// partly wiped. Otherwise the source state must still be what the cutover
// recorded — a state that changed since may hold the only copy of the change,
// so nothing is written and the cleanup stops — and is written temp → fsync →
// rename → directory fsync, mode 0600.
func (s *Server) writeRetainedFirmwareBundle(m fwmig.Marker) error {
	path, err := s.fwRecords().RetainedPath(m.VM, m.Attempt)
	if err != nil {
		return err
	}
	switch fi, err := os.Lstat(path); {
	case err == nil && fi.Mode().IsRegular() && fi.Size() > 0:
		return nil
	case err == nil:
		return fmt.Errorf("%s is there and is not a bundle (mode %v, %d bytes)", path, fi.Mode(), fi.Size())
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	fw := s.fw()
	if m.TPM {
		got, err := fw.PermallSHA256(m.UUID)
		if err != nil {
			return fmt.Errorf("read the source TPM state: %w", err)
		}
		if got != m.SrcPermallSHA256 {
			return fmt.Errorf("the source TPM state is %s, not the %s recorded at cutover", got, m.SrcPermallSHA256)
		}
	}
	if m.UEFI {
		got, err := fw.NvramSHA256(m.VM)
		if err != nil {
			return fmt.Errorf("read the source NVRAM: %w", err)
		}
		if got != m.SrcNvramSHA256 {
			return fmt.Errorf("the source NVRAM is %s, not the %s recorded at cutover", got, m.SrcNvramSHA256)
		}
	}
	dir := filepath.Dir(path)
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := syncDirPath(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*") // mode 0600
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp.Name())
		}
	}()
	has, err := fw.WriteFirmwareBundle(m.VM, m.UUID, tmp)
	if err == nil && !has {
		err = errors.New("the source has no firmware state to keep")
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	renamed = true
	return syncDirPath(dir)
}

// undefineLiveFirmwareLeftover is §6.7 step 3: the leftover definition goes,
// its state kept for step 4. Only libvirt's own "no such domain" counts as
// already undefined; an active domain is never undefined (it would run on as a
// transient one).
func (s *Server) undefineLiveFirmwareLeftover(m fwmig.Marker) error {
	if s.virt == nil {
		return errors.New("no libvirt connection")
	}
	active, err := s.virt.DomainIsActive(m.VM)
	switch {
	case lv.IsNoDomain(err):
		return nil
	case err != nil:
		return err
	case active:
		return errors.New("the source domain is active")
	}
	return s.virt.UndefineFirmwareMoveLeftover(m.VM, m.UUID, m.Attempt)
}

// ── Retries and the retained sweep ──

// RunFirmwareRetainedSweep retries each stopped source cleanup and sweeps the
// retained bundles, now and every firmwareRetainedSweepInterval, until ctx is
// done.
func (s *Server) RunFirmwareRetainedSweep(ctx context.Context) {
	t := time.NewTicker(firmwareRetainedSweepInterval)
	defer t.Stop()
	for {
		s.RetryLiveFirmwareCleanupsOnce(ctx)
		s.FirmwareRetainedSweepOnce(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RetryLiveFirmwareCleanupsOnce runs the cleanup of each marker in released or
// cleaning (§7 S1: a cleanup that stopped, or one that never began). A VM
// whose lock is held (its move, or anything else, still runs) waits for the
// next pass; the marker is re-read under the lock.
func (s *Server) RetryLiveFirmwareCleanupsOnce(ctx context.Context) {
	markers, err := s.fwRecords().ListMarkers()
	if err != nil {
		// firmware_migration_record_unreadable names the file.
		slog.Warn("live firmware move: the markers cannot be read; no cleanup is retried", "error", err)
		return
	}
	for _, m := range markers {
		if m.Phase != fwmig.PhaseReleased && m.Phase != fwmig.PhaseCleaning {
			continue
		}
		unlock, ok := s.tryLockVM(m.VM)
		if !ok {
			continue
		}
		cur, found, err := s.fwRecords().GetMarker(m.VM)
		if err == nil && found && cur.Attempt == m.Attempt && (cur.Phase == fwmig.PhaseReleased || cur.Phase == fwmig.PhaseCleaning) {
			_ = s.fwmigCleanupSource(ctx, cur)
		}
		unlock()
	}
}

// retainedNameRe is a retained bundle's file name, or a crashed write's temp:
// <vm>-<attempt>.tar[.tmp-<digits>]. The attempt is a UUID.
var retainedNameRe = regexp.MustCompile(`^(.+)-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.tar(\.tmp-[0-9]+)?$`)

// FirmwareRetainedSweepOnce removes each retained bundle (and each crashed
// write's temp) older than firmwareRetainedKeep at now whose attempt no marker
// (in progress or parked) and no owed DISCARD names. It reads only
// fwmig-retained/, leaves anything there it does not recognise, does not wait
// on a VM's lock, and removes nothing while a marker or owed-discard record
// cannot be read.
func (s *Server) FirmwareRetainedSweepOnce(ctx context.Context, now time.Time) {
	rec := s.fwRecords()
	dir := filepath.Join(s.fw().DataDir, fwmig.RetainedDir)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		slog.Warn("retained firmware sweep: the directory cannot be read", "dir", dir, "error", err)
		return
	}
	for _, e := range ents {
		sub := retainedNameRe.FindStringSubmatch(e.Name())
		if sub == nil || !e.Type().IsRegular() {
			continue
		}
		vm, attempt := sub[1], sub[2]
		want, err := rec.RetainedPath(vm, attempt)
		if err != nil || filepath.Base(want)+sub[3] != e.Name() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() || now.Sub(fi.ModTime()) < firmwareRetainedKeep {
			continue
		}
		unlock, ok := s.tryLockVM(vm)
		if !ok {
			continue
		}
		why, keep := s.retainedBundleNamed(attempt)
		if keep {
			unlock()
			slog.Debug("retained firmware sweep: kept", "path", path, "why", why)
			continue
		}
		err = os.Remove(path)
		unlock()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("retained firmware sweep: remove", "path", path, "error", err)
			continue
		}
		_ = syncDirPath(dir)
		slog.Info("retained firmware sweep: removed a retained firmware bundle past its 24 h", "vm", vm, "attempt", attempt, "path", path,
			"written", fi.ModTime().UTC().Format(time.RFC3339))
	}
}

// retainedBundleNamed reports whether a record still names attempt's bundle:
// a marker of the attempt (any phase), or an owed DISCARD of it. A record
// that cannot be read may name it, so it keeps the bundle too. Markers are
// read before owed discards: fence resolution writes the owed record before
// it removes the marker, so a reference moving between them is seen.
func (s *Server) retainedBundleNamed(attempt string) (string, bool) {
	rec := s.fwRecords()
	markers, err := rec.ListMarkers()
	if err != nil {
		return fmt.Sprintf("the markers cannot be read: %v", err), true
	}
	for _, m := range markers {
		if strings.EqualFold(m.Attempt, attempt) {
			return fmt.Sprintf("marker of %s in %s", m.VM, m.Phase), true
		}
	}
	owed, err := rec.ListOwedDiscards()
	if err != nil {
		return fmt.Sprintf("the owed discards cannot be read: %v", err), true
	}
	for _, o := range owed {
		if strings.EqualFold(o.Attempt, attempt) {
			return fmt.Sprintf("owed DISCARD of %s to %s", o.VM, o.Target), true
		}
	}
	return "", false
}
