package libvirtfake

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// The fake's model of what libvirt does to a domain's firmware state, as the
// lab probes observed it (trackD-probe-results.md; spec §0, §15 "Fake
// prerequisites"). It acts on the files of the store SetFirmwareStore gives
// it, directly, as libvirt and swtpm do: none of it goes through the store's
// own guarded methods. A fake with no store has no firmware state.
//
//   - Probe (g): UndefineDomain (litevirt passes UNDEFINE_NVRAM) deletes the
//     domain's NVRAM file and keeps its swtpm tree.
//     UndefineDomainPreservingState (KEEP_NVRAM|KEEP_TPM, probe (b)) keeps
//     both.
//   - Probe (b): a FirmwareLive migrate (no UNDEFINE_SOURCE) leaves the
//     source defined and shut off, reason migrated, its state intact.
//   - Probe (c): the target gets the permall byte-for-byte.
//   - Probe (d): the target's NVRAM file is what was there while the guest
//     is paused (libvirt copies the template when there is none), and the
//     source's final NVRAM once it resumes.

// TemplateNVRAM is what the fake's libvirt copies to a target that has no
// NVRAM file when a UEFI guest migrates in (the MS template on a host).
var TemplateNVRAM = []byte("libvirtfake: OVMF_VARS template\n")

// SetFirmwareStore gives the fake the host's firmware store: the files its
// libvirt model reads and writes.
func (f *Fake) SetFirmwareStore(s *libvirt.FirmwareStore) {
	f.mu.Lock()
	f.fwStore = s
	f.mu.Unlock()
}

// FirmwareStore is the store SetFirmwareStore gave the fake, or nil.
func (f *Fake) FirmwareStore() *libvirt.FirmwareStore {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fwStore
}

func permallPath(s *libvirt.FirmwareStore, uuid string) string {
	return filepath.Join(s.SwtpmDir(uuid), "tpm2", "tpm2-00.permall")
}

// deleteNvramLocked is probe (g): libvirt unlinks the domain's NVRAM file on
// an undefine with UNDEFINE_NVRAM. Caller holds f.mu.
func (f *Fake) deleteNvramLocked(name string) {
	if f.fwStore == nil {
		return
	}
	if err := os.Remove(f.fwStore.NvramPath(name)); err == nil {
		f.record("nvram-deleted", name, "")
	}
}

// LandFirmwareLive lands on this fake (the target host) a FirmwareLive
// migrate of name from src, as libvirt did in the probes: the domain is
// defined (PERSIST_DEST) and paused, the swtpm permall is copied into this
// host's store, and the NVRAM file is left as it is (the template when there
// is none) until the guest resumes, when the source's final NVRAM is
// written. The fleet harness calls it from src's OnMigrateToTarget.
//
// Knobs on this fake: CorruptLandedPermall alters the copied permall;
// FailAfterTargetTree fails the migrate once the tree exists, with no domain
// defined here.
func (f *Fake) LandFirmwareLive(src *Fake, name string, p libvirt.MigrateParams) error {
	src.mu.Lock()
	live, persist, srcStore := p.DestXML, p.PersistXML, src.fwStore
	if live == "" {
		live = src.liveXMLLocked(name)
	}
	if persist == "" {
		persist = src.xml[name]
	}
	_, srcHas := src.domains[name]
	src.mu.Unlock()
	if !srcHas {
		return fmt.Errorf("libvirtfake: migrate %q: no such domain on the source", name)
	}
	if persist == "" {
		persist = live
	}
	uuid := domainUUIDFromXML(live)

	f.mu.Lock()
	dstStore := f.fwStore
	if srcStore == nil || dstStore == nil {
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: migrate %q: a firmware move needs a firmware store on both fakes", name)
	}
	// libvirt refuses an incoming domain whose name is taken by another
	// uuid, or by an active domain, before anything starts.
	if st, ok := f.domains[name]; ok {
		if st == StateRunning || st == StatePaused {
			f.mu.Unlock()
			return fmt.Errorf("libvirtfake: migrate %q: domain is already active on the target", name)
		}
		if cur := domainUUIDFromXML(f.liveXMLLocked(name)); cur != "" && !strings.EqualFold(cur, uuid) {
			f.mu.Unlock()
			return fmt.Errorf("libvirtfake: migrate %q: domain already exists with uuid %s", name, cur)
		}
	}
	corrupt, failTree := f.CorruptLandedPermall, f.FailAfterTargetTree
	f.mu.Unlock()

	// swtpm on the target receives the permanent state from the stream.
	if uuid != "" {
		if permall, err := os.ReadFile(permallPath(srcStore, uuid)); err == nil {
			if corrupt != nil && corrupt(name) {
				permall = append(bytes.Clone(permall), []byte(" (corrupted in transit)")...)
			}
			dir := filepath.Join(dstStore.SwtpmDir(uuid), "tpm2")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "tpm2-00.permall"), permall, 0o600); err != nil {
				return err
			}
			// The running swtpm holds its lock file.
			if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0o600); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if failTree != nil {
		if err := failTree(name); err != nil {
			return err
		}
	}

	// NVRAM: the target file stays as it is while paused; libvirt copies
	// the template to a UEFI guest's path when there is none.
	srcNvram, nerr := os.ReadFile(srcStore.NvramPath(name))
	if nerr != nil && !os.IsNotExist(nerr) {
		return nerr
	}
	uefi := nerr == nil || strings.Contains(live, "<nvram")
	if uefi {
		path := dstStore.NvramPath(name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(path, TemplateNVRAM, 0o600); err != nil {
				return err
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[name] = StatePaused
	f.xml[name] = persist
	if live != persist {
		f.activeXML[name] = live
	} else {
		delete(f.activeXML, name)
	}
	delete(f.offReason, name)
	if nerr == nil {
		if f.pendingNvram == nil {
			f.pendingNvram = map[string][]byte{}
		}
		f.pendingNvram[name] = srcNvram
	}
	f.captureConsolePasswordsLocked(name, live)
	f.record("migrate-in", name, "firmware_live=true paused=true")
	return nil
}

// flushPendingNvramLocked is probe (d): when a migrated-in guest resumes,
// QEMU writes the migrated pflash, the source's final NVRAM, to the file.
// Caller holds f.mu.
func (f *Fake) flushPendingNvramLocked(name string) {
	b, ok := f.pendingNvram[name]
	if !ok {
		return
	}
	delete(f.pendingNvram, name)
	if f.fwStore == nil {
		return
	}
	path := f.fwStore.NvramPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.record("nvram-write-failed", name, err.Error())
		return
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		f.record("nvram-write-failed", name, err.Error())
		return
	}
	f.record("nvram-written", name, "migrated")
}

// leftStateLocked forgets what belonged to the domain's last state: the
// migrated pflash of a guest that never resumed (it dies with the paused
// QEMU), and the reason of a shut-off. Caller holds f.mu.
func (f *Fake) leftStateLocked(name string) {
	delete(f.pendingNvram, name)
	delete(f.offReason, name)
}

// ShutOffDomain takes a domain to shut off with reason, as a crash of its
// QEMU or of its host does: a held target that never resumed loses the
// migrated NVRAM, one that resumed keeps what was written. Scenario knob.
func (f *Fake) ShutOffDomain(name, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return
	}
	f.leftStateLocked(name)
	f.domains[name] = StateShutdown
	delete(f.liveConsolePw, name)
	if f.offReason == nil {
		f.offReason = map[string]string{}
	}
	f.offReason[name] = reason
	f.record("shutoff", name, "reason="+reason)
}

// migratedOutLocked is probe (b) on the source of a migrate that keeps its
// definition: shut off, reason migrated (or unknown, by the
// ReportSourceReasonUnknown knob), the state files untouched. Caller holds
// f.mu.
func (f *Fake) migratedOutLocked(name string) {
	if _, ok := f.domains[name]; !ok {
		return
	}
	f.leftStateLocked(name)
	f.domains[name] = StateShutdown
	delete(f.liveConsolePw, name)
	reason := "migrated"
	if f.ReportSourceReasonUnknown != nil && f.ReportSourceReasonUnknown(name) {
		reason = "unknown"
	}
	if f.offReason == nil {
		f.offReason = map[string]string{}
	}
	f.offReason[name] = reason
	f.record("migrate-out", name, "reason="+reason)
}
