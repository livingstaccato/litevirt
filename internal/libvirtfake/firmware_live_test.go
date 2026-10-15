package libvirtfake

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// The fake models what libvirt did to the firmware state in the lab probes
// (trackD-probe-results.md), so a grpcapi or fleet test that asserts on a
// firmware move's state asserts on what a host would hold.

const (
	flVM   = "fwvm"
	flUUID = "0b6f7f62-1c39-4c8c-9a0e-6f0c2f4c7a11"
	flXML  = "<domain><name>" + flVM + "</name><uuid>" + flUUID + "</uuid>" +
		"<os><loader secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE_4M.secboot.fd</loader>" +
		"<nvram>/var/lib/litevirt/nvram/" + flVM + "_VARS.fd</nvram></os>" +
		"<devices><tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='yes'/></tpm></devices></domain>"
)

var (
	flPermall = []byte("permall: the source's TPM permanent state")
	flNvramS  = []byte("nvram: the source's final UEFI vars (T1)")
	flNvramT0 = []byte("nvram: what Prepare materialised on the target (T0)")
)

// flHost is one host: a fake with a store of its own.
func flHost(t *testing.T) (*Fake, *libvirt.FirmwareStore) {
	t.Helper()
	root := t.TempDir()
	fw := &libvirt.FirmwareStore{DataDir: filepath.Join(root, "data"), SwtpmBase: filepath.Join(root, "swtpm")}
	f := New()
	f.SetFirmwareStore(fw)
	return f, fw
}

func flPermallPath(fw *libvirt.FirmwareStore) string {
	return filepath.Join(fw.SwtpmDir(flUUID), "tpm2", "tpm2-00.permall")
}

func flWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func flRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func flAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s: stat = %v, want absent", path, err)
	}
}

// flSource is a source host with the VM defined in state st, its swtpm tree
// and its NVRAM on disk.
func flSource(t *testing.T, st State) (*Fake, *libvirt.FirmwareStore) {
	t.Helper()
	f, fw := flHost(t)
	if err := f.DefineDomain(flXML); err != nil {
		t.Fatal(err)
	}
	f.SetState(flVM, st)
	flWrite(t, flPermallPath(fw), flPermall)
	flWrite(t, filepath.Join(fw.SwtpmDir(flUUID), "tpm2", ".lock"), nil)
	flWrite(t, fw.NvramPath(flVM), flNvramS)
	return f, fw
}

// Probe (g): litevirt's UndefineDomain(name, false) on a shut-off TPM domain
// deleted the NVRAM and kept the swtpm tree. The preserving undefine
// (KEEP_NVRAM|KEEP_TPM, probe (b)) kept both, byte-unchanged. A refused
// undefine changes nothing.
//
// Mutations: keep the NVRAM on UndefineDomain — red; delete the swtpm tree
// too — red; delete the NVRAM on the preserving undefine — red; delete
// before the guard is asked — red.
func TestFake_UndefineModelsProbeG(t *testing.T) {
	for _, removeStorage := range []bool{false, true} {
		name := "UndefineDomain/remove_storage=false"
		if removeStorage {
			name = "UndefineDomain/remove_storage=true"
		}
		t.Run(name, func(t *testing.T) {
			f, fw := flSource(t, StateShutdown)
			if err := f.UndefineDomain(flVM, removeStorage); err != nil {
				t.Fatal(err)
			}
			if f.DomainExists(flVM) {
				t.Error("domain still defined")
			}
			flAbsent(t, fw.NvramPath(flVM))
			if got := flRead(t, flPermallPath(fw)); !bytes.Equal(got, flPermall) {
				t.Errorf("permall = %q, want it kept byte-for-byte", got)
			}
		})
	}
	t.Run("UndefineDomainPreservingState", func(t *testing.T) {
		f, fw := flSource(t, StateShutdown)
		if err := f.UndefineDomainPreservingState(flVM); err != nil {
			t.Fatal(err)
		}
		if f.DomainExists(flVM) {
			t.Error("domain still defined")
		}
		if got := flRead(t, fw.NvramPath(flVM)); !bytes.Equal(got, flNvramS) {
			t.Errorf("nvram = %q, want it kept", got)
		}
		if got := flRead(t, flPermallPath(fw)); !bytes.Equal(got, flPermall) {
			t.Errorf("permall = %q, want it kept", got)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f, fw := flSource(t, StateShutdown)
		f.SetFirmwareMoveGuard(libvirt.FirmwareMoveGuard{Check: func(libvirt.FirmwareCall) error {
			return libvirt.ErrFirmwareMoveInFlight
		}})
		if err := f.UndefineDomain(flVM, false); !errors.Is(err, libvirt.ErrFirmwareMoveInFlight) {
			t.Fatalf("UndefineDomain = %v, want the guard's refusal", err)
		}
		if got := flRead(t, fw.NvramPath(flVM)); !bytes.Equal(got, flNvramS) {
			t.Errorf("nvram = %q after a refused undefine, want it kept", got)
		}
	})
	t.Run("no store", func(t *testing.T) {
		// A fake with no store has no firmware state to delete: the
		// undefine still works, as it did before the model.
		f := New()
		if err := f.DefineDomain(flXML); err != nil {
			t.Fatal(err)
		}
		if err := f.UndefineDomain(flVM, false); err != nil {
			t.Fatal(err)
		}
	})
}

// flMigrate migrates the VM from src to dst as libvirt would: src's
// MigrateToTarget, with dst landing it (the fleet harness's hook).
func flMigrate(t *testing.T, src, dst *Fake, p libvirt.MigrateParams) (libvirt.MigrateParams, error) {
	t.Helper()
	var seen libvirt.MigrateParams
	src.OnMigrateToTarget = func(name, _ string, p libvirt.MigrateParams) error {
		seen = p
		return dst.LandFirmwareLive(src, name, p)
	}
	err := src.MigrateToTarget(flVM, "qemu+tls://10.0.0.2/system", p)
	return seen, err
}

var flLive = libvirt.MigrateParams{Live: true, FirmwareLive: true, WithStorage: true, TLS: true,
	TargetAddress: "10.0.0.2", TLSDestination: "10.0.0.2"}

// A FirmwareLive migrate does what probes (b), (c) and (d) observed:
//   - the source stays defined, shut off, reason migrated, its swtpm tree
//     and NVRAM intact;
//   - the target domain is defined and paused, whatever Paused said, with
//     the permall copied byte-for-byte into the target's store;
//   - the target's NVRAM is what was there (the template when absent) until
//     the guest resumes, and the source's final NVRAM after.
//
// Mutations: land the target running when Paused is unset (D2-4 m-2) — red;
// undefine or keep running the source — red; report the source reason
// unknown — red; copy the permall from anywhere but the source — red; write
// the source NVRAM at arrival instead of on resume — red; never write it —
// red; overwrite a materialised NVRAM with the template — red; keep the
// migrated vars past a shut-off — red; keep the migrated reason past a start
// — red; land over an active domain of the name — red; ignore any knob —
// red.
func TestFake_FirmwareLiveModelsProbe(t *testing.T) {
	t.Run("materialised NVRAM", func(t *testing.T) {
		src, sfw := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		flWrite(t, dfw.NvramPath(flVM), flNvramT0)
		seen, err := flMigrate(t, src, dst, flLive)
		if err != nil {
			t.Fatal(err)
		}
		if !seen.Paused {
			t.Error("libvirt was not asked to land the guest paused")
		}
		// Source: probe (b).
		if st, ok := src.RawState(flVM); !ok || st != StateShutdown {
			t.Errorf("source = %q (defined %v), want defined and shut off", st, ok)
		}
		if src.DefinedXML(flVM) == "" {
			t.Error("source lost its persistent definition")
		}
		if ds, err := src.DomainStateReason(flVM); err != nil || ds.State != "stopped" || ds.Reason != "migrated" {
			t.Errorf("source state = %+v, %v; want stopped, migrated", ds, err)
		}
		if got := flRead(t, flPermallPath(sfw)); !bytes.Equal(got, flPermall) {
			t.Errorf("source permall = %q, want it intact", got)
		}
		if got := flRead(t, sfw.NvramPath(flVM)); !bytes.Equal(got, flNvramS) {
			t.Errorf("source nvram = %q, want it intact", got)
		}
		// Target: paused, the permall copied (probe (c)).
		if st, ok := dst.RawState(flVM); !ok || st != StatePaused {
			t.Fatalf("target = %q (defined %v), want defined and paused", st, ok)
		}
		if !strings.Contains(dst.DefinedXML(flVM), flUUID) {
			t.Error("target has no persistent definition of the guest (PERSIST_DEST)")
		}
		ssum, _ := sfw.PermallSHA256(flUUID)
		dsum, err := dfw.PermallSHA256(flUUID)
		if err != nil || dsum != ssum {
			t.Errorf("target permall sha256 = %q, %v; want the source's %q", dsum, err, ssum)
		}
		// NVRAM: written on resume (probe (d)).
		if got := flRead(t, dfw.NvramPath(flVM)); !bytes.Equal(got, flNvramT0) {
			t.Errorf("target nvram while paused = %q, want the materialised T0", got)
		}
		if err := dst.ResumeFirmwareMoveTarget(flVM, flUUID, "attempt"); err != nil {
			t.Fatal(err)
		}
		if got := flRead(t, dfw.NvramPath(flVM)); !bytes.Equal(got, flNvramS) {
			t.Errorf("target nvram after resume = %q, want the source's final %q", got, flNvramS)
		}
		// A later stop and start keeps what the guest wrote: the migrated
		// vars are written once.
		flWrite(t, dfw.NvramPath(flVM), []byte("the guest's own later write"))
		_ = dst.DestroyDomain(flVM)
		if err := dst.StartDomain(flVM); err != nil {
			t.Fatal(err)
		}
		if got := flRead(t, dfw.NvramPath(flVM)); string(got) != "the guest's own later write" {
			t.Errorf("target nvram after a restart = %q, want the guest's own write", got)
		}
	})
	t.Run("no NVRAM on the target", func(t *testing.T) {
		// libvirt copies the template when the file is absent.
		src, _ := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		if _, err := flMigrate(t, src, dst, flLive); err != nil {
			t.Fatal(err)
		}
		if got := flRead(t, dfw.NvramPath(flVM)); !bytes.Equal(got, TemplateNVRAM) {
			t.Errorf("target nvram while paused = %q, want the template", got)
		}
		if err := dst.ResumeDomain(flVM); err != nil {
			t.Fatal(err)
		}
		if got := flRead(t, dfw.NvramPath(flVM)); !bytes.Equal(got, flNvramS) {
			t.Errorf("target nvram after resume = %q, want the source's", got)
		}
	})
	t.Run("refused route", func(t *testing.T) {
		// What MigrateToTarget refuses never reaches libvirt: nothing moves.
		src, _ := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		p := flLive
		p.TLS = false
		if _, err := flMigrate(t, src, dst, p); err == nil {
			t.Fatal("a storage copy without TLS was not refused")
		}
		if st, _ := src.RawState(flVM); st != StateRunning {
			t.Errorf("source = %q, want still running", st)
		}
		if dst.DomainExists(flVM) || dfw.HasTPMState(flUUID) {
			t.Error("the target got a domain or a tree from a refused migrate")
		}
	})
	t.Run("ordinary migrate", func(t *testing.T) {
		// Not a firmware move: the source is left as the fake always left it.
		src, _ := flSource(t, StateRunning)
		src.OnMigrateToTarget = func(string, string, libvirt.MigrateParams) error { return nil }
		if err := src.MigrateToTarget(flVM, "qemu+tls://10.0.0.2/system", libvirt.MigrateParams{Live: true}); err != nil {
			t.Fatal(err)
		}
		if st, _ := src.RawState(flVM); st != StateRunning {
			t.Errorf("source = %q after an ordinary migrate, want unchanged", st)
		}
	})

	// Knobs.
	t.Run("knob/corrupt permall", func(t *testing.T) {
		src, sfw := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		dst.CorruptLandedPermall = func(name string) bool { return name == flVM }
		if _, err := flMigrate(t, src, dst, flLive); err != nil {
			t.Fatal(err)
		}
		ssum, _ := sfw.PermallSHA256(flUUID)
		dsum, err := dfw.PermallSHA256(flUUID)
		if err != nil || dsum == ssum {
			t.Errorf("target permall sha256 = %q, %v; want it to differ from the source's", dsum, err)
		}
	})
	t.Run("knob/fail after the target tree", func(t *testing.T) {
		src, _ := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		boom := errors.New("migration failed after the target's swtpm tree was created")
		dst.FailAfterTargetTree = func(string) error { return boom }
		if _, err := flMigrate(t, src, dst, flLive); !errors.Is(err, boom) {
			t.Fatalf("migrate = %v, want the knob's error", err)
		}
		if !dfw.HasTPMState(flUUID) {
			t.Error("the target tree was not left behind")
		}
		if dst.DomainExists(flVM) {
			t.Error("the target has a domain after the failed migrate")
		}
		if st, _ := src.RawState(flVM); st != StateRunning {
			t.Errorf("source = %q, want still running", st)
		}
	})
	t.Run("knob/held target shut off", func(t *testing.T) {
		// Shut off while paused: the migrated vars were never written, and a
		// later start does not write them.
		src, _ := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		flWrite(t, dfw.NvramPath(flVM), flNvramT0)
		if _, err := flMigrate(t, src, dst, flLive); err != nil {
			t.Fatal(err)
		}
		dst.ShutOffDomain(flVM, "crashed")
		if st, ok := dst.RawState(flVM); !ok || st != StateShutdown {
			t.Fatalf("target = %q (defined %v), want defined and shut off", st, ok)
		}
		if ds, _ := dst.DomainStateReason(flVM); ds.Reason != "crashed" {
			t.Errorf("target reason = %q, want crashed", ds.Reason)
		}
		if err := dst.StartDomain(flVM); err != nil {
			t.Fatal(err)
		}
		// A pause and resume of the new run writes nothing either.
		if err := dst.SuspendDomain(flVM); err != nil {
			t.Fatal(err)
		}
		if err := dst.ResumeDomain(flVM); err != nil {
			t.Fatal(err)
		}
		if got := flRead(t, dfw.NvramPath(flVM)); !bytes.Equal(got, flNvramT0) {
			t.Errorf("target nvram = %q, want T0 (the migrated vars died with the paused guest)", got)
		}
	})
	t.Run("knob/target shut off after resume", func(t *testing.T) {
		src, _ := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		flWrite(t, dfw.NvramPath(flVM), flNvramT0)
		if _, err := flMigrate(t, src, dst, flLive); err != nil {
			t.Fatal(err)
		}
		if err := dst.ResumeDomain(flVM); err != nil {
			t.Fatal(err)
		}
		dst.ShutOffDomain(flVM, "unknown")
		if got := flRead(t, dfw.NvramPath(flVM)); !bytes.Equal(got, flNvramS) {
			t.Errorf("target nvram = %q, want T1 (written on resume)", got)
		}
	})
	t.Run("knob/source reason unknown", func(t *testing.T) {
		src, _ := flSource(t, StateRunning)
		dst, _ := flHost(t)
		src.ReportSourceReasonUnknown = func(name string) bool { return name == flVM }
		if _, err := flMigrate(t, src, dst, flLive); err != nil {
			t.Fatal(err)
		}
		if ds, _ := src.DomainStateReason(flVM); ds.State != "stopped" || ds.Reason != "unknown" {
			t.Errorf("source = %+v, want stopped, unknown", ds)
		}
		if st, _ := src.RawState(flVM); st != StateShutdown {
			t.Errorf("source = %q, want shut off", st)
		}
	})
	t.Run("source restarted", func(t *testing.T) {
		// The migrated reason belongs to that shut-off: a start clears it.
		src, _ := flSource(t, StateRunning)
		dst, _ := flHost(t)
		if _, err := flMigrate(t, src, dst, flLive); err != nil {
			t.Fatal(err)
		}
		if err := src.StartDomain(flVM); err != nil {
			t.Fatal(err)
		}
		if ds, _ := src.DomainStateReason(flVM); ds.Reason != "running" {
			t.Errorf("source reason after a start = %q, want running", ds.Reason)
		}
		src.SetState(flVM, StateShutdown)
		if ds, _ := src.DomainStateReason(flVM); ds.Reason != "unknown" {
			t.Errorf("source reason after a later shut-off = %q, want unknown, not the old migrated", ds.Reason)
		}
	})
	t.Run("name taken on the target", func(t *testing.T) {
		// libvirt refuses an incoming guest whose name an active domain
		// holds, before swtpm starts: no tree, the source untouched.
		src, _ := flSource(t, StateRunning)
		dst, dfw := flHost(t)
		if err := dst.DefineDomain(flXML); err != nil {
			t.Fatal(err)
		}
		dst.SetState(flVM, StateRunning)
		if _, err := flMigrate(t, src, dst, flLive); err == nil {
			t.Fatal("migrate onto an active domain of the name was not refused")
		}
		if dfw.HasTPMState(flUUID) {
			t.Error("the refused migrate created a tree on the target")
		}
		if st, _ := src.RawState(flVM); st != StateRunning {
			t.Errorf("source = %q, want still running", st)
		}
	})
}
