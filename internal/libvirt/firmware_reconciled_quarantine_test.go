package libvirt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// D2-18 re-review 3, n-1: the reconciler's quarantine of a leftover is staged
// and renamed into place whole. A failure after the NVRAM moved and before
// the swtpm tree did leaves only the stage, never a final directory; the next
// pass finishes the same stage into one directory holding the NVRAM, the tree
// and reason.txt. reason.txt is fsynced, and so is the directory holding it,
// before the stage takes its final name; the final name's directory is
// fsynced after. A definition with no uuid has its NVRAM quarantined alone.
//
// Mutations: gather straight into the final directory — red (split); write
// reason.txt with os.WriteFile — red (durable); refuse a "" uuid as before —
// red (no_uuid).
func TestQuarantineLeftoverFirmwareState(t *testing.T) {
	reason := []byte("vm: vm1\n")
	dirs := func(e *fwEnv) (string, string) {
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine")
		return filepath.Join(q, "vm1-reconciling-"+fwTestUUID), filepath.Join(q, "vm1-reconciled-100")
	}
	whole := func(t *testing.T, final string, swtpm bool) {
		t.Helper()
		if b, err := os.ReadFile(filepath.Join(final, "nvram")); err != nil || string(b) != "T0" {
			t.Errorf("quarantined nvram = %q, %v", b, err)
		}
		_, err := os.Stat(filepath.Join(final, "swtpm", "tpm2", "tpm2-00.permall"))
		if (err == nil) != swtpm {
			t.Errorf("quarantined swtpm present = %v, want %v", err == nil, swtpm)
		}
		if b, err := os.ReadFile(filepath.Join(final, "reason.txt")); err != nil || string(b) != string(reason) {
			t.Errorf("reason.txt = %q, %v", b, err)
		}
	}

	t.Run("split", func(t *testing.T) {
		e := newFWEnv(t, fwState{name: "none"}, golibvirt.DomainShutoff)
		stage, final := dirs(e)
		defer func(r func(string, string) error) { quarantineRename = r }(quarantineRename)
		quarantineRename = func(o, n string) error {
			if o == e.store.SwtpmDir(fwTestUUID) {
				return errors.New("injected crash before the tree moved")
			}
			return os.Rename(o, n)
		}
		if err := e.store.QuarantineLeftoverFirmwareState(fwTestVM, fwTestUUID, stage, final, reason); err == nil {
			t.Fatal("a stopped quarantine reported success")
		}
		if _, err := os.Lstat(final); !os.IsNotExist(err) {
			t.Fatalf("the final directory exists after a stopped pass (%v)", err)
		}
		if !e.hasSwtpm() {
			t.Fatal("the swtpm tree is gone although it did not move")
		}
		quarantineRename = os.Rename
		final2 := filepath.Join(filepath.Dir(final), "vm1-reconciled-200")
		if err := e.store.QuarantineLeftoverFirmwareState(fwTestVM, fwTestUUID, stage, final2, reason); err != nil {
			t.Fatal(err)
		}
		whole(t, final2, true)
		ents, _ := os.ReadDir(filepath.Dir(final))
		if len(ents) != 1 {
			t.Errorf("quarantine entries %v, want the one finished directory", ents)
		}
		if _, ok := e.nvram(fwTestVM); ok || e.hasSwtpm() {
			t.Error("a source is still in place after the quarantine")
		}
	})

	t.Run("durable", func(t *testing.T) {
		e := newFWEnv(t, fwState{name: "none"}, golibvirt.DomainShutoff)
		stage, final := dirs(e)
		defer func(s func(string) error) { quarantineSync = s }(quarantineSync)
		var synced []string
		quarantineSync = func(p string) error {
			synced = append(synced, p)
			return fsyncPath(p)
		}
		if err := e.store.QuarantineLeftoverFirmwareState(fwTestVM, fwTestUUID, stage, final, reason); err != nil {
			t.Fatal(err)
		}
		whole(t, final, true)
		i := slices.Index(synced, filepath.Join(stage, "reason.txt.tmp"))
		if i < 0 {
			t.Fatalf("reason.txt never fsynced (synced %v)", synced)
		}
		if !slices.Contains(synced[i+1:], stage) {
			t.Errorf("the stage was not fsynced after reason.txt (synced %v)", synced)
		}
		if synced[len(synced)-1] != filepath.Dir(final) {
			t.Errorf("the final name was not made durable last (synced %v)", synced)
		}
	})

	t.Run("no_uuid", func(t *testing.T) {
		e := newFWEnv(t, fwState{name: "none"}, golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine")
		final := filepath.Join(q, "vm1-reconciled-100")
		if err := e.store.QuarantineLeftoverFirmwareState(fwTestVM, "", filepath.Join(q, "vm1-reconciling-nouuid"), final, reason); err != nil {
			t.Fatal(err)
		}
		whole(t, final, false)
		if !e.hasSwtpm() {
			t.Error("a swtpm tree no uuid ties to the domain was moved")
		}
	})

	t.Run("refused_under_record", func(t *testing.T) {
		e := newFWEnv(t, fwHold("prepared"), golibvirt.DomainShutoff)
		stage, final := dirs(e)
		if err := e.store.QuarantineLeftoverFirmwareState(fwTestVM, fwTestUUID, stage, final, reason); err == nil {
			t.Fatal("quarantined under a hold")
		}
		if _, ok := e.nvram(fwTestVM); !ok || !e.hasSwtpm() {
			t.Error("state moved under a hold")
		}
	})
}

// D2-18 re-review 4, m-2: a stage of the VM's firmware state (an unfinished
// quarantine, an interrupted restore) refuses whatever would boot or redefine
// the VM on blank firmware state, and allows what finishes or restores it.
//
// Mutation: let a staged record allow OpStart — red.
func TestFirmwareMoveGuard_StagedRefusesBoot(t *testing.T) {
	staged := FirmwareMoveRecord{Kind: FirmwareStaged, VM: fwTestVM, UUID: fwTestUUID, State: "reconciling", Path: "/q/vm1-reconciling-x"}
	g := NewFirmwareMoveGuard(func(string, string) ([]FirmwareMoveRecord, error) { return []FirmwareMoveRecord{staged}, nil })
	for op, allow := range map[FirmwareOp]bool{OpStart: false, OpResume: false, OpDefine: false,
		OpStop: true, OpUndefine: true, OpWipe: true, OpWriteState: true} {
		err := g.check(FirmwareCall{Op: op, Name: fwTestVM, UUID: fwTestUUID})
		if (err == nil) != allow {
			t.Errorf("%s under a stage: %v, want allowed=%v", op, err, allow)
		}
		if err != nil && !strings.Contains(err.Error(), "blank firmware state") {
			t.Errorf("%s refusal does not say why: %v", op, err)
		}
	}
}

// D2-18 re-review 4, I-1/m-2: a quarantine is put back as the VM's own state;
// what was in place is set aside whole first, and a restore stopped after the
// set-aside finishes on a rerun without setting aside what it already moved
// back. FinishOrphanedStage renames a stage whole with its reason.
//
// Mutations: skip the set-aside — red (replaced); set aside again on a rerun
// — red (rerun).
func TestRestoreFirmwareQuarantine(t *testing.T) {
	setup := func(t *testing.T) (*fwEnv, string, string) {
		e := newFWEnv(t, fwState{name: "none"}, golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine")
		from := filepath.Join(q, "vm1-reconciled-100")
		fwWriteFile(t, filepath.Join(from, "nvram"), "NEWER")
		fwWriteFile(t, filepath.Join(from, "swtpm", "tpm2", "tpm2-00.permall"), "NEWERP")
		fwWriteFile(t, filepath.Join(from, "reason.txt"), "x")
		return e, q, from
	}
	permall := func(e *fwEnv) string {
		b, _ := os.ReadFile(filepath.Join(e.store.SwtpmDir(fwTestUUID), "tpm2", "tpm2-00.permall"))
		return string(b)
	}
	t.Run("replaced", func(t *testing.T) {
		e, q, from := setup(t)
		restoring, stage, final := filepath.Join(q, "vm1-restoring-"+fwTestUUID), filepath.Join(q, "vm1-reconciling-"+fwTestUUID), filepath.Join(q, "vm1-reconciled-200")
		if err := e.store.RestoreFirmwareQuarantine(fwTestVM, fwTestUUID, from, restoring, stage, final, []byte("r")); err != nil {
			t.Fatal(err)
		}
		if b, _ := e.nvram(fwTestVM); b != "NEWER" || permall(e) != "NEWERP" {
			t.Errorf("restored nvram %q permall %q", b, permall(e))
		}
		if b, _ := os.ReadFile(filepath.Join(final, "nvram")); string(b) != "T0" {
			t.Errorf("the replaced NVRAM is not set aside: %q", b)
		}
		if b, _ := os.ReadFile(filepath.Join(final, "swtpm", "tpm2", "tpm2-00.permall")); string(b) != "P0" {
			t.Errorf("the replaced TPM state is not set aside: %q", b)
		}
		for _, p := range []string{from, restoring, stage} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Errorf("%s left behind (%v)", p, err)
			}
		}
	})
	t.Run("rerun", func(t *testing.T) {
		e, q, from := setup(t)
		restoring, stage, final := filepath.Join(q, "vm1-restoring-"+fwTestUUID), filepath.Join(q, "vm1-reconciling-"+fwTestUUID), filepath.Join(q, "vm1-reconciled-200")
		defer func(r func(string, string) error) { quarantineRename = r }(quarantineRename)
		quarantineRename = func(o, n string) error {
			if o == filepath.Join(restoring, "swtpm") {
				return errors.New("injected crash after the NVRAM went back")
			}
			return os.Rename(o, n)
		}
		if err := e.store.RestoreFirmwareQuarantine(fwTestVM, fwTestUUID, from, restoring, stage, final, []byte("r")); err == nil {
			t.Fatal("a stopped restore reported success")
		}
		quarantineRename = os.Rename
		// As a cross-filesystem move a crash interrupted leaves it: the
		// NVRAM is in place and its source not yet removed.
		fwWriteFile(t, filepath.Join(restoring, "nvram"), "NEWER")
		if err := e.store.RestoreFirmwareQuarantine(fwTestVM, fwTestUUID, restoring, restoring, stage, filepath.Join(q, "vm1-reconciled-300"), []byte("r")); err != nil {
			t.Fatal(err)
		}
		if b, _ := e.nvram(fwTestVM); b != "NEWER" || permall(e) != "NEWERP" {
			t.Errorf("restored nvram %q permall %q", b, permall(e))
		}
		if _, err := os.Lstat(filepath.Join(q, "vm1-reconciled-300")); !os.IsNotExist(err) {
			t.Errorf("the rerun set aside state the restore had already put back (%v)", err)
		}
	})
	// D2-18 verify, m-C: a swtpm tree restored across filesystems is
	// recreated 0700; the per-uuid directory is made 0711 so swtpm can
	// traverse it. Mutation: drop the chmod — red.
	t.Run("cross_fs_swtpm_mode", func(t *testing.T) {
		e, q, from := setup(t)
		restoring, stage, final := filepath.Join(q, "vm1-restoring-"+fwTestUUID), filepath.Join(q, "vm1-reconciling-"+fwTestUUID), filepath.Join(q, "vm1-reconciled-200")
		defer func(r func(string, string) error) { quarantineRename = r }(quarantineRename)
		quarantineRename = func(o, n string) error {
			if o == filepath.Join(restoring, "swtpm") {
				return &os.LinkError{Op: "rename", Old: o, New: n, Err: syscall.EXDEV}
			}
			return os.Rename(o, n)
		}
		if err := e.store.RestoreFirmwareQuarantine(fwTestVM, fwTestUUID, from, restoring, stage, final, []byte("r")); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(e.store.SwtpmDir(fwTestUUID))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o711 {
			t.Fatalf("restored swtpm dir mode %v, want 0711", fi.Mode().Perm())
		}
		if permall(e) != "NEWERP" {
			t.Errorf("restored permall %q", permall(e))
		}
	})
	t.Run("finish_orphaned_stage", func(t *testing.T) {
		e, q, _ := setup(t)
		stage := filepath.Join(q, "vm1-reconciling-"+fwTestUUID)
		fwWriteFile(t, filepath.Join(stage, "nvram"), "T0")
		final := filepath.Join(q, "vm1-reconciled-400")
		if err := e.store.FinishOrphanedStage(stage, final, []byte("orphaned")); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(final, "nvram")); string(b) != "T0" {
			t.Errorf("finished nvram %q", b)
		}
		if b, _ := os.ReadFile(filepath.Join(final, "reason.txt")); string(b) != "orphaned" {
			t.Errorf("reason %q", b)
		}
	})
}
