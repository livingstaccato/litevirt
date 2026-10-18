package libvirt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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
