package libvirt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// recordDirSyncs replaces the directory fsync of ReadFirmwareBundle with a
// recorder; fail, when it returns an error for a path, makes that fsync fail.
func recordDirSyncs(t *testing.T, fail func(string) error) *[]string {
	t.Helper()
	var calls []string
	old := fsyncDir
	fsyncDir = func(p string) error {
		calls = append(calls, p)
		if fail != nil {
			return fail(p)
		}
		return nil
	}
	t.Cleanup(func() { fsyncDir = old })
	return &calls
}

func bundleOf(t *testing.T, nvram, tpm bool) *bytes.Buffer {
	t.Helper()
	src := t.TempDir()
	seedFirmware(t, src, "src", "uuid-s", nvram, tpm)
	var buf bytes.Buffer
	if _, err := WriteFirmwareBundle(src, "src", "uuid-s", &buf); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// A restore is on disk once it returns: the staged swtpm tree's directories
// before it is renamed into place, the directory a new nvram dir was made in,
// and both directories the renames changed.
func TestReadFirmwareBundle_FsyncsEveryDirectoryItChanges(t *testing.T) {
	base := redirectSwtpmBase(t)
	buf := bundleOf(t, true, true)
	calls := recordDirSyncs(t, nil)
	dst := t.TempDir()
	if err := ReadFirmwareBundle(buf, dst, "dst", "uuid-d"); err != nil {
		t.Fatal(err)
	}
	nvramDir := filepath.Dir(NvramPath(dst, "dst"))
	for _, want := range []string{dst, nvramDir, base} {
		if !slices.Contains(*calls, want) {
			t.Errorf("no fsync of %s; calls %v", want, *calls)
		}
	}
	stagedTPM2 := slices.IndexFunc(*calls, func(p string) bool {
		return strings.Contains(p, ".swtpm-restore-") && filepath.Base(p) == "tpm2"
	})
	stageRoot := slices.IndexFunc(*calls, func(p string) bool {
		return strings.HasPrefix(filepath.Base(p), ".swtpm-restore-")
	})
	parent := slices.Index(*calls, base)
	if stagedTPM2 < 0 || stageRoot < 0 || !(stagedTPM2 < stageRoot && stageRoot < parent) {
		t.Fatalf("staged swtpm dirs not fsynced bottom-up before the rename: %v", *calls)
	}
}

// A rollback is made as durable as the restore it undoes: a failed fsync of
// the swtpm directory, after the nvram directory's succeeded, must not leave
// the new NVRAM on disk beside the old swtpm state.
func TestReadFirmwareBundle_RollbackIsFsynced(t *testing.T) {
	base := redirectSwtpmBase(t)
	buf := bundleOf(t, true, true)
	dst := t.TempDir()
	seedFirmware(t, dst, "dst", "uuid-d", true, true)
	if err := os.WriteFile(NvramPath(dst, "dst"), []byte("OLD-NVRAM"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := false
	calls := recordDirSyncs(t, func(p string) error {
		if p == base && !failed {
			failed = true
			return errors.New("EIO")
		}
		return nil
	})
	if err := ReadFirmwareBundle(buf, dst, "dst", "uuid-d"); err == nil {
		t.Fatal("restore succeeded although the swtpm directory fsync failed")
	}
	if got, _ := os.ReadFile(NvramPath(dst, "dst")); string(got) != "OLD-NVRAM" {
		t.Fatalf("nvram after the rollback = %q, want OLD-NVRAM", got)
	}
	nvramDir := filepath.Dir(NvramPath(dst, "dst"))
	at := slices.Index(*calls, base)
	if at < 0 || !slices.Contains((*calls)[at+1:], nvramDir) || !slices.Contains((*calls)[at+1:], base) {
		t.Fatalf("the rollback's renames were not fsynced: %v", *calls)
	}
}

// A backup left by an interrupted earlier restore holds the state from before
// it, and is the only copy of that state: a retry keeps it.
func TestReadFirmwareBundle_KeepsABackupLeftByAnEarlierAttempt(t *testing.T) {
	redirectSwtpmBase(t)
	buf := bundleOf(t, true, true)
	recordDirSyncs(t, nil)
	dst := t.TempDir()
	seedFirmware(t, dst, "dst", "uuid-d", true, true)
	nvBak := NvramPath(dst, "dst") + ".bak"
	if err := os.WriteFile(nvBak, []byte("ORIGINAL-NVRAM"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpmBak := LibvirtSwtpmDir("uuid-d") + ".bak"
	if err := os.MkdirAll(tpmBak, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpmBak, "marker"), []byte("ORIGINAL-TPM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadFirmwareBundle(buf, dst, "dst", "uuid-d"); err != nil {
		t.Fatal(err)
	}
	found := func(glob, want string) bool {
		m, _ := filepath.Glob(glob)
		for _, p := range m {
			if b, err := os.ReadFile(p); err == nil && string(b) == want {
				return true
			}
		}
		return false
	}
	if !found(nvBak+"*", "ORIGINAL-NVRAM") {
		t.Error("the earlier attempt's nvram backup was overwritten or removed")
	}
	if !found(tpmBak+"*/marker", "ORIGINAL-TPM") {
		t.Error("the earlier attempt's swtpm backup was overwritten or removed")
	}
}
