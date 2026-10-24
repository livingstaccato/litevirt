package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The source reads a disk through its directory held open beneath the disk
// root, with no link followed and O_NOFOLLOW on the file, so a name swapped for
// a link between its checks and its read cannot make it send another file.
//
// Red before the held directory (a path-based os.Open followed both swaps).
// Mutations: read through hostDiskFile(path) again - both tests go red; drop
// O_NOFOLLOW from the final open - the file-swap test goes red.

func newSourceReadScenario(t *testing.T) (*foreignPoolScenario, string) {
	t.Helper()
	fp := newForeignPoolScenario(t,
		func(pool, _ string) string { return filepath.Join(pool, "sub", "x.qcow2") },
		func(pool, _ string) string { return pool })
	secret := filepath.Join(fp.c.tmpRoot, "secret-outside")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "x.qcow2"), []byte("SECRET-NOT-THE-DISK"), 0o600); err != nil {
		t.Fatal(err)
	}
	return fp, secret
}

func srcFS(fp *foreignPoolScenario, p string) string {
	return filepath.Join(fp.c.tmpRoot, "fs-"+fp.src.Name, p)
}

func TestFleet_ColdMigrationSourceDoesNotReadALinkSwappedInAsTheDisk(t *testing.T) {
	fp, secret := newSourceReadScenario(t)
	file := srcFS(fp, fp.disk)
	fp.src.Server.SetColdSourceReadHookForTest(func() {
		_ = os.Remove(file)
		if err := os.Symlink(filepath.Join(secret, "x.qcow2"), file); err != nil {
			t.Errorf("swap: %v", err)
		}
	})
	err := fp.migrate()
	if err == nil {
		t.Errorf("migrate --cold read a link swapped in as the disk")
	}
	if got, rerr := os.ReadFile(fp.targetFile(fp.disk)); rerr == nil {
		t.Errorf("the target holds %q after the disk was swapped for a link", got)
	}
}

func TestFleet_ColdMigrationSourceReadsTheDirectoryItJudgedNotOneSwappedInForIt(t *testing.T) {
	fp, secret := newSourceReadScenario(t)
	sub := srcFS(fp, filepath.Join(fp.pool, "sub"))
	fp.src.Server.SetColdSourceReadHookForTest(func() {
		if err := os.Rename(sub, sub+".judged"); err != nil {
			t.Errorf("swap: %v", err)
			return
		}
		if err := os.Symlink(secret, sub); err != nil {
			t.Errorf("swap: %v", err)
		}
	})
	_ = fp.migrate()
	got, err := os.ReadFile(fp.targetFile(fp.disk))
	if err != nil {
		t.Fatalf("the disk did not arrive: %v", err)
	}
	if strings.Contains(string(got), "SECRET") || string(got) != string(fp.payload) {
		t.Fatalf("the source sent %d bytes that are not the disk it judged (secret leaked: %v)", len(got), strings.Contains(string(got), "SECRET"))
	}
}
