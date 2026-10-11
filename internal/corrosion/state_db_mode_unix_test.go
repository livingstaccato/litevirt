//go:build unix

package corrosion

import (
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/hlc"
)

func stateDBUmask022(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func stateDBPerm(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// stateDBFiles is the database and the two files SQLite keeps beside it in WAL
// mode while a connection is open.
func stateDBFiles(dir string) []string {
	db := filepath.Join(dir, "state.db")
	return []string{db, db + "-wal", db + "-shm"}
}

// The cluster database holds every credential the cluster has (password
// hashes, API tokens, the credential tables), so a new one, and the WAL and
// shared-memory files SQLite makes beside it, are the owner's alone. SQLite
// makes the database 0644 less the umask, and its -wal and -shm take the
// database's mode.
//
// Mutation: drop the 0600 create of a new state.db (prepareStateDBFile) — every
// file comes out 0644 and this goes red.
func TestStateDB_ANewDatabaseIsOwnerOnly(t *testing.T) {
	stateDBUmask022(t)
	dir := t.TempDir()
	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	defer c.Close()
	if _, err := c.db.Exec(`CREATE TABLE mode_probe (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	for _, p := range stateDBFiles(dir) {
		if got := stateDBPerm(t, p); got != 0o600 {
			t.Errorf("%s is %04o, want 0600", filepath.Base(p), got)
		}
	}
}

// A database an earlier build made 0644 is narrowed when it is opened: this
// one file is narrowed in place because it holds the credentials. Its WAL and
// shared-memory files, which hold the same rows, go with it. Nothing else in
// the data directory is touched (no backfill), and the data is all still there.
//
// Mutation: drop the narrowing of an existing state.db — the database and its
// -wal/-shm stay 0644 and this goes red. Narrow the whole directory instead —
// the unrelated file goes red.
func TestStateDB_AnExistingWiderDatabaseIsNarrowedWhenOpened(t *testing.T) {
	stateDBUmask022(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	old, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	old.SetMaxOpenConns(1)
	if _, err := old.Exec(`CREATE TABLE kept (x INTEGER); INSERT INTO kept VALUES (42)`); err != nil {
		t.Fatal(err)
	}
	for _, p := range stateDBFiles(dir) {
		if got := stateDBPerm(t, p); got != 0o644 {
			t.Fatalf("setup: %s is %04o, want the old 0644", filepath.Base(p), got)
		}
	}
	other := filepath.Join(dir, "not-the-database")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	defer c.Close()
	for _, p := range stateDBFiles(dir) {
		if got := stateDBPerm(t, p); got != 0o600 {
			t.Errorf("%s is %04o after the open, want 0600", filepath.Base(p), got)
		}
	}
	if got := stateDBPerm(t, other); got != 0o644 {
		t.Errorf("an unrelated file in the data directory was changed to %04o", got)
	}
	var x int
	if err := c.db.QueryRow(`SELECT x FROM kept`).Scan(&x); err != nil || x != 42 {
		t.Fatalf("the database's rows after the narrowing: x=%d err=%v", x, err)
	}
}

// A narrowing that fails — a filesystem that refuses chmod — never stops the
// database from opening: main opened it at 0644, and the daemon must start.
//
// Mutation: return the narrowing's error from NewLocalClient — this goes red.
func TestStateDB_ARefusedNarrowingStillOpens(t *testing.T) {
	stateDBUmask022(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	restore := diskmode.SetFchmodForTest(func(*os.File, fs.FileMode) error { return errors.New("chmod refused") })
	defer restore()
	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatalf("a refused chmod stopped the database from opening: %v", err)
	}
	defer c.Close()
	if _, err := c.db.Exec(`CREATE TABLE mode_probe (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
}

// The daemon opens the database through NewClient, so the narrowing happens at
// daemon start.
//
// Mutation: drop the call from NewClient — this goes red.
func TestStateDB_TheDaemonsOpenNarrowsAnExistingDatabase(t *testing.T) {
	stateDBUmask022(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(Config{HostName: "node-1", DataDir: dir, BindAddr: "127.0.0.1", BindPort: freePort(t)},
		hlc.NewClock("node-1"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	if got := stateDBPerm(t, path); got != 0o600 {
		t.Errorf("state.db is %04o after the daemon's open, want 0600", got)
	}
}
