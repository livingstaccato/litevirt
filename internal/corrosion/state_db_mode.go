package corrosion

import (
	"errors"
	"io/fs"
	"log/slog"

	"github.com/litevirt/litevirt/internal/diskmode"
)

// The cluster database, state.db, holds every credential the cluster has —
// password hashes, API tokens, the credential tables — so it is the owner's
// (root's, the daemon's) alone: diskmode.File, 0600. Nothing else opens it:
// the commands that open it locally (`lv user reset-admin`, the `lv sg ls`
// fallback when the daemon cannot answer, `litevirt schema-migrate`) run as
// root, as the daemon does, and could not open it as another user before
// either — a WAL reader needs write access to state.db-shm.

// prepareStateDBFile is called before the database at path is opened.
//
// A new database is made here, empty and 0600, before SQLite opens it: SQLite
// would make it 0644 less the umask, and it makes the -wal and -shm files
// beside it with the database's own mode, so all three come out 0600.
//
// An existing database is narrowed in place to 0600, with its -wal, -shm and
// -journal if they exist (they hold the same rows). This is the one exception
// to "no backfill" (internal/diskmode): every earlier build made state.db
// 0644, readable by any local user, and it is the file whose content is the
// credentials. Only these files are touched. Best effort: a narrowing that
// fails is logged and the open goes on, as it did on main; the daemon never
// fails to start over it.
func prepareStateDBFile(path string) {
	err := diskmode.Create(path)
	switch {
	case err == nil:
		return
	case !errors.Is(err, fs.ErrExist):
		// Let SQLite open (and report) it as it always has.
		slog.Warn("state.db: could not make the new database owner-only before opening it",
			"path", path, "error", err)
		return
	}
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := diskmode.Narrow(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("state.db: could not narrow the cluster database to its owner; it keeps its mode, readable by other local users",
				"path", p, "error", err)
		}
	}
}
