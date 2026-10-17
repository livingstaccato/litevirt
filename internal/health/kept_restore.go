package health

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

// KeptName is where a create moves a file a deleted VM of its name was kept
// with, at path, at time at: <path>.kept-<time>. Nothing removes it but an
// operator.
func KeptName(path string, at time.Time) string { return keptName(path, at) }

// KeptBack is one disk RestoreKeptAfterFailedCreate dealt with: Path is the
// path its VM recorded, From its .kept- name. Err is nil when the disk is at
// Path again; otherwise it says why the disk stays at From.
type KeptBack struct {
	Path, From string
	Err        error
}

// RestoreKeptAfterFailedCreate puts back the disks a create of VM name moved
// off their paths (SetAsideBeforeCreate's Moved) when that create then
// failed: each disk a delete kept is at the path its VM recorded again, and
// this host's note lists it again, so the next create of the name moves it as
// the failed one did.
//
// Nothing is replaced: the disk is linked back, and a link fails on a path
// that holds a file — a disk the failed create could not remove, or one a
// concurrent create of the name made. That disk then stays at its .kept-
// name, where nothing removes it. The note is written before the link, so a
// disk back at its path is never one a create would clear as debris.
//
// A real disk a failover left, set aside for the retention (.superseded-),
// is not put back: its record no longer lists it at the path, and a create
// would clear it there.
func RestoreKeptAfterFailedCreate(dataDir, name string, moved []MovedBeforeCreate) []KeptBack {
	var out []KeptBack
	for _, m := range moved {
		if !m.Kept {
			continue
		}
		p := filepath.Clean(m.Path)
		back := KeptBack{Path: p, From: m.To}
		back.Err = restoreKept(dataDir, name, p, m.To)
		if back.Err != nil {
			slog.Warn("create failed: a disk a deleted VM of this name was kept with stays where the create moved it",
				"vm", name, "path", p, "kept_at", m.To, "error", back.Err)
		} else {
			slog.Info("create failed: moved a disk a deleted VM of this name was kept with back to its path",
				"vm", name, "path", p, "from", m.To)
		}
		out = append(out, back)
	}
	return out
}

func restoreKept(dataDir, name, path, from string) error {
	if _, err := lstatSetAside(path); err == nil {
		return fmt.Errorf("%s holds a file", path)
	} else if !notThere(err) {
		return fmt.Errorf("whether a file is at %s cannot be told: %w", path, err)
	}
	if err := NoteKeptDisks(dataDir, name, []string{path}); err != nil {
		return fmt.Errorf("note %s as kept: %w", path, err)
	}
	if err := linkSetAside(from, path); err != nil {
		if storage.IsFSNoAnswer(err) {
			// The link may still land: the note stays, so a disk that
			// appears at the path is never cleared as debris.
			return fmt.Errorf("link it back: %w (the link may still land, as a second name of %s)", err, from)
		}
		if ferr := forgetKeptDisks(dataDir, name, []string{path}); ferr != nil {
			slog.Warn("create failed: could not drop a note of a kept disk that was not put back", "vm", name, "path", path, "error", ferr)
		}
		return fmt.Errorf("link it back: %w", err)
	}
	if err := removeSetAside(from); err != nil {
		slog.Warn("create failed: a kept disk is back at its path, and its .kept- name could not be removed (a second name of the same file)",
			"vm", name, "path", path, "kept_at", from, "error", err)
	}
	return nil
}
