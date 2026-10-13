package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// imageSkewHistoryFile, under the data directory, holds the clock skews this
// host has seen (imageSkewHistory). It is this host's own: nothing replicates
// it.
const imageSkewHistoryFile = "image-delete-skew.json"

// imageSkewHistoryMax bounds the history. Past it the two oldest entries are
// merged into one that covers both (the larger skew, the later time).
const imageSkewHistoryMax = 32

// imageSkewRecordInterval is how often RunImageSkewRecorder reads the
// clock_skew rows: well within corrosion.ClockSkewRetention, so every row is
// read before it ages out.
const imageSkewRecordInterval = 10 * time.Minute

// skewSeen is a clock skew, and the latest time it was measured.
type skewSeen struct {
	Skew time.Duration `json:"skew_ns"`
	Seen time.Time     `json:"seen"`
}

// imageSkewHistory is the clock skews over imageDeleteMarginFloor this host
// has read from clock_skew rows (re-review 2, m-2), kept after the rows age
// out (corrosion.ClockSkewRetention, 1 hour) — in memory, and in
// imageSkewHistoryFile when the server has a data directory, so a restart
// keeps it. Only the entries no other entry covers are kept: one with a skew
// at least as large, seen at least as late.
type imageSkewHistory struct {
	mu     sync.Mutex
	loaded bool
	seen   []skewSeen
}

// load reads the history file, until a read succeeds. A file that cannot be
// read is an error: the prune then keeps every deleted image's file the
// history decides on, until the file is readable or removed.
func (h *imageSkewHistory) load(dataDir string) error {
	if h.loaded || dataDir == "" {
		return nil
	}
	path := filepath.Join(dataDir, imageSkewHistoryFile)
	b, err := os.ReadFile(path)
	var seen []skewSeen
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("%s: %w", path, err)
	default:
		if err := json.Unmarshal(b, &seen); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	for _, e := range seen {
		h.add(e)
	}
	h.loaded = true
	return nil
}

// add merges e in, reporting whether the history changed.
func (h *imageSkewHistory) add(e skewSeen) bool {
	for _, o := range h.seen {
		if o.Skew >= e.Skew && !o.Seen.Before(e.Seen) {
			return false
		}
	}
	h.seen = slices.DeleteFunc(h.seen, func(o skewSeen) bool {
		return e.Skew >= o.Skew && !e.Seen.Before(o.Seen)
	})
	h.seen = append(h.seen, e)
	slices.SortFunc(h.seen, func(a, b skewSeen) int { return a.Seen.Compare(b.Seen) })
	for len(h.seen) > imageSkewHistoryMax {
		// The oldest has the larger skew (no entry covers another).
		h.seen[1] = skewSeen{Skew: max(h.seen[0].Skew, h.seen[1].Skew), Seen: h.seen[1].Seen}
		h.seen = h.seen[1:]
	}
	return true
}

// save writes the history to its file, replacing it whole.
func (h *imageSkewHistory) save(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	b, err := json.Marshal(h.seen)
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, imageSkewHistoryFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// recordImageSkew reads every clock_skew row this host holds into the history
// and returns the largest skew among them (0 when there is none, or the rows
// cannot be read).
func (s *Server) recordImageSkew(ctx context.Context) time.Duration {
	rows, err := s.db.Query(ctx, `SELECT ABS(skew_seconds) AS s, updated_at FROM clock_skew`)
	if err != nil {
		return 0
	}
	var largest time.Duration
	var seen []skewSeen
	for _, r := range rows {
		sk := time.Duration(r.Float("s") * float64(time.Second))
		largest = max(largest, sk)
		if sk <= imageDeleteMarginFloor {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, r.String("updated_at"))
		if perr != nil {
			at = time.Now() // measured no later than now
		}
		seen = append(seen, skewSeen{Skew: sk, Seen: at.UTC()})
	}
	h := &s.imagePrune.skew
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.load(s.dataDir) != nil {
		return largest
	}
	changed := false
	for _, e := range seen {
		changed = h.add(e) || changed
	}
	if changed {
		if err := h.save(s.dataDir); err != nil {
			slog.Warn("image: the clock skews this host has seen are not saved; a restart forgets them", "error", err)
		}
	}
	return largest
}

// RunImageSkewRecorder reads the clock_skew rows into the history at once and
// every imageSkewRecordInterval, so a skew is remembered after its rows age
// out even when no prune runs while they are held.
func (s *Server) RunImageSkewRecorder(ctx context.Context) {
	t := time.NewTicker(imageSkewRecordInterval)
	defer t.Stop()
	for {
		s.recordImageSkew(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// imageDeleteMargin is how far apart the clock of the host that deleted an
// image at deletedAt and this host's may have been: the largest of
//   - imageDeleteMarginFloor;
//   - every skew in a clock_skew row this host holds now, however old the row
//     (review re-review 1, R-m3);
//   - every skew in the history that was measured no earlier than
//     corrosion.ClockSkewRetention plus that skew before deletedAt (re-review
//     2, m-2). Rows age out after ClockSkewRetention; the history keeps them,
//     so the margin of a delete does not shrink once they have.
//
// A skew counts toward keeping a file only: a larger margin keeps more. A
// history that cannot be read is an error, and the prune keeps the file.
func (s *Server) imageDeleteMargin(ctx context.Context, deletedAt string) (time.Duration, error) {
	m := imageDeleteMarginFloor
	if d := s.imagePrune.deleteMargin.Load(); d > 0 {
		m = time.Duration(d)
	}
	m = max(m, s.recordImageSkew(ctx))
	h := &s.imagePrune.skew
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.load(s.dataDir); err != nil {
		return 0, err
	}
	del, err := time.Parse(time.RFC3339Nano, deletedAt)
	for _, e := range h.seen {
		if err != nil || !e.Seen.Before(del.Add(-corrosion.ClockSkewRetention-e.Skew)) {
			m = max(m, e.Skew)
		}
	}
	return m, nil
}
