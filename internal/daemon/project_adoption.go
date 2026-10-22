package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

// ProjectAdoptionFallback is how long after both a candidate's last write
// and this node's first-latched time a host that is not the project's
// preferred adopter adopts it anyway (a dead or stuck holder). Adopters write
// identical statements, so this only bounds write volume, not correctness.
const ProjectAdoptionFallback = 2 * time.Hour

// projectAdoptionFirstLatchedFile is this node's first-latched time: when its
// first pass after the latch found a project waiting for another host.
// Written once (O_EXCL) and not rewritten while it holds a time no later than
// now, so a restart, or a marker rewrite, cannot restart the fallback clock
// (re-review M-3); firstLatchedAt replaces one it cannot read (review m-F).
const projectAdoptionFirstLatchedFile = "project-adoption-first-latched"

// ProjectAdoptionPass is one run of this host's project adoption
// (corrosion/project_adoption.go). The order is the rollback contract
// (re-review I-2): read the candidates; stop if there are none, or if
// Enabled is false; stop if the release token has not latched here; only
// then ask Gate, which records the feature's use before the first write. So
// a cluster with nothing to adopt, or with the flag off, records no use and
// keeps its rollback below release_2027_01_v1.
type ProjectAdoptionPass struct {
	DB   *corrosion.Client
	Host string
	// Enabled is enforcement.project_adoption.
	Enabled func() bool
	// Available reports that the feature's release token has durably
	// latched here (health.Checker.FeatureAvailable); it records nothing.
	Available func() bool
	// Gate is health.Checker.WithFeature.
	Gate func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error
	// DataDir holds projectAdoptionFirstLatchedFile.
	DataDir string
	Now     func() time.Time
}

// Run runs the pass once and returns how many projects it adopted.
func (p ProjectAdoptionPass) Run(ctx context.Context) (int, error) {
	scan, err := corrosion.ScanProjectAdoption(ctx, p.DB)
	if err != nil {
		return 0, err
	}
	metrics.ProjectAdoptionBlocked("spellings", len(scan.BlockedSpellings))
	for _, canon := range scan.BlockedSpellings {
		slog.Warn("project adoption: more than one spelling of the project is live, so it keeps the pre-latch incarnation; see `lv doctor project-spellings`",
			"project", canon)
	}
	// project_incarnation_v1 must have latched here too (design §3): an
	// adopted incarnation is never written while this host still writes the
	// pre-latch forms.
	if len(scan.Candidates) == 0 || !p.Enabled() || !p.Available() || !p.DB.ProjectIncarnationOn() {
		return 0, nil
	}
	now := p.now()
	hosts, err := corrosion.ListHosts(ctx, p.DB)
	if err != nil {
		return 0, err
	}
	var todo []string
	var since *time.Time
	var clockErr error
	skipped := 0
	for _, cand := range scan.Candidates {
		preferred, err := p.preferred(ctx, cand.Name, hosts)
		if err != nil {
			return 0, err
		}
		if preferred {
			todo = append(todo, cand.Name)
			continue
		}
		// Read only for a host that is not the preferred adopter, so the
		// holder never depends on the file. An error on it (a read-only data
		// dir, a full disk) holds off only these fallback candidates (review
		// N-2): logged once per pass and counted, never the whole pass.
		if since == nil && clockErr == nil {
			t, err := firstLatchedAt(p.DataDir, now)
			if err != nil {
				clockErr = err
				slog.Warn("project adoption: the fallback clock is unreadable, so this host adopts only the projects it holds this pass",
					"error", err)
			} else {
				since = &t
			}
		}
		if clockErr != nil {
			skipped++
			continue
		}
		if projectAdoptionOverdue(cand.UpdatedAt, *since, now) {
			todo = append(todo, cand.Name)
		}
	}
	metrics.ProjectAdoptionBlocked("fallback_clock", skipped)
	if len(todo) == 0 {
		return 0, nil
	}
	adopted := 0
	err = p.Gate(ctx, capabilities.FeatureProjectAdoption, func(ctx context.Context, g capabilities.FeatureGrant) error {
		var errs []error
		failed := 0
		for _, name := range todo {
			ok, err := corrosion.AdoptProjectIncarnation(ctx, p.DB, g, name)
			if err != nil {
				failed++
				slog.Warn("project adoption: transaction failed; retrying on the next pass", "project", name, "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			if ok {
				adopted++
				slog.Info("project adoption: the project created before project_incarnation_v1 has its stable incarnation", "project", name)
			}
		}
		metrics.ProjectAdoptionBlocked("write_error", failed)
		return errors.Join(errs...)
	})
	return adopted, err
}

func (p ProjectAdoptionPass) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// preferred reports whether this host is name's preferred adopter: its
// current authority holder, or, with no authority row, the host
// DeterministicAuthorityCandidate would mint.
func (p ProjectAdoptionPass) preferred(ctx context.Context, name string, hosts []corrosion.HostRecord) (bool, error) {
	a, ok, err := corrosion.CurrentProjectAuthority(ctx, p.DB, name)
	if err != nil {
		return false, err
	}
	if ok {
		return a.Holder == p.Host, nil
	}
	h, ok := corrosion.DeterministicAuthorityCandidate(hosts, name)
	return ok && h == p.Host, nil
}

// projectAdoptionOverdue: a non-preferred host adopts once both the row's last
// write and this node's first-latched time are ProjectAdoptionFallback
// old. Both are durable, so neither a restart nor a crash loop resets them.
//
// A backward clock step can shorten the wait (review N-1, accepted): an
// early fallback adoption is harmless, because adoption is idempotent and
// every adopter writes the identical statement.
func projectAdoptionOverdue(updatedAt string, since, now time.Time) bool {
	from := since
	if u, ok := corrosion.ParseUpdatedAt(updatedAt); ok && u.After(from) {
		from = u
	}
	return now.Sub(from) >= ProjectAdoptionFallback
}

// firstLatchedAt reads this node's first-latched time, writing now the first
// time it is asked. The file is created with O_EXCL and not rewritten while it
// holds a time no later than now. A file that does not hold one — empty or
// garbled after a crash or a full disk between its create and its write, or a
// time in the future, written while the clock was ahead — is replaced with
// now (review m-F): the fallback clock restarts, which only delays a
// non-holder's adoption, and never wedges the pass.
func firstLatchedAt(dir string, now time.Time) (time.Time, error) {
	path := filepath.Join(dir, projectAdoptionFirstLatchedFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		t, perr := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
		if perr == nil && !t.After(now) {
			return t, nil
		}
		slog.Warn("project adoption: the first-latched time is unreadable or in the future; restarting the fallback clock",
			"file", path, "content", strings.TrimSpace(string(b)))
		return now, replaceFirstLatched(path, now)
	case !os.IsNotExist(err):
		return time.Time{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return firstLatchedAt(dir, now)
		}
		return time.Time{}, err
	}
	if err := writeFirstLatched(f, now); err != nil {
		return time.Time{}, err
	}
	return now, syncDir(dir)
}

// replaceFirstLatched writes now to a temporary file and renames it over path.
func replaceFirstLatched(path string, now time.Time) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := writeFirstLatched(f, now); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeFirstLatched writes now, syncs and closes f.
func writeFirstLatched(f *os.File, now time.Time) error {
	if _, err := f.WriteString(now.UTC().Format(time.RFC3339Nano) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// projectAdoptionInterval is how often the daemon runs its pass, and
// projectAdoptionPoll how often it looks for the release latch before the
// first one. Vars so tests can shrink them.
var (
	projectAdoptionInterval = time.Hour
	projectAdoptionPoll     = time.Minute
	// projectAdoptionFirstJitter bounds the extra wait before the first pass.
	projectAdoptionFirstJitter = time.Minute
)

// startProjectAdoption runs the pass in its own goroutine: once, with jitter,
// as soon as the feature's release token has latched here, and hourly after.
func (d *Daemon) startProjectAdoption(ctx context.Context) {
	p := ProjectAdoptionPass{
		DB:        d.db,
		Host:      d.cfg.HostName,
		Enabled:   func() bool { return d.cfg.Enforcement.ProjectAdoption },
		Available: func() bool { return d.checker.FeatureAvailable(capabilities.FeatureProjectAdoption) },
		Gate:      d.checker.WithFeature,
		DataDir:   d.cfg.DataDir,
	}
	go func() {
		wait := projectAdoptionPoll
		first := true
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			if !p.Available() {
				wait = projectAdoptionPoll
				continue
			}
			if first {
				// The first pass after the latch waits 0-60s more, so the
				// hosts that saw the latch together do not all adopt at once.
				first = false
				wait = time.Duration(rand.Int63n(int64(projectAdoptionFirstJitter) + 1))
				continue
			}
			if n, err := p.Run(ctx); err != nil {
				slog.Warn("project adoption pass", "error", err)
			} else if n > 0 {
				slog.Info("project adoption pass", "adopted", n)
			}
			wait = projectAdoptionInterval + time.Duration(rand.Int63n(int64(time.Minute)))
		}
	}()
}
