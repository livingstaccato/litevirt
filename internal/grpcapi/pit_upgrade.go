package grpcapi

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// ReleaseFeaturesFlag makes a litevirt binary print the release features it
// declares, as "litevirt release-features=<a,b,…>", and exit
// (cmd/litevirt/main.go). A binary that predates it fails or prints no such
// token: it knows none.
const ReleaseFeaturesFlag = "--release-features"

// ReleaseFeaturesLine is what `litevirt --release-features` prints.
func ReleaseFeaturesLine() string {
	fs := capabilities.Features()
	names := make([]string, len(fs))
	for i, f := range fs {
		names[i] = string(f)
	}
	return "litevirt release-features=" + strings.Join(names, ",")
}

// releaseFeaturesOf runs `<bin> --release-features` and returns the
// features it declares. A variable so a test can stand in for a binary.
var releaseFeaturesOf = func(ctx context.Context, bin string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, ReleaseFeaturesFlag).Output()
	if err != nil {
		return nil, err
	}
	for _, f := range strings.Fields(string(out)) {
		if v, ok := strings.CutPrefix(f, "release-features="); ok {
			return strings.Split(v, ","), nil
		}
	}
	return nil, fmt.Errorf("%s printed no release-features", bin)
}

// pitOverlayScanTimeout bounds the overlay scan of an upgrade: a hung NFS
// mount must not wedge `lv host upgrade`. walkForOverlays is the walk, a
// variable so a test can model a directory that never answers.
var (
	pitOverlayScanTimeout = 10 * time.Second
	walkForOverlays       = filepath.WalkDir
)

// pitOverlayUsed reports whether this host's replica holds a used record of
// pit_overlay. Before one exists no overlay can, and the upgrade paths do
// exactly what main does: no scan, no probe. A read error counts as used
// (the scan is bounded, and data safety wins once overlays may exist).
func (s *Server) pitOverlayUsed(ctx context.Context) bool {
	if s.db == nil {
		return false
	}
	used, err := corrosion.ReleaseFeatureUsed(ctx, s.db, featureToken(capabilities.FeaturePITOverlay), string(capabilities.FeaturePITOverlay))
	return err != nil || used
}

// pitOverlayScan lists every point-in-time overlay (not a set-aside
// .orphan-* copy, not a binding) in a directory that holds this host's VM
// disks: <data_dir>/disks, every storage pool of this host, and the
// directory of every disk recorded on this host. Each directory is walked on
// its own, all under one pitOverlayScanTimeout; one that has not finished by
// then (a hung mount) is returned in unanswered, and the caller fails closed.
func (s *Server) pitOverlayScan(ctx context.Context) (files, unanswered []string) {
	dirs := map[string]bool{}
	if s.dataDir != "" {
		dirs[filepath.Join(s.dataDir, "disks")] = true
	}
	if s.db != nil {
		if pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName); err == nil {
			for _, p := range pools {
				if filepath.IsAbs(p.Target) {
					dirs[p.Target] = true
				}
			}
		}
		if rows, err := s.db.Query(ctx, `SELECT path FROM vm_disks WHERE host_name = ? AND path != ''`, s.hostName); err == nil {
			for _, r := range rows {
				if p := s.hostDiskFile(r.String("path")); filepath.IsAbs(p) {
					dirs[filepath.Dir(p)] = true
				}
			}
		}
	}
	type result struct {
		dir   string
		found []string
	}
	results := make(chan result, len(dirs))
	for dir := range dirs {
		go func(dir string) {
			var found []string
			_ = walkForOverlays(dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				n := d.Name()
				if !d.IsDir() && strings.HasPrefix(n, ".") && strings.HasSuffix(n, pitoverlay.Suffix) {
					found = append(found, p)
				}
				return nil
			})
			results <- result{dir: dir, found: found}
		}(dir)
	}
	deadline := time.NewTimer(pitOverlayScanTimeout)
	defer deadline.Stop()
	done := map[string]bool{}
	seen := map[string]bool{}
collect:
	for len(done) < len(dirs) {
		select {
		case r := <-results:
			done[r.dir] = true
			for _, f := range r.found {
				seen[f] = true
			}
		case <-deadline.C:
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	for dir := range dirs {
		if !done[dir] {
			unanswered = append(unanswered, dir)
		}
	}
	for p := range seen {
		files = append(files, p)
	}
	slices.Sort(files)
	slices.Sort(unanswered)
	return files, unanswered
}

// pitOverlayDowngradeRefusal refuses swapping in binary bin when it does not
// declare the pit_overlay release feature (a build older than
// release_2026_11_v1, which would start a VM on its bare disk and drop an
// overlay's writes) while any overlay exists on this host, or while a
// directory that could hold one does not answer. Before pit_overlay has a
// used record here it does nothing (as main); after, the binary is asked
// first, so an upgrade to a build that knows pit_overlay never scans.
func (s *Server) pitOverlayDowngradeRefusal(ctx context.Context, bin string) error {
	if !s.pitOverlayUsed(ctx) {
		return nil
	}
	if feats, err := releaseFeaturesOf(ctx, bin); err == nil && slices.Contains(feats, string(capabilities.FeaturePITOverlay)) {
		return nil
	}
	files, unanswered := s.pitOverlayScan(ctx)
	if len(unanswered) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"refusing to install a binary that does not know point-in-time overlays (pit_overlay; older than %s): %s did not answer within %s, so this host cannot show it holds no overlay. "+
				"Fix the mount and retry, or pass --force",
			capabilities.ReleaseToken, strings.Join(unanswered, ", "), pitOverlayScanTimeout)
	}
	if len(files) == 0 {
		return nil
	}
	shown := files
	if len(shown) > 10 {
		shown = shown[:10]
	}
	more := ""
	if len(files) > len(shown) {
		more = fmt.Sprintf(" and %d more", len(files)-len(shown))
	}
	return status.Errorf(codes.FailedPrecondition,
		"refusing to install a binary that does not know point-in-time overlays (pit_overlay; older than %s) while %d overlay(s) exist on this host: %s%s. "+
			"Such a build would start the VM on its bare disk and drop the writes an overlay holds. Settle each first — start or replicate its VM on this build, "+
			"or resolve it with `lv resolve-pit-overlay <vm> <disk>` — or drain the host (`lv host drain`); --force overrides",
		capabilities.ReleaseToken, len(files), strings.Join(shown, ", "), more)
}

// checkPITOverlayDowngrade runs pitOverlayDowngradeRefusal for a swap. Under
// --force a refusal is not returned, but it is logged and audited, naming
// this host and the overlays the force skipped (N4 of the switch re-review).
func (s *Server) checkPITOverlayDowngrade(ctx context.Context, bin string, force bool) error {
	err := s.pitOverlayDowngradeRefusal(ctx, bin)
	if err == nil || !force {
		return err
	}
	msg := status.Convert(err).Message()
	slog.Warn("upgrade: --force installs a binary that does not know point-in-time overlays over this host's overlays", "host", s.hostName, "refusal", msg)
	s.audit(ctx, "host.upgrade.force_pit_overlay", s.hostName, "--force skipped: "+msg, "ok")
	return nil
}
