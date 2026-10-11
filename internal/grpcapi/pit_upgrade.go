package grpcapi

import (
	"context"
	"fmt"
	"io/fs"
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

// pitOverlayFiles lists every point-in-time overlay (not a set-aside
// .orphan-* copy, not a binding) in a directory that holds this host's VM
// disks: <data_dir>/disks, every storage pool of this host, and the
// directory of every disk recorded on this host.
func (s *Server) pitOverlayFiles(ctx context.Context) []string {
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
	seen := map[string]bool{}
	for dir := range dirs {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			n := d.Name()
			if !d.IsDir() && strings.HasPrefix(n, ".") && strings.HasSuffix(n, pitoverlay.Suffix) {
				seen[p] = true
			}
			return nil
		})
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// pitOverlayDowngradeRefusal refuses swapping in binary bin while any
// point-in-time overlay exists on this host and bin does not declare the
// pit_overlay release feature (a build older than release_2026_11_v1, which
// would start a VM on its bare disk and drop the overlay's writes). An upgrade
// to a build that knows pit_overlay, or a host with no overlay, is never
// refused. bin is run only when an overlay exists.
func (s *Server) pitOverlayDowngradeRefusal(ctx context.Context, bin string) error {
	files := s.pitOverlayFiles(ctx)
	if len(files) == 0 {
		return nil
	}
	if feats, err := releaseFeaturesOf(ctx, bin); err == nil && slices.Contains(feats, string(capabilities.FeaturePITOverlay)) {
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
