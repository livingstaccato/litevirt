package pbsstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// ManifestsFor returns the manifests of one (vm, disk) — snapshots/<vm>/
// *-<disk>.manifest.json only, not the whole repo — sorted by timestamp. A
// structurally invalid manifest is skipped, as ListManifests does; one that
// cannot be read or parsed is an error, since the caller cannot then say
// what the repo holds. ctx is checked before every file, so an abandoned
// caller stops the walk.
func (r *Repo) ManifestsFor(ctx context.Context, vm, disk string) ([]Manifest, error) {
	if err := safename.ValidateVMName(vm); err != nil {
		return nil, err
	}
	if err := safename.ValidateDiskName(disk); err != nil {
		return nil, err
	}
	dir := filepath.Join(r.root, "snapshots", vm)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	suffix := "-" + disk + ".manifest.json"
	var out []Manifest
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if ValidateManifest(&m) != nil || m.VMName != vm || m.DiskName != disk {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
	return out, nil
}
