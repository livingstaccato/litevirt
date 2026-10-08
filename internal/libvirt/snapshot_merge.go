package libvirt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// maxMergeWalk bounds the header walk from a disk's active layer to the base
// a merge commits into. It is far above the start's 16-layer cap on purpose:
// a chain that has already grown past the cap is exactly what a merge exists
// to collapse.
const maxMergeWalk = 256

// resolvedPath is p resolved through symlinks, or p cleaned when it cannot be.
func resolvedPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// layersAbove returns top and every layer of its qcow2 backing chain above
// base, top first, resolved. base must be reached; every layer is a qcow2
// file with no external data file, and none names a protocol backing.
func layersAbove(top, base string) ([]string, error) {
	want := resolvedPath(base)
	if err := qcow2.AssertNoExternalData(want); err != nil {
		return nil, fmt.Errorf("merge base %s: %w", base, err)
	}
	var out []string
	path := resolvedPath(top)
	for i := 0; i < maxMergeWalk; i++ {
		if path == want {
			if len(out) == 0 {
				return nil, fmt.Errorf("%s is the merge base itself", top)
			}
			return out, nil
		}
		if err := qcow2.AssertNoExternalData(path); err != nil {
			return nil, fmt.Errorf("layer %s: %w", path, err)
		}
		info, err := qcow2.Info(path)
		if err != nil {
			return nil, fmt.Errorf("layer %s: %w", path, err)
		}
		out = append(out, path)
		b := info.BackingFile
		if b == "" {
			return nil, fmt.Errorf("%s is not in the backing chain of %s", base, top)
		}
		c := strings.IndexByte(b, ':')
		if sl := strings.IndexByte(b, '/'); c >= 0 && (sl < 0 || c < sl) {
			return nil, fmt.Errorf("layer %s names a protocol backing %q", path, b)
		}
		if !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(path), b)
		}
		path = resolvedPath(b)
	}
	return nil, fmt.Errorf("%s is not within %d layers of %s", base, maxMergeWalk, top)
}

// commitLayersOffline commits top, and every layer between it and base, into
// base with qemu-img (the VM is not running; nothing holds the files). It
// returns the layers above base — every one of them now unused by this
// chain — for the caller to remove once the domain names base. Nothing is
// written when base is not in top's chain.
func commitLayersOffline(top, base string) ([]string, error) {
	above, err := layersAbove(top, base)
	if err != nil {
		return nil, err
	}
	// -b commits down to base (every layer between included) and leaves the
	// layers as they were: the data is in base, and top over base still
	// reads the same until the domain is repointed.
	cmd := exec.Command("qemu-img", "commit", "-q", "-f", "qcow2", "-b", resolvedPath(base), above[0])
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("qemu-img commit %s into %s: %w: %s", above[0], base, err, strings.TrimSpace(string(out)))
	}
	return above, nil
}

// removeMergedLayers removes layers a merge left unused, logging (not
// failing on) a file that will not go: the merge is complete either way.
func removeMergedLayers(layers []string) []error {
	var errs []error
	for _, l := range layers {
		if err := os.Remove(l); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errs
}

// SnapshotBaseFiles lists every snapshot libvirt holds for the domain with
// the files its embedded domain's disks were on (the layers it froze). The
// snapshot metadata belongs to the domain, so it is the same list whether the
// domain runs or not.
func (c *Client) SnapshotBaseFiles(domainName string) (map[string][]string, error) {
	return snapshotBaseFiles(c.virt, domainName)
}

// snapshotListAPI is the part of libvirt snapshotBaseFiles uses.
type snapshotListAPI interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainListAllSnapshots(dom golibvirt.Domain, needResults int32, flags uint32) ([]golibvirt.DomainSnapshot, int32, error)
	DomainSnapshotGetXMLDesc(snap golibvirt.DomainSnapshot, flags uint32) (string, error)
}

func snapshotBaseFiles(v snapshotListAPI, domainName string) (map[string][]string, error) {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	snaps, _, err := v.DomainListAllSnapshots(dom, -1, 0)
	if err != nil {
		return nil, fmt.Errorf("list snapshots of %q: %w", domainName, err)
	}
	out := map[string][]string{}
	for _, sn := range snaps {
		x, err := v.DomainSnapshotGetXMLDesc(sn, 0)
		if err != nil {
			return nil, fmt.Errorf("snapshot %q of %q: %w", sn.Name, domainName, err)
		}
		files := []string{}
		for _, f := range parseSnapshotDomainDisks(x) {
			files = append(files, f)
		}
		out[sn.Name] = files
	}
	return out, nil
}
