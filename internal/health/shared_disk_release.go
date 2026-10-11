package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A shared disk this host has released (review c2b): `lv doctor repair-owner`
// on another host re-homed a shared disk row naming this host — the source of
// a migration whose ownership commit declined — after this host attested,
// under sharedReleaseMu, that no domain defined here uses the disk's path.
// The attestation is recorded here, beside the host's other start state, and
// every start of a domain on this host checks it under the same lock
// (GuardSharedDiskStart): a domain that uses a released path is refused
// until the released VM's own row for that disk names this host again (the
// VM moved back), so the attestation can never be outrun by a start.
//
// Starts take the read side, so they do not serialize each other; an
// attestation takes the write side, so it never interleaves with a start's
// check and its StartDomain.
var sharedReleaseMu sync.RWMutex

// SharedDiskRelease is one recorded attestation.
type SharedDiskRelease struct {
	Path      string `json:"path"`
	VM        string `json:"vm"`
	Disk      string `json:"disk"`
	Requester string `json:"requester"`
	At        string `json:"at"`
}

func sharedReleaseDir(dataDir string) string { return filepath.Join(dataDir, "shared-disk-released") }

func sharedReleaseFile(dataDir, path string) string {
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(sharedReleaseDir(dataDir), hex.EncodeToString(sum[:]))
}

// LockSharedDiskStarts takes the write side of the start lock for an
// attestation: no start on this host checks or runs until release is called.
func LockSharedDiskStarts() (release func()) {
	sharedReleaseMu.Lock()
	return sharedReleaseMu.Unlock
}

// RecordSharedDiskRelease durably records rel. The caller holds
// LockSharedDiskStarts.
func RecordSharedDiskRelease(dataDir string, rel SharedDiskRelease) error {
	if rel.Path == "" {
		return fmt.Errorf("a released disk names a path")
	}
	if rel.At == "" {
		rel.At = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(sharedReleaseDir(dataDir), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(rel)
	p := sharedReleaseFile(dataDir, rel.Path)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(p)
		return fmt.Errorf("record the release of %s: %v %v %v", rel.Path, werr, serr, cerr)
	}
	if d, err := os.Open(sharedReleaseDir(dataDir)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// sharedReleases lists the recorded releases. An unreadable record fails the
// check (it may be one).
func sharedReleases(dataDir string) ([]SharedDiskRelease, error) {
	ents, err := os.ReadDir(sharedReleaseDir(dataDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []SharedDiskRelease
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(sharedReleaseDir(dataDir), e.Name()))
		if err != nil {
			return nil, err
		}
		var rel SharedDiskRelease
		if err := json.Unmarshal(b, &rel); err != nil || rel.Path == "" {
			return nil, fmt.Errorf("unreadable shared-disk release %s: %v", e.Name(), err)
		}
		out = append(out, rel)
	}
	return out, nil
}

// DomainXMLUsesPath reports whether a domain definition names path as a
// disk source.
func DomainXMLUsesPath(xml, path string) bool {
	return path != "" && (strings.Contains(xml, "'"+path+"'") || strings.Contains(xml, `"`+path+`"`))
}

// GuardSharedDiskStart is the start check every start of an existing VM's
// domain on this host runs just before StartDomain, with domXML the
// definition about to start. It holds the read side of the start lock until
// release is called — after StartDomain — so no attestation interleaves. A
// domain using a path this host released is refused, unless vm is the
// released VM and its row for that disk names this host again.
func GuardSharedDiskStart(ctx context.Context, db *corrosion.Client, dataDir, host, vm, domXML string) (release func(), err error) {
	sharedReleaseMu.RLock()
	rels, err := sharedReleases(dataDir)
	if err != nil {
		sharedReleaseMu.RUnlock()
		return nil, fmt.Errorf("read this host's released shared disks: %w", err)
	}
	if domXML == "" && len(rels) > 0 {
		// The definition cannot be read (review m2): with releases on record
		// it may use one, so the start is refused rather than run unchecked.
		sharedReleaseMu.RUnlock()
		return nil, fmt.Errorf("%s is not started on %s: its definition cannot be read to check it against the shared "+
			"disks this host released", vm, host)
	}
	for _, rel := range rels {
		if !DomainXMLUsesPath(domXML, rel.Path) {
			continue
		}
		if db != nil {
			// A release for a VM that no longer exists (review m6) protects
			// nothing: that VM's row cannot name this host again.
			if rec, gerr := corrosion.GetVM(ctx, db, rel.VM); gerr == nil && rec == nil {
				continue
			}
		}
		if rel.VM == vm && db != nil {
			if disks, derr := corrosion.GetVMDisks(ctx, db, vm); derr == nil {
				back := false
				for _, d := range disks {
					if d.DiskName == rel.Disk && d.Path == rel.Path && d.HostName == host {
						back = true
					}
				}
				if back {
					continue // the VM came back with its disk: the release is over
				}
			}
		}
		sharedReleaseMu.RUnlock()
		return nil, fmt.Errorf("%s is not started on %s: it uses the shared disk %s, which %s released to %s (lv doctor "+
			"repair-owner of %s, %s) after attesting no domain here used it; it may be started here only once %s's row "+
			"for that disk names %s again, or %s is deleted (the release is recorded in %s)", vm, host, rel.Path, host,
			rel.Requester, rel.VM, rel.At, rel.VM, host, rel.VM, sharedReleaseFile(dataDir, rel.Path))
	}
	return sharedReleaseMu.RUnlock, nil
}
