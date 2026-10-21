package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// A migration-CA rotation's progress, kept beside the CA on the machine that
// runs `lv host rotate-migration-ca`, so a re-run continues where it stopped.
const (
	rotationFileName = "migration-rotation.json"
	rotationLockName = "migration-rotation.lock"
	nextCACertName   = "migration-ca.next.crt"
	nextCAKeyName    = "migration-ca.next.key"
	bundleCACertName = "migration-ca.bundle.crt"

	phaseTrustBoth = "trust-both"
	phaseReissue   = "reissue"
	phaseDropOld   = "drop-old"
	phaseCutover   = "cutover" // --no-overlap's single pass
	phaseDone      = "done"
)

type migrationRotation struct {
	Phase            string              `json:"phase"`
	NoOverlap        bool                `json:"no_overlap"`
	NewCAFingerprint string              `json:"new_ca_fingerprint"`
	Done             map[string][]string `json:"done"`
	Skipped          map[string]bool     `json:"skipped"`
}

func loadMigrationRotation(pkiDir string) (*migrationRotation, error) {
	data, err := os.ReadFile(filepath.Join(pkiDir, rotationFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r migrationRotation
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", rotationFileName, err)
	}
	return &r, nil
}

func (r *migrationRotation) save(pkiDir string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return secretfile.Write(filepath.Join(pkiDir, rotationFileName), append(data, '\n'), 0o600)
}

func (r *migrationRotation) inProgress() bool { return r != nil && r.Phase != phaseDone }

func (r *migrationRotation) hostDone(host, phase string) bool {
	return slices.Contains(r.Done[host], phase)
}

func (r *migrationRotation) markDone(host, phase string) {
	if r.Done == nil {
		r.Done = map[string][]string{}
	}
	if !r.hostDone(host, phase) {
		r.Done[host] = append(r.Done[host], phase)
	}
}

func (r *migrationRotation) phases() []string {
	if r.NoOverlap {
		return []string{phaseCutover}
	}
	return []string{phaseTrustBoth, phaseReissue, phaseDropOld}
}

// rotationFilePrefix begins every file the rotation keeps in the operator's
// PKI directory beyond migration-ca.crt|.key: next.*, bundle.crt and each
// retired-<date>[-N].crt.
const rotationFilePrefix = "migration-ca."

// rotationFileCollisions names each host whose cluster pair (<name>.crt|.key
// in the operator's PKI directory) would share a file with the rotation's:
// a name beginning rotationFilePrefix, compared case-insensitively because
// that directory may be on a case-insensitive filesystem.
func rotationFileCollisions(hosts []MigrationTLSHost) []string {
	var out []string
	for _, h := range hosts {
		n := h.Name()
		if len(n) >= len(rotationFilePrefix) && strings.EqualFold(n[:len(rotationFilePrefix)], rotationFilePrefix) {
			out = append(out, n)
		}
	}
	return out
}

// lockMigrationRotation takes the operator machine's rotation lock, so two
// runs cannot each mint a next CA. It never waits: a held lock refuses. The
// lock file stays in place; only the flock(2) on it is released.
func lockMigrationRotation(pkiDir string) (unlock func(), err error) {
	path := filepath.Join(pkiDir, rotationLockName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the rotation lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another `lv host rotate-migration-ca` is running on this machine (it holds %s); "+
				"nothing was changed. Let it finish, then run this again if it stopped", path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// unlistedHosts names each status row's host that is not in hosts: one added
// after the run listed the cluster's hosts, which the run would never push.
func unlistedHosts(rows []*pb.MigrationTLSHostStatus, hosts []MigrationTLSHost) []string {
	listed := map[string]bool{}
	for _, h := range hosts {
		listed[h.Name()] = true
	}
	var out []string
	for _, r := range rows {
		if !listed[r.GetHost()] {
			out = append(out, r.GetHost())
		}
	}
	slices.Sort(out)
	return out
}

// unlistedHostsError refuses to go on past hosts the run is not rotating.
func unlistedHostsError(names []string) error {
	return fmt.Errorf("host(s) %s joined the cluster after this run listed its hosts, so this run would "+
		"never bring them to the new CA; it stopped here with its progress saved. Run "+
		"`lv host rotate-migration-ca` again: it lists every host afresh and continues", strings.Join(names, ", "))
}
