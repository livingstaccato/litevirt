package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// A migration-CA rotation's progress, kept beside the CA on the machine that
// runs `lv host rotate-migration-ca`, so a re-run continues where it stopped.
const (
	rotationFileName = "migration-rotation.json"
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
