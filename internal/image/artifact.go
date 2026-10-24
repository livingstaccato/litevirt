package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
)

// ArtifactDiskPlan contains immutable effect arguments, never execution authority.
// Version1 supports one local qcow2 overlay on one standalone retained base;
// VirtualSize always inherits that verified base, with no live size override.
type ArtifactDiskPlan struct {
	Version          int                     `json:"version"`
	Artifact         contract.ArtifactRecord `json:"artifact"`
	VMName           string                  `json:"vm_name"`
	DiskName         string                  `json:"disk_name"`
	Locator          string                  `json:"locator"`
	TemporaryLocator string                  `json:"temporary_locator"`
	ImageName        string                  `json:"image_name"`
	BaseLocator      string                  `json:"base_locator"`
	ImageDigest      string                  `json:"image_digest"`
	VirtualSize      uint64                  `json:"virtual_size"`
}

var artifactPinFileSync = func(f *os.File) error { return f.Sync() }
var artifactPinDirectorySync = func(f *os.File) error { return f.Sync() }
var artifactPinOpen = qcow2.OpenArtifactPinAt
var artifactRemovalChecked func(*Store, string)

// Closing the last retained identity is part of classifying an owned result.
func closeArtifactFile(f *os.File, result *error) {
	if err := f.Close(); err != nil {
		*result = fmt.Errorf("%w: close retained identity: %v", qcow2.ErrArtifactUnknown, err)
	}
}

// Validate checks local data shape only. It cannot authorize execution.
func (p ArtifactDiskPlan) Validate() error {
	a := p.Artifact
	if p.Version != 1 || a.Kind != "disk" || a.Backend != "local" || a.State != "planned" || a.Locator != p.Locator || a.ImageDigest != p.ImageDigest || a.PayloadID != "" || a.Origin.Generation == 0 || a.Origin.Decision.Sequence == 0 || !validDigest(a.Origin.Decision.Digest) || !validDigest(p.ImageDigest) || p.VirtualSize == 0 {
		return fmt.Errorf("invalid disk artifact plan")
	}
	for _, s := range []string{a.ID, a.Key, a.ObjectID, a.ResourceUID, a.Incarnation, a.OperationID, a.HostUID, a.HostIncarnation, a.PoolUID} {
		if s == "" || len(s) > 1024 || !utf8.ValidString(s) {
			return fmt.Errorf("invalid disk artifact identity")
		}
	}
	if safename.ValidateVMName(p.VMName) != nil || safename.ValidateDiskName(p.DiskName) != nil || safename.ValidateImageName(p.ImageName) != nil {
		return fmt.Errorf("invalid disk artifact names")
	}
	for _, s := range []string{p.Locator, p.TemporaryLocator, p.BaseLocator} {
		if !filepath.IsAbs(s) || filepath.Clean(s) != s {
			return fmt.Errorf("invalid disk artifact locator")
		}
	}
	if p.TemporaryLocator == p.Locator || filepath.Dir(p.TemporaryLocator) != filepath.Dir(p.Locator) || filepath.Base(p.TemporaryLocator)[0] != '.' {
		return fmt.Errorf("invalid planned artifact temporary")
	}
	return nil
}

func artifactOwnership(a contract.ArtifactRecord) []byte {
	a.State = ""
	a.Locator = ""
	b, _ := json.Marshal(a)
	h := sha256.Sum256(append([]byte("litevirt-disk-artifact/v1\x00"), b...))
	// Object identity and binding fingerprint are nonsecret physical metadata.
	value, _ := json.Marshal(struct {
		Version int    `json:"v"`
		Object  string `json:"object"`
		Binding string `json:"binding"`
	}{1, a.ObjectID, hex.EncodeToString(h[:])})
	return value
}

func (s *Store) validateArtifactPlan(p ArtifactDiskPlan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	path, err := s.SafeDiskPath(p.VMName, p.DiskName)
	if err != nil || path != p.Locator || !IsImageFile(s.imageDir, p.ImageName, p.BaseLocator) {
		return fmt.Errorf("artifact plan does not belong to this store")
	}
	if len(artifactOwnership(p.Artifact)) > 256 {
		return fmt.Errorf("artifact physical identity too large")
	}
	return nil
}

func inspectArtifactBase(dir *os.File, path, digest string, size uint64) (*os.File, *qcow2.ImageInfo, error) {
	if err := qcow2.ArtifactLocalFilesystem(dir); err != nil {
		return nil, nil, err
	}
	f, err := qcow2.OpenArtifactFileAt(dir, filepath.Base(path))
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.File, *qcow2.ImageInfo, error) { f.Close(); return nil, nil, err }
	info, err := qcow2.InspectArtifactFile(f, true)
	if err != nil {
		return fail(err)
	}
	if size != 0 && info.VirtualSize != size {
		return fail(fmt.Errorf("frozen base size differs"))
	}
	provenance, ok := RecordedDigest(path)
	if !ok || provenance != digest {
		return fail(fmt.Errorf("retained base provenance differs"))
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(f, 0, 1<<63-1)); err != nil {
		return fail(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return fail(fmt.Errorf("actual retained base digest differs"))
	}
	if err = qcow2.ArtifactFileAssociated(f, dir, filepath.Base(path)); err != nil {
		return fail(err)
	}
	return f, info, nil
}

// PrepareArtifactOverlay reads the actual base without any disk or pin effect.
// The returned complete value must be persisted by the existing journal first.
func (s *Store) PrepareArtifactOverlay(a contract.ArtifactRecord, vm, disk, name, digest string) (ArtifactDiskPlan, error) {
	var p ArtifactDiskPlan
	if safename.ValidateImageName(name) != nil || !validDigest(digest) {
		return p, fmt.Errorf("invalid pinned image")
	}
	path, err := s.SafeDiskPath(vm, disk)
	if err != nil {
		return p, err
	}
	defer s.lockName(name)()
	dir, err := qcow2.OpenArtifactDirectory(s.imageDir)
	if err != nil {
		return p, err
	}
	defer dir.Close()
	for _, base := range s.ImageFiles(name) {
		if recorded, ok := RecordedDigest(base); !ok || recorded != digest {
			continue
		}
		f, info, err := inspectArtifactBase(dir, base, digest, 0)
		if err != nil {
			return p, err
		}
		f.Close()
		if a.ObjectID == "" {
			a.ObjectID = randid.New()
		}
		a.State = "planned"
		a.Locator = path
		p = ArtifactDiskPlan{Version: 1, Artifact: a, VMName: vm, DiskName: disk, Locator: path, TemporaryLocator: filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+randid.New()+".tmp"), ImageName: name, BaseLocator: base, ImageDigest: digest, VirtualSize: info.VirtualSize}
		return p, s.validateArtifactPlan(p)
	}
	return p, fmt.Errorf("exact retained image content unavailable")
}

// pinArtifactLocked requires the Store's image name lock, also held by both
// removal owners. Pins are permanent, including after an uncertain sync.
func (s *Store) pinArtifactLocked(path string, create bool) (err error) {
	dir, err := qcow2.OpenArtifactDirectory(s.imageDir)
	if err != nil {
		return err
	}
	defer closeArtifactFile(dir, &err)
	base, err := qcow2.OpenArtifactFileAt(dir, filepath.Base(path))
	if err != nil {
		return err
	}
	defer closeArtifactFile(base, &err)
	name := filepath.Base(pinPath(path))
	f, err := artifactPinOpen(dir, name, create)
	if err != nil {
		return err
	}
	defer closeArtifactFile(f, &err)
	if err = artifactPinFileSync(f); err != nil {
		return err
	}
	if err = qcow2.ArtifactFileAssociated(f, dir, name); err != nil {
		return err
	}
	if err = artifactPinDirectorySync(dir); err != nil {
		return err
	}
	if err = qcow2.ArtifactFileAssociated(base, dir, filepath.Base(path)); err != nil {
		return err
	}
	return qcow2.ArtifactFileAssociated(f, dir, name)
}

// CreateArtifactOverlayDisk consumes only the immutable recorded plan. Its
// caller must hold actual execution permission; this backend grants none.
func (s *Store) CreateArtifactOverlayDisk(p ArtifactDiskPlan) (err error) {
	if err = s.validateArtifactPlan(p); err != nil {
		return err
	}
	defer s.lockName(p.ImageName)()
	dir, err := qcow2.OpenArtifactDirectory(s.imageDir)
	if err != nil {
		return err
	}
	defer closeArtifactFile(dir, &err)
	base, _, err := inspectArtifactBase(dir, p.BaseLocator, p.ImageDigest, p.VirtualSize)
	if err != nil {
		return err
	}
	defer closeArtifactFile(base, &err)
	// Strict durable backing retention precedes even the temporary disk.
	if err = s.pinArtifactLocked(p.BaseLocator, true); err != nil {
		return err
	}
	if err = diskmode.MkdirAll(filepath.Dir(p.Locator)); err != nil {
		return err
	}
	// The flat destination directory is synced before disk publication.
	parent, err := qcow2.OpenArtifactDirectory(s.diskDir)
	if err != nil {
		return err
	}
	if err = parent.Sync(); err != nil {
		parent.Close()
		return err
	}
	if err = parent.Close(); err != nil {
		return err
	}
	if err = qcow2.ArtifactFileAssociated(base, dir, filepath.Base(p.BaseLocator)); err != nil {
		return err
	}
	return qcow2.CreateWithBacking(p.Locator, p.BaseLocator, p.VirtualSize, &qcow2.Options{Artifact: &qcow2.ArtifactOptions{Ownership: artifactOwnership(p.Artifact), TemporaryPath: p.TemporaryLocator}})
}

// ObserveArtifactDisk recognizes a physical object only. Unknown/absent final
// or temporary objects never authorize another allocation, cleanup or boot.
func (s *Store) ObserveArtifactDisk(p ArtifactDiskPlan) (observed contract.ArtifactRecord, err error) {
	var zero contract.ArtifactRecord
	if err := s.validateArtifactPlan(p); err != nil {
		return zero, err
	}
	defer s.lockName(p.ImageName)()
	baseDir, err := qcow2.OpenArtifactDirectory(s.imageDir)
	if err != nil {
		return zero, err
	}
	defer closeArtifactFile(baseDir, &err)
	base, _, err := inspectArtifactBase(baseDir, p.BaseLocator, p.ImageDigest, p.VirtualSize)
	if err != nil {
		return zero, err
	}
	defer closeArtifactFile(base, &err)
	if err = s.pinArtifactLocked(p.BaseLocator, false); err != nil {
		return zero, err
	}
	dir, err := qcow2.OpenArtifactDirectory(filepath.Dir(p.Locator))
	if err != nil {
		return zero, err
	}
	defer closeArtifactFile(dir, &err)
	if err = qcow2.ArtifactLocalFilesystem(dir); err != nil {
		return zero, err
	}
	f, err := qcow2.OpenArtifactFileAt(dir, filepath.Base(p.Locator))
	if err != nil {
		// Inspect only the exact pre-journaled temp. Recognizing it still does
		// not prove publication or allow a retry allocation/automatic cleanup.
		if temporary, openErr := qcow2.OpenArtifactFileAt(dir, filepath.Base(p.TemporaryLocator)); openErr == nil {
			marker, markerErr := qcow2.ReadArtifactOwnership(temporary)
			info, infoErr := qcow2.InspectArtifactFile(temporary, false)
			associated := qcow2.ArtifactFileAssociated(temporary, dir, filepath.Base(p.TemporaryLocator))
			closeErr := temporary.Close()
			if markerErr == nil && infoErr == nil && associated == nil && closeErr == nil && bytes.Equal(marker, artifactOwnership(p.Artifact)) && info.VirtualSize == p.VirtualSize && info.BackingFile == p.BaseLocator {
				return zero, fmt.Errorf("%w: original temporary object %s retained; publication uncertain", qcow2.ErrArtifactUnknown, p.Artifact.ObjectID)
			}
		}
		return zero, fmt.Errorf("%w: final unavailable; retain plan and temporary %s: %v", qcow2.ErrArtifactUnknown, p.TemporaryLocator, err)
	}
	defer closeArtifactFile(f, &err)
	marker, err := qcow2.ReadArtifactOwnership(f)
	if err != nil || !bytes.Equal(marker, artifactOwnership(p.Artifact)) {
		return zero, fmt.Errorf("artifact ownership differs: %v", err)
	}
	info, err := qcow2.InspectArtifactFile(f, false)
	if err != nil {
		return zero, err
	}
	if info.VirtualSize != p.VirtualSize || info.BackingFile != p.BaseLocator || info.BackingFormat != "qcow2" {
		return zero, fmt.Errorf("artifact backing/size differs")
	}
	if err = qcow2.ArtifactFileAssociated(f, dir, filepath.Base(p.Locator)); err != nil {
		return zero, err
	}
	if err = qcow2.ArtifactFileAssociated(base, baseDir, filepath.Base(p.BaseLocator)); err != nil {
		return zero, err
	}
	a := p.Artifact
	a.State = "active"
	return a, nil
}

// IsArtifactUnknown keeps backend uncertainty structural, never text matched.
func IsArtifactUnknown(err error) bool { return errors.Is(err, qcow2.ErrArtifactUnknown) }
