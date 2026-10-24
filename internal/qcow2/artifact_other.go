//go:build !linux

package qcow2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrArtifactUnknown = errors.New("qcow2: artifact outcome unknown")
var errArtifactUnsupported = errors.New("qcow2: owned artifact requires supported Linux local filesystem")

type artifactCreation struct{ file *os.File }

func openArtifactCreation(string, ArtifactOptions) (*artifactCreation, error) {
	return nil, errArtifactUnsupported
}
func (*artifactCreation) closeResult(*error) {}
func (*artifactCreation) publish() error     { return errArtifactUnsupported }

// Ordinary permanent image pins remain available. Owned QCOW2 creation and
// inspection still refuse this platform, before any owned disk effect.
func OpenArtifactDirectory(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		f.Close()
		return nil, fmt.Errorf("invalid pin directory")
	}
	return f, nil
}
func ArtifactFileAssociated(f, dir *os.File, name string) error {
	held, err := f.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(filepath.Join(dir.Name(), name))
	if err != nil {
		return err
	}
	if !held.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(held, named) {
		return fmt.Errorf("pin file identity differs")
	}
	return nil
}
func OpenArtifactFileAt(dir *os.File, name string) (*os.File, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid pin basename")
	}
	f, err := os.Open(filepath.Join(dir.Name(), name))
	if err != nil {
		return nil, err
	}
	if err := ArtifactFileAssociated(f, dir, name); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func ReadArtifactOwnership(*os.File) ([]byte, error)         { return nil, errArtifactUnsupported }
func InspectArtifactFile(*os.File, bool) (*ImageInfo, error) { return nil, errArtifactUnsupported }
func ArtifactLocalFilesystem(*os.File) error                 { return errArtifactUnsupported }
func OpenArtifactPinAt(dir *os.File, name string, create bool) (*os.File, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid pin basename")
	}
	f, err := os.Open(filepath.Join(dir.Name(), name))
	if create && errors.Is(err, os.ErrNotExist) {
		f, err = os.OpenFile(filepath.Join(dir.Name(), name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	}
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || st.Size() != 0 {
		f.Close()
		return nil, fmt.Errorf("foreign pin marker")
	}
	if err := ArtifactFileAssociated(f, dir, name); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
