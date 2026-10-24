//go:build linux

package qcow2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/litevirt/litevirt/internal/diskmode"
	"golang.org/x/sys/unix"
)

var ErrArtifactUnknown = errors.New("qcow2: artifact outcome unknown")

const artifactAttribute = "user.litevirt.artifact"
const maxArtifactOwnership = 256

// Narrow syscall seams are used only by same-package physical fault tests.
var artifactFileSync = func(f *os.File) error { return f.Sync() }
var artifactDirectorySync = func(f *os.File) error { return f.Sync() }
var artifactTempUnlink = func(fd int, name string) error { return unix.Unlinkat(fd, name, 0) }
var artifactClose = func(f *os.File) error { return f.Close() }
var artifactSetOwnership = func(fd int, value []byte) error {
	return unix.Fsetxattr(fd, artifactAttribute, value, unix.XATTR_CREATE)
}

// OpenArtifactDirectory follows no symlink, including intermediate components.
// Owned effects additionally require ArtifactLocalFilesystem; ordinary pins
// retain their existing filesystem support.
func OpenArtifactDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("artifact directory is not canonical")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	return f, nil
}

func ArtifactLocalFilesystem(dir *os.File) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &fs); err != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		return fmt.Errorf("artifact filesystem unsupported: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		return fmt.Errorf("artifact directory is not controlled by the participating owner: %v", err)
	}
	return nil
}

func OpenArtifactPinAt(dir *os.File, name string, create bool) (*os.File, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid pin basename")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if create && errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0644)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name))
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size != 0 || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		f.Close()
		return nil, fmt.Errorf("foreign or uncertain pin marker: %v", err)
	}
	if err := ArtifactFileAssociated(f, dir, name); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ArtifactFileAssociated checks the current name against the retained object.
// It supplies no authority and does not unlink anything.
func ArtifactFileAssociated(f, dir *os.File, name string) error {
	if actual, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10)); err != nil || actual != dir.Name() {
		return fmt.Errorf("artifact directory identity changed: %v", err)
	}
	if name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("invalid artifact basename")
	}
	var held, named unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &held); err != nil {
		return err
	}
	if err := unix.Fstatat(int(dir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Mode&unix.S_IFMT != unix.S_IFREG || named.Mode&unix.S_IFMT != unix.S_IFREG || held.Dev != named.Dev || held.Ino != named.Ino {
		return fmt.Errorf("artifact name no longer denotes original file")
	}
	return nil
}

func OpenArtifactFileAt(dir *os.File, name string) (*os.File, error) {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid artifact basename")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name))
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("artifact file type/link state unsupported: %v", err)
	}
	if err := ArtifactFileAssociated(f, dir, name); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func ReadArtifactOwnership(f *os.File) ([]byte, error) {
	b := make([]byte, maxArtifactOwnership+1)
	n, err := unix.Fgetxattr(int(f.Fd()), artifactAttribute, b)
	if err != nil {
		return nil, err
	}
	if n == 0 || n > maxArtifactOwnership {
		return nil, fmt.Errorf("invalid artifact ownership length")
	}
	return b[:n], nil
}

// InspectArtifactFile deliberately restricts the owned profile; ordinary Info
// and Check continue to accept their previous inputs.
func InspectArtifactFile(f *os.File, standalone bool) (*ImageInfo, error) {
	h, err := readHeader(f)
	if err != nil {
		return nil, err
	}
	if h.Version != 3 || h.CryptMethod != 0 || h.SnapshotsOffset != 0 || h.IncompatibleFeatures != 0 || h.CompatibleFeatures != 0 || h.AutoclearFeatures != 0 || h.NbSnapshots != 0 || h.HeaderLength != 104 {
		return nil, fmt.Errorf("unsupported artifact qcow2 profile")
	}
	if standalone && (h.BackingFileOffset != 0 || h.BackingFileSize != 0) {
		return nil, fmt.Errorf("owned base must be standalone")
	}
	end := int64(h.ClusterSize())
	if h.BackingFileOffset != 0 {
		end = int64(h.BackingFileOffset)
	}
	terminated := false
	for offset := int64(h.HeaderLength); offset+8 <= end; {
		var raw [8]byte
		if _, err := f.ReadAt(raw[:], offset); err != nil {
			return nil, err
		}
		kind, size := binary.BigEndian.Uint32(raw[:4]), binary.BigEndian.Uint32(raw[4:])
		if kind == ExtEndOfArea {
			if size != 0 {
				return nil, fmt.Errorf("invalid extension terminator")
			}
			terminated = true
			break
		}
		if standalone || kind != ExtBackingFormat || size != 5 {
			return nil, fmt.Errorf("unsupported artifact header extension")
		}
		var format [5]byte
		if _, err := f.ReadAt(format[:], offset+8); err != nil || string(format[:]) != "qcow2" {
			return nil, fmt.Errorf("unsupported artifact backing format")
		}
		offset += 8 + int64((uint64(size)+7)&^7)
		if offset > end {
			return nil, fmt.Errorf("artifact extension outside header")
		}
	}
	if !terminated {
		return nil, fmt.Errorf("artifact extensions lack terminator")
	}
	if err := CheckFile(f); err != nil {
		return nil, err
	}
	return InfoFile(f)
}

type artifactCreation struct {
	file, dir        *os.File
	temporary, final string
	ownership        []byte
	visible          bool
}

func openArtifactCreation(path string, options ArtifactOptions) (*artifactCreation, error) {
	options.Ownership = append([]byte(nil), options.Ownership...)
	if len(options.Ownership) == 0 || len(options.Ownership) > maxArtifactOwnership || filepath.Dir(options.TemporaryPath) != filepath.Dir(path) || filepath.Clean(path) != path || options.TemporaryPath == path {
		return nil, fmt.Errorf("invalid owned artifact creation options")
	}
	dir, err := OpenArtifactDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := ArtifactLocalFilesystem(dir); err != nil {
		dir.Close()
		return nil, err
	}
	name := filepath.Base(options.TemporaryPath)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(diskmode.File))
	if err != nil {
		dir.Close()
		return nil, err
	}
	return &artifactCreation{file: os.NewFile(uintptr(fd), options.TemporaryPath), dir: dir, temporary: name, final: filepath.Base(path), ownership: options.Ownership}, nil
}

func (a *artifactCreation) closeResult(result *error) {
	for _, f := range []*os.File{a.file, a.dir} {
		if err := artifactClose(f); err != nil {
			*result = fmt.Errorf("%w: close: %v", ErrArtifactUnknown, err)
		}
	}
	// No rollback by path. Even a pre-publication temp remains identified by
	// the pre-journaled plan; missing final does not prove no effect happened.
}

func (a *artifactCreation) publish() error {
	if err := artifactSetOwnership(int(a.file.Fd()), a.ownership); err != nil {
		return err
	}
	marker, err := ReadArtifactOwnership(a.file)
	if err != nil || !bytes.Equal(marker, a.ownership) {
		return fmt.Errorf("artifact ownership readback differs: %v", err)
	}
	if _, err := InspectArtifactFile(a.file, false); err != nil {
		return err
	}
	if err := artifactFileSync(a.file); err != nil {
		return err
	}
	if err := ArtifactFileAssociated(a.file, a.dir, a.temporary); err != nil {
		return err
	}
	// Link the retained original object, not whatever a temp pathname might
	// subsequently denote. /proc is part of this explicitly local profile.
	if err := unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.FormatUint(uint64(a.file.Fd()), 10), int(a.dir.Fd()), a.final, unix.AT_SYMLINK_FOLLOW); err != nil {
		return err
	}
	a.visible = true
	unknown := func(err error) error { return fmt.Errorf("%w: %v", ErrArtifactUnknown, err) }
	if err := ArtifactFileAssociated(a.file, a.dir, a.final); err != nil {
		return unknown(err)
	}
	marker, err = ReadArtifactOwnership(a.file)
	if err != nil || !bytes.Equal(marker, a.ownership) {
		return unknown(fmt.Errorf("published ownership changed: %v", err))
	}
	if err := ArtifactFileAssociated(a.file, a.dir, a.temporary); err != nil {
		return unknown(err)
	}
	if err := artifactTempUnlink(int(a.dir.Fd()), a.temporary); err != nil {
		return unknown(err)
	}
	if err := artifactFileSync(a.file); err != nil {
		return unknown(err)
	}
	if err := artifactDirectorySync(a.dir); err != nil {
		return unknown(err)
	}
	if err := ArtifactFileAssociated(a.file, a.dir, a.final); err != nil {
		return unknown(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(a.file.Fd()), &st); err != nil || st.Nlink != 1 {
		return unknown(fmt.Errorf("published artifact link state: %v", err))
	}
	return nil
}
