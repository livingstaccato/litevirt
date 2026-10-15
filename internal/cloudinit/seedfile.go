package cloudinit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Seed is the files of a NoCloud seed. NetworkConfig is "" for a seed with
// no network-config file.
type Seed struct {
	MetaData, UserData, NetworkConfig string
}

// InstanceID is the instance-id the seed's meta-data names, "" for none.
func (s Seed) InstanceID() string {
	for _, line := range strings.Split(s.MetaData, "\n") {
		if v, ok := strings.CutPrefix(line, "instance-id:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// RebuildISO replaces the network-config of the seed at path with
// networkConfig ("" for none) and keeps its meta-data and user-data byte for
// byte, so cloud-init never sees a new instance (a new instance-id would run
// first boot again). It reports whether the seed was rewritten: a seed whose
// network-config already is networkConfig is left as it is. A seed that
// cannot be read, or names no instance-id, is left as it is and is an error.
func RebuildISO(path, networkConfig string) (bool, error) {
	seed, err := ReadSeed(path)
	if err != nil {
		return false, err
	}
	if seed.InstanceID() == "" {
		return false, fmt.Errorf("seed %s names no instance-id", path)
	}
	if seed.NetworkConfig == networkConfig {
		return false, nil
	}
	seed.NetworkConfig = networkConfig
	if err := writeISO(seed, path); err != nil {
		return false, err
	}
	return true, nil
}

const (
	isoSector = 2048
	// maxSeedFile bounds what one seed file read may allocate.
	maxSeedFile = 64 << 20
)

// ReadSeed reads the NoCloud seed at path, an ISO 9660 image with Rock Ridge
// names as GenerateISO writes it (genisoimage -rock). meta-data is required;
// user-data and network-config are "" when the image has none.
func ReadSeed(path string) (Seed, error) {
	f, err := os.Open(path)
	if err != nil {
		return Seed{}, err
	}
	defer f.Close()
	files, err := isoRootFiles(f)
	if err != nil {
		return Seed{}, fmt.Errorf("read seed %s: %w", path, err)
	}
	read := func(name string) (string, bool, error) {
		e, ok := files[name]
		if !ok {
			return "", false, nil
		}
		if e.size > maxSeedFile {
			return "", false, fmt.Errorf("read seed %s: %s is %d bytes", path, name, e.size)
		}
		b := make([]byte, e.size)
		if _, err := f.ReadAt(b, int64(e.extent)*isoSector); err != nil {
			return "", false, fmt.Errorf("read seed %s: %s: %w", path, name, err)
		}
		return string(b), true, nil
	}
	var s Seed
	var ok bool
	if s.MetaData, ok, err = read("meta-data"); err != nil {
		return Seed{}, err
	} else if !ok {
		return Seed{}, fmt.Errorf("read seed %s: no meta-data", path)
	}
	if s.UserData, _, err = read("user-data"); err != nil {
		return Seed{}, err
	}
	if s.NetworkConfig, _, err = read("network-config"); err != nil {
		return Seed{}, err
	}
	return s, nil
}

type isoFile struct {
	extent, size uint32
}

// isoRootFiles lists the regular files of the root directory of the ISO 9660
// image r by their Rock Ridge names. An entry with no Rock Ridge name is not
// listed.
func isoRootFiles(r io.ReaderAt) (map[string]isoFile, error) {
	pvd := make([]byte, isoSector)
	if _, err := r.ReadAt(pvd, 16*isoSector); err != nil {
		return nil, fmt.Errorf("no ISO 9660 volume descriptor: %w", err)
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return nil, errors.New("not an ISO 9660 image")
	}
	root := pvd[156 : 156+34]
	extent := binary.LittleEndian.Uint32(root[2:6])
	size := binary.LittleEndian.Uint32(root[10:14])
	if size == 0 || size > maxSeedFile {
		return nil, fmt.Errorf("root directory of %d bytes", size)
	}
	dir := make([]byte, size)
	if _, err := r.ReadAt(dir, int64(extent)*isoSector); err != nil {
		return nil, fmt.Errorf("read root directory: %w", err)
	}
	out := map[string]isoFile{}
	for off := 0; off < len(dir); {
		n := int(dir[off])
		if n == 0 {
			// Records do not cross a sector; the rest of this one is padding.
			off = (off/isoSector + 1) * isoSector
			continue
		}
		if n < 34 || off+n > len(dir) {
			return nil, errors.New("malformed directory record")
		}
		rec := dir[off : off+n]
		off += n
		if rec[25]&0x02 != 0 { // a directory, "." or ".." among them
			continue
		}
		idLen := int(rec[32])
		su := 33 + idLen
		if idLen%2 == 0 {
			su++ // padding byte after an even-length identifier
		}
		if su > len(rec) {
			return nil, errors.New("malformed directory record")
		}
		if name := rockRidgeName(rec[su:]); name != "" {
			out[name] = isoFile{extent: binary.LittleEndian.Uint32(rec[2:6]), size: binary.LittleEndian.Uint32(rec[10:14])}
		}
	}
	return out, nil
}

// rockRidgeName is the name the Rock Ridge NM entries of a directory record's
// system use area spell, "" for none.
func rockRidgeName(su []byte) string {
	var name bytes.Buffer
	for len(su) >= 4 {
		l := int(su[2])
		if l < 4 || l > len(su) {
			break
		}
		if su[0] == 'N' && su[1] == 'M' && l >= 5 {
			name.Write(su[5:l])
		}
		su = su[l:]
	}
	return name.String()
}
