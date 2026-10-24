package grpcapi

import (
	"fmt"
	"path/filepath"
)

// heldConvertSource is the name a qcow2.ConvertConfined with NoFollowSource
// opens the top layer of the disk file at p by: in a disk-artifact root (the
// disk directory or a file-based pool), the file beneath its directory held
// open by descriptor with no link followed (openDiskDir), so a directory on
// the way swapped for a link after the caller's checks cannot redirect the
// read; elsewhere p itself, whose final component NoFollowSource still does
// not follow. mapped: p is a logical path the per-node test root maps
// (hostDiskFile). release closes the held directory; call it once the
// conversion is done.
func (s *Server) heldConvertSource(p string, mapped bool) (src string, release func(), err error) {
	root, ok := s.diskArtifactRootOf(p)
	if !ok {
		return s.rootFS(p, mapped), func() {}, nil
	}
	pd, err := s.openDiskDir(root, relUnder(root, filepath.Dir(p)), false, mapped)
	if err != nil {
		return "", nil, fmt.Errorf("the directory of %s cannot be opened without following a link (%w); nothing was read", p, err)
	}
	return pd.path(filepath.Base(p)), pd.close, nil
}

// convertSourceHook runs after a caller of heldConvertSource has done its
// checks and just before the conversion reads the source (tests: swap the
// source's directory there).
var convertSourceHook func(p string)

func runConvertSourceHook(p string) {
	if convertSourceHook != nil {
		convertSourceHook(p)
	}
}
