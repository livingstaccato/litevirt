package grpcapi

import "fmt"

// removeDiskFileBeneath removes the file at p, which lies in one of this
// host's disk roots, through the directory held open beneath that root
// (removeBeneath): a component swapped for a link is never followed. mapped is
// whether p is a logical path the per-node test root maps (hostDiskFile), as
// the cold-move and firmware paths do; EnsureDisks names the file itself.
func (s *Server) removeDiskFileBeneath(p string, mapped bool) error {
	root, ok := s.diskArtifactRootOf(p)
	if !ok {
		return fmt.Errorf("%s is not in a disk-artifact root of %s", p, s.hostName)
	}
	rootFS := root
	if mapped {
		rootFS = s.hostDiskFile(root)
	}
	return removeBeneath(rootFS, root, p)
}
