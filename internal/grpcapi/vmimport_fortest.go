package grpcapi

import (
	"os"
	"path/filepath"
)

// RecordImportLeftoverForTest records the file at path as an import of this
// host left it, the way a crashed import does. With live, the import is still
// running in this process (its name, importName, stays claimed until release);
// without, it ran under a daemon process that is gone. For the fleet harness,
// which cannot crash a daemon mid-import.
func (s *Server) RecordImportLeftoverForTest(path, importName string, live bool) (release func(), err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	rec, ok := placementOf(path, fi, "imp-fortest", false, true)
	if !ok {
		return nil, os.ErrInvalid
	}
	release = func() {}
	if live {
		if release, err = s.claimImportNameAs(importName, rec.ImportID); err != nil {
			return nil, err
		}
	} else {
		rec.Instance = "a-daemon-gone"
	}
	rec.Path = filepath.Clean(path)
	if err := s.writeImportPlacement(rec); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
