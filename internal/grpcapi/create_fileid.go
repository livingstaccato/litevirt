package grpcapi

import "os"

// madeFileID is a file a create (or clone) made, as it was right after it was
// made: its device and inode, and where the filesystem records one its birth
// time. A failed create removes a path only while the file there is still
// this one. The inode alone is not enough: ext4 and xfs often give a file
// unlinked and recreated at the same path the same inode number, so a file
// another made there since would read as this create's own. The birth time
// tells them apart; where the filesystem keeps none (fileBirth is zero) the
// inode is all there is, and the comparison is that weak.
type madeFileID struct {
	fi    os.FileInfo
	birth int64
}

// madeFileIdentity reads p's identity now.
func madeFileIdentity(p string) (madeFileID, bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return madeFileID{}, false
	}
	return madeFileID{fi: fi, birth: fileBirth(p)}, true
}

// stillAt reports whether the file at p is still id's.
func (id madeFileID) stillAt(p string) bool {
	now, ok := madeFileIdentity(p)
	if !ok || id.fi == nil || !os.SameFile(now.fi, id.fi) {
		return false
	}
	return id.birth == 0 || now.birth == 0 || id.birth == now.birth
}
