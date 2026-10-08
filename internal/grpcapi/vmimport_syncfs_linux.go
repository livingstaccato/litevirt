package grpcapi

import (
	"os"

	"golang.org/x/sys/unix"
)

// syncFilesystem commits the filesystem holding dir (syncfs). On btrfs that
// commits the transaction, after which a file's new blocks show in the free
// space.
func syncFilesystem(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.Syncfs(int(f.Fd()))
}
