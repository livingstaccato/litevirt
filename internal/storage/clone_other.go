//go:build !linux

package storage

import (
	"io"
	"os"
)

// cloneFile copies in to out: no reflink off Linux.
func cloneFile(out, in *os.File) error {
	_, err := io.Copy(out, in)
	return err
}
