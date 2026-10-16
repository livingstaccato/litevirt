package pki

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Fault injection at actual file boundaries; nil in production.
var trustDurabilitySeam func(stage string) error

func trustDurabilityPoint(stage string) error {
	if trustDurabilitySeam != nil {
		return trustDurabilitySeam(stage)
	}
	return nil
}

func syncTrustDirectory(dir string) error {
	if err := trustDurabilityPoint("directory-sync"); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func durableTrustReopen(path string, want []byte) error {
	if err := trustDurabilityPoint("reopen"); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := trustDurabilityPoint("file-sync"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	got, err := readBoundedN(path, len(want))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("PKI file changed during durable reopen")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if err := syncTrustDirectory(filepath.Dir(real)); err != nil {
		return err
	}
	return syncTrustDirectory(filepath.Dir(path))
}

func writeTrustFile(path string, body []byte, mode os.FileMode) error {
	if err := trustDurabilityPoint("rename"); err != nil {
		return err
	}
	// secretfile synchronizes the temporary file before its atomic rename.
	if err := secretfile.Write(path, body, mode); err != nil {
		return err
	}
	return durableTrustReopen(path, body)
}
