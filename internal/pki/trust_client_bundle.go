package pki

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// InstallCLIClientFiles is the operator's existing CLI-bundle copy path. It
// cannot replace a host domain's CA. Classifying a workstation directory and
// writing its CA share the enrollment owner barrier, including when no host
// files exist yet. Client file ownership stays on the temporary descriptors.
func InstallCLIClientFiles(ctx context.Context, dir string, ca, cert, key []byte, uid, gid int) (err error) {
	for _, body := range [][]byte{ca, cert, key} {
		if len(body) > 1<<20 {
			return errors.New("CLI bundle file exceeds bound")
		}
	}
	ca, cert, key = bytes.Clone(ca), bytes.Clone(cert), bytes.Clone(key)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	owner, err := trustOwnerFor(dir)
	if err != nil {
		return err
	}
	lock, err := owner.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.release()
	active := len(owner.root) != 0 || owner.servedFingerprint != [32]byte{} || owner.retired
	for _, name := range []string{"host.crt", "host.key", hostDirName} {
		if _, e := os.Lstat(filepath.Join(owner.dir, name)); e == nil {
			active = true
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if active {
		old, err := readBounded(filepath.Join(owner.dir, "ca.crt"))
		if err != nil {
			return fmt.Errorf("active host CA is unavailable: %w", err)
		}
		if !bytes.Equal(old, ca) {
			return errors.New("CLI bundle cannot replace an active host CA; use authorized quiescent enrollment")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owner.invalidateLocked()
	defer func() {
		if err != nil {
			owner.dirty = err
		}
	}()
	// A root installing a workstation bundle for its invoking user must leave
	// the stable lock usable by that user. Chown the actual locked descriptor,
	// never a user-controlled pathname, and never transfer an active host lock.
	if !active && (uid >= 0 || gid >= 0) {
		if err := lock.file.Chown(uid, gid); err != nil {
			return err
		}
		if err := lock.file.Sync(); err != nil {
			return err
		}
	}
	files := []struct {
		name string
		body []byte
		mode os.FileMode
	}{{"ca.crt", ca, 0644}, {"client.crt", cert, 0644}, {"client.key", key, 0600}}
	for _, file := range files {
		if active && file.name == "ca.crt" {
			continue
		}
		path := filepath.Join(owner.dir, file.name)
		if err := trustDurabilityPoint("rename"); err != nil {
			return err
		}
		if err := secretfile.WriteOwned(path, file.body, file.mode, uid, gid); err != nil {
			return err
		}
		if err := durableTrustReopen(path, file.body); err != nil {
			return err
		}
	}
	return nil
}
