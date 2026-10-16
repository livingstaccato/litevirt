package pki

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// InitializeOperatorCA creates only a genuinely unused operator CA. It is not
// root replacement or force-reinitialization authority. Existing CA material is
// left untouched; missing active or unknown identity evidence requires repair.
func InitializeOperatorCA(ctx context.Context, dir string) (err error) {
	o, err := trustOwnerFor(dir)
	if err != nil {
		return err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return err
	}
	absent, err := o.operatorCAAbsentLocked()
	lock.release()
	if err != nil || !absent {
		return err
	}
	// A different process may retain an active domain even if its files have
	// disappeared. Never wait for lifetime admission while holding the owner.
	admissionCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	admission, err := AcquireHostReinitialization(admissionCtx, o.dir)
	if err != nil {
		return err
	}
	defer admission.Release()
	lock, err = o.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.release()
	absent, err = o.operatorCAAbsentLocked()
	if err != nil || !absent {
		return err
	}
	o.invalidateLocked()
	defer func() {
		if err != nil {
			o.dirty = err
		}
	}()
	staging, err := os.MkdirTemp(o.dir, ".operator-ca-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := GenerateCA(filepath.Join(staging, "ca.crt"), filepath.Join(staging, "ca.key")); err != nil {
		return err
	}
	cert, err := readBounded(filepath.Join(staging, "ca.crt"))
	if err != nil {
		return err
	}
	key, err := readBounded(filepath.Join(staging, "ca.key"))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Publish the complete private key first, then its root certificate. A
	// partial error leaves explicit evidence and is never guessed to be unused.
	if err := writeTrustFile(filepath.Join(o.dir, "ca.key"), key, 0600); err != nil {
		return err
	}
	return writeTrustFile(filepath.Join(o.dir, "ca.crt"), cert, 0644)
}

func (o *trustOwner) operatorCAAbsentLocked() (bool, error) {
	rootPath := filepath.Join(o.dir, "ca.crt")
	if _, err := os.Lstat(rootPath); err == nil {
		info, err := os.Stat(rootPath)
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, errors.New("operator CA is not a regular file")
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if len(o.root) != 0 || o.servedFingerprint != [32]byte{} || o.retired {
		return false, errors.New("established operator CA is missing; restore or quiescently reinitialize the domain")
	}
	for _, name := range []string{"ca.key", "host.crt", "host.key", hostDirName} {
		if _, err := os.Lstat(filepath.Join(o.dir, name)); err == nil {
			return false, errors.New("missing operator CA with existing identity evidence; refusing first creation")
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return true, nil
}
