package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const nativeCARecordName = ".operator-ca-operation"
const nativeCAStageName = ".operator-ca-native"
const nativeCARecordSize = 104

// LVNCA001 identifies version 1, operator-root creation, unassigned. No
// assignment/enrollment authority is exposed by this publication-only record.
// Bytes 8..39 are the random operation ID; 40..71 and 72..103 are SHA256 of
// the exact staged certificate and key PEM. The committed record and pair are
// retained: neither retry nor normal existing-root return mints another record.
type nativeOperatorCA struct {
	record, cert, key []byte
	original          []byte
	assignment        *nativeAssignedOperation
}

func readNativeCAFile(path string, limit int) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("native CA evidence is not a regular file")
	}
	body, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, errors.New("native CA evidence exceeds bound")
	}
	return body, nil
}

func (o *trustOwner) readNativeOperatorCALocked() (*nativeOperatorCA, error) {
	record, err := readNativeCAFile(filepath.Join(o.dir, nativeCARecordName), nativeAssignmentLimit)
	if errors.Is(err, os.ErrNotExist) {
		if _, stageErr := os.Lstat(filepath.Join(o.dir, nativeCAStageName)); !errors.Is(stageErr, os.ErrNotExist) {
			return nil, errors.New("uncommitted native CA staging requires repair")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	original := record
	var assignment *nativeAssignedOperation
	if len(record) >= 8 && string(record[:8]) == "LVNCA002" {
		assignment = new(nativeAssignedOperation)
		if err := nativeCanonicalDER(record[8:], nativeAssignmentLimit-8, assignment); err != nil {
			return nil, err
		}
		original = assignment.Original
	}
	if len(original) != nativeCARecordSize || string(original[:8]) != "LVNCA001" || bytes.Equal(original[8:40], make([]byte, 32)) {
		return nil, errors.New("invalid native CA operation")
	}
	stage := filepath.Join(o.dir, nativeCAStageName)
	info, err := os.Lstat(stage)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("native CA staging is not a private directory")
	}
	cert, err := readNativeCAFile(filepath.Join(stage, "ca.crt"), maxServingChainBytes)
	if err != nil {
		return nil, err
	}
	key, err := readNativeCAFile(filepath.Join(stage, "ca.key"), maxServingChainBytes)
	if err != nil {
		return nil, err
	}
	certHash, keyHash := sha256.Sum256(cert), sha256.Sum256(key)
	if !bytes.Equal(original[40:72], certHash[:]) || !bytes.Equal(original[72:], keyHash[:]) {
		return nil, errors.New("native CA staged binding mismatch")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("native CA pair: %w", err)
	}
	if len(pair.Certificate) != 1 {
		return nil, errors.New("native CA is not one root")
	}
	root, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("native CA is not self-signed")
	}
	if assignment != nil {
		if err := validateNativeAssignment(assignment, cert, original); err != nil {
			return nil, err
		}
	}
	return &nativeOperatorCA{record: record, cert: cert, key: key, original: original, assignment: assignment}, nil
}

// Validate before the old existing-root early return. Missing active material
// is recoverable only during the exact committed, not-yet-serving publication.
func (o *trustOwner) nativeOperatorCAPendingLocked(n *nativeOperatorCA) (bool, error) {
	root, rootErr := readNativeCAFile(filepath.Join(o.dir, "ca.crt"), maxServingChainBytes)
	key, keyErr := readNativeCAFile(filepath.Join(o.dir, "ca.key"), maxServingChainBytes)
	if rootErr != nil && !errors.Is(rootErr, os.ErrNotExist) {
		return false, rootErr
	}
	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return false, keyErr
	}
	if rootErr == nil && !bytes.Equal(root, n.cert) || keyErr == nil && !bytes.Equal(key, n.key) {
		return false, errors.New("published native CA contradicts operation")
	}
	if rootErr == nil {
		if keyErr != nil {
			return false, errors.New("published native CA key is missing")
		}
		if err := o.syncNativeOperatorCALocked(n); err != nil {
			return false, err
		}
		return false, nil
	}
	if n.assignment != nil {
		return false, errors.New("assigned native CA publication is missing; refusing re-publication")
	}
	if len(o.root) != 0 || o.servedFingerprint != [32]byte{} || o.retired {
		return false, errors.New("established native CA is missing")
	}
	for _, name := range []string{"host.crt", "host.key", hostDirName} {
		if _, err := os.Lstat(filepath.Join(o.dir, name)); !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("native CA publication has established identity evidence")
		}
	}
	return true, nil
}

func (o *trustOwner) syncNativeOperatorCALocked(n *nativeOperatorCA) error {
	for _, entry := range []struct {
		name string
		body []byte
	}{
		{filepath.Join(nativeCAStageName, "ca.crt"), n.cert},
		{filepath.Join(nativeCAStageName, "ca.key"), n.key},
		{nativeCARecordName, n.record},
		{"ca.key", n.key}, {"ca.crt", n.cert},
	} {
		if err := durableTrustReopen(filepath.Join(o.dir, entry.name), entry.body); err != nil {
			return err
		}
	}
	return nil
}

func (o *trustOwner) publishNativeOperatorCALocked(ctx context.Context) (err error) {
	n, err := o.readNativeOperatorCALocked()
	if err != nil {
		return err
	}
	if n == nil {
		stage := filepath.Join(o.dir, nativeCAStageName)
		if err := os.Mkdir(stage, 0700); err != nil {
			return err
		}
		// Only a known, live precommit error may discard its own staging.
		// Process death preserves ambiguous staging and reopening refuses it.
		defer func() {
			if err != nil {
				if _, e := os.Lstat(filepath.Join(o.dir, nativeCARecordName)); errors.Is(e, os.ErrNotExist) {
					_ = os.RemoveAll(stage)
					_ = syncTrustDirectory(o.dir)
				}
			}
		}()
		if err := generateCAAt(filepath.Join(stage, "ca.crt"), filepath.Join(stage, "ca.key"), nativeEnrollmentNow()); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(stage, "ca.crt"), 0600); err != nil {
			return err
		}
		cert, err := readNativeCAFile(filepath.Join(stage, "ca.crt"), maxServingChainBytes)
		if err != nil {
			return err
		}
		key, err := readNativeCAFile(filepath.Join(stage, "ca.key"), maxServingChainBytes)
		if err != nil {
			return err
		}
		for name, body := range map[string][]byte{"ca.crt": cert, "ca.key": key} {
			if err := durableTrustReopen(filepath.Join(stage, name), body); err != nil {
				return err
			}
		}
		if err := trustDurabilityPoint("native-ca:staged"); err != nil {
			return err
		}
		record := make([]byte, nativeCARecordSize)
		copy(record, "LVNCA001")
		if _, err := rand.Read(record[8:40]); err != nil {
			return err
		}
		certHash, keyHash := sha256.Sum256(cert), sha256.Sum256(key)
		copy(record[40:72], certHash[:])
		copy(record[72:], keyHash[:])
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeTrustFile(filepath.Join(o.dir, nativeCARecordName), record, 0600); err != nil {
			return err
		}
		if err := trustDurabilityPoint("native-ca:record-committed"); err != nil {
			return err
		}
		n = &nativeOperatorCA{record: record, cert: cert, key: key, original: record}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Re-sync the retained commitment before any active publication, including
	// when the previous process died during the record's durable reopen.
	for _, entry := range []struct {
		name string
		body []byte
	}{{filepath.Join(nativeCAStageName, "ca.crt"), n.cert}, {filepath.Join(nativeCAStageName, "ca.key"), n.key}, {nativeCARecordName, n.record}} {
		if err := durableTrustReopen(filepath.Join(o.dir, entry.name), entry.body); err != nil {
			return err
		}
	}
	if err := writeTrustFile(filepath.Join(o.dir, "ca.key"), n.key, 0600); err != nil {
		return err
	}
	if err := trustDurabilityPoint("native-ca:key-published"); err != nil {
		return err
	}
	if err := writeTrustFile(filepath.Join(o.dir, "ca.crt"), n.cert, 0644); err != nil {
		return err
	}
	return trustDurabilityPoint("native-ca:root-published")
}
