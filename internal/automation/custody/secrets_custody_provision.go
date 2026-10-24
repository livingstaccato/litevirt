package custody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const CustodyProvisionRecordVersion = 1
const maxCustodyProtocolBytes = 1 << 20

type CustodyProvisionRef struct {
	Attempt         string
	Voter, Equality CustodyKeyRef
}

type custodyProvisionRecord struct {
	Version int
	Purpose string
	Scope   CustodyScope
	Ref     CustodyProvisionRef
	Body    []byte
}

func provisionPurpose(phase string) string {
	switch phase {
	case "plan":
		return "automation-custody-plan"
	case "recipient":
		return "automation-custody-recipient-record"
	case "completion":
		return "automation-custody-completion-record"
	}
	return ""
}
func provisionName(scope CustodyScope, ref CustodyProvisionRef) (string, error) {
	if !scope.valid() || !secretStringValid(ref.Attempt) || !ref.Voter.valid() || !ref.Equality.valid() || ref.Voter.Generation != ref.Equality.Generation || ref.Voter.ConfigDigest != ref.Equality.ConfigDigest {
		return "", ErrCustodyCorrupt
	}
	// Only public scope/attempt/key references determine the reservation name.
	b, err := json.Marshal(struct {
		Scope CustodyScope
		Ref   CustodyProvisionRef
	}{scope, ref})
	if err != nil || len(b) > maxCustodyProtocolBytes {
		return "", ErrCustodyCorrupt
	}
	h := sha256.Sum256(append([]byte("litevirt/automation/custody-provision-path/v1\x00"), b...))
	return "provision-" + hex.EncodeToString(h[:]), nil
}

// SaveProvisionRecord persists inert continuation data. An existing record can
// only be reopened byte-exactly; partial writes require explicit recovery and
// never grant currentness, certification, or permission to replace a key.
func (s *LocalCustody) SaveProvisionRecord(ref CustodyProvisionRef, phase string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if provisionPurpose(phase) == "" || len(body) == 0 || len(body) > maxCustodyProtocolBytes {
		return ErrCustodyCorrupt
	}
	name, err := provisionName(s.scope, ref)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(custodyProvisionRecord{CustodyProvisionRecordVersion, provisionPurpose(phase), s.scope, ref, body})
	if err != nil || len(encoded) > maxCustodyProtocolBytes {
		return ErrCustodyCorrupt
	}
	if err = s.attached(); err != nil {
		return err
	}
	if err = unix.Mkdirat(int(s.root.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return ErrCustodyUnavailable
	}
	dir, err := custodyOpenDir(s.root, name)
	if err != nil {
		return ErrCustodyUnavailable
	}
	defer dir.Close()
	if custodyDirectory(dir, true) != nil || s.syncDir(s.root) != nil || !custodyNamedDir(s.root, name, dir) {
		return ErrCustodyUnavailable
	}
	fd, err := unix.Openat(int(dir.Fd()), phase, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err == nil {
		f := os.NewFile(uintptr(fd), "custody-provision-record")
		n, writeErr := f.Write(encoded)
		syncErr := s.syncFile(f)
		closeErr := f.Close()
		if writeErr != nil || n != len(encoded) || syncErr != nil || closeErr != nil {
			return ErrCustodyUnavailable
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return ErrCustodyUnavailable
	}
	got, err := s.readProvision(dir, name, ref, phase)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, body) {
		return ErrCustodyConflict
	}
	return nil
}

func (s *LocalCustody) ReadProvisionRecord(ref CustodyProvisionRef, phase string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if provisionPurpose(phase) == "" {
		return nil, ErrCustodyCorrupt
	}
	name, err := provisionName(s.scope, ref)
	if err != nil {
		return nil, err
	}
	if err = s.attached(); err != nil {
		return nil, err
	}
	dir, err := custodyOpenDir(s.root, name)
	if err != nil {
		return nil, ErrCustodyUnavailable
	}
	defer dir.Close()
	if err = custodyDirectory(dir, true); err != nil {
		return nil, err
	}
	return s.readProvision(dir, name, ref, phase)
}

func (s *LocalCustody) readProvision(dir *os.File, name string, ref CustodyProvisionRef, phase string) ([]byte, error) {
	b, f, err := custodyReadBounded(dir, phase, maxCustodyProtocolBytes)
	if errors.Is(err, errCustodyMissing) {
		return nil, ErrCustodyRecoveryRequired
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var record custodyProvisionRecord
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&record) != nil {
		return nil, ErrCustodyCorrupt
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, b) || record.Version != CustodyProvisionRecordVersion || record.Purpose != provisionPurpose(phase) || record.Scope != s.scope || record.Ref != ref || len(record.Body) == 0 {
		return nil, ErrCustodyCorrupt
	}
	if s.syncFile(f) != nil || s.syncDir(dir) != nil || s.syncDir(s.root) != nil || !custodyNamedDir(s.root, name, dir) {
		return nil, ErrCustodyUnavailable
	}
	var current, opened unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), phase, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(f.Fd()), &opened) != nil || current.Dev != opened.Dev || current.Ino != opened.Ino {
		return nil, ErrCustodyUnavailable
	}
	if err = s.attached(); err != nil {
		return nil, err
	}
	return record.Body, nil
}

// HasProvisionRecord distinguishes a genuinely absent continuation from a
// corrupt or inaccessible one. Presence is never import or current authority.
func (s *LocalCustody) HasProvisionRecord(ref CustodyProvisionRef, phase string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if provisionPurpose(phase) == "" {
		return false, ErrCustodyCorrupt
	}
	name, err := provisionName(s.scope, ref)
	if err != nil {
		return false, err
	}
	if err = s.attached(); err != nil {
		return false, err
	}
	dir, err := custodyOpenDir(s.root, name)
	if errors.Is(err, errCustodyMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if err = custodyDirectory(dir, true); err != nil {
		return false, err
	}
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), phase, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || !custodyNamedDir(s.root, name, dir) {
		return false, ErrCustodyUnavailable
	}
	return true, nil
}
