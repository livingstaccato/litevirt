package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"
	"os"
)

// An ephemeral owner-held FD, never a caller path or durable authority. The
// original DB inventory is separately rehashed under the real FULL lease.
// Only already authenticated prepared public artifacts enter this spool.
type receiverEstablishedSpool struct {
	file        *os.File
	dir         string
	h           hash.Hash
	digest      string
	count, size int64
	last        string
}

func newReceiverEstablishedSpool() (*receiverEstablishedSpool, error) {
	dir, err := os.MkdirTemp("", "litevirt-receiver-established-")
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "prepared-")
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	s := &receiverEstablishedSpool{file: f, dir: dir, h: sha256.New()}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		s.close()
		return nil, errors.New("receiver establishment spool is not owned regular file")
	}
	sourceHash(s.h, []byte("litevirt/receiver-prepared-artifacts/v1"))
	return s, nil
}
func (s *receiverEstablishedSpool) close() {
	if s == nil {
		return
	}
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	if s.dir != "" {
		os.RemoveAll(s.dir)
		s.dir = ""
	}
}
func (s *receiverEstablishedSpool) add(ctx context.Context, attempt, digest string, artifact []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.file == nil || s.digest != "" {
		return errors.New("receiver establishment spool is closed or sealed")
	}
	key := attempt + digest
	if !receiverDigest(attempt) || !receiverDigest(digest) || (s.count > 0 && key <= s.last) || len(artifact) == 0 || len(artifact) > maxReceiverEstablishedBytes || s.count == math.MaxInt64 || s.size > math.MaxInt64-int64(len(artifact))-132 {
		return errors.New("receiver establishment prepared frame bound or order")
	}
	var prefix [132]byte
	copy(prefix[:64], attempt)
	copy(prefix[64:128], digest)
	binary.BigEndian.PutUint32(prefix[128:], uint32(len(artifact)))
	for _, part := range [][]byte{prefix[:], artifact} {
		n, err := s.file.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	sourceHash(s.h, []byte(attempt), []byte(digest), artifact)
	s.count++
	s.size += int64(len(artifact)) + 132
	s.last = key
	return nil
}
func (s *receiverEstablishedSpool) seal() error {
	if s == nil || s.file == nil || s.digest != "" {
		return errors.New("receiver establishment spool cannot seal")
	}
	sourceHash(s.h, []byte("end"), automationCutInteger(s.count))
	s.digest = hex.EncodeToString(s.h.Sum(nil))
	s.h = nil
	return nil
}

// replay only frames bounded raw bytes. Signature verification/key access never
// occurs inside the caller's transaction. Exact private digest/count/end checks
// reject altered, missing, extra or reordered frames before any commit.
func (s *receiverEstablishedSpool) replay(ctx context.Context, visit func(string, string, []byte) error) error {
	if s == nil || s.file == nil || s.digest == "" {
		return errors.New("receiver establishment unsealed spool")
	}
	info, err := s.file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != s.size {
		return errors.New("receiver establishment spool size differs")
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-prepared-artifacts/v1"))
	last := ""
	remaining := s.size
	for n := int64(0); n < s.count; n++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		if remaining < 132 {
			return errors.New("receiver establishment spool truncated header")
		}
		remaining -= 132
		var prefix [132]byte
		if _, err = io.ReadFull(s.file, prefix[:]); err != nil {
			return err
		}
		attempt, digest := string(prefix[:64]), string(prefix[64:128])
		size := binary.BigEndian.Uint32(prefix[128:])
		if !receiverDigest(attempt) || !receiverDigest(digest) || attempt+digest <= last || size == 0 || size > maxReceiverEstablishedBytes || int64(size) > remaining {
			return errors.New("receiver establishment spool frame differs")
		}
		remaining -= int64(size)
		raw := make([]byte, int(size))
		if _, err = io.ReadFull(s.file, raw); err != nil {
			return err
		}
		sourceHash(h, []byte(attempt), []byte(digest), raw)
		if err = visit(attempt, digest, raw); err != nil {
			return err
		}
		last = attempt + digest
	}
	if remaining != 0 {
		return errors.New("receiver establishment spool count differs")
	}
	var extra [1]byte
	n, err := s.file.Read(extra[:])
	if n != 0 || err != io.EOF {
		return errors.New("receiver establishment spool has trailing data")
	}
	sourceHash(h, []byte("end"), automationCutInteger(s.count))
	if hex.EncodeToString(h.Sum(nil)) != s.digest {
		return errors.New("receiver establishment prepared bytes changed")
	}
	return ctx.Err()
}
