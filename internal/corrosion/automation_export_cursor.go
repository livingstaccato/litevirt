package corrosion

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
)

const sourceExportCursorDomain = "litevirt/automation-source-export-cursor/v1"

// Fixed-size binary fields keep decoding independent of untrusted allocation
// sizes. SHA-256's standard binary state is 108 bytes in this codec version.
type sourceExportCursor struct {
	Binding                                   [32]byte
	Position, Bytes, TotalRecords, TotalBytes int64
	Digest                                    [32]byte
	HashState                                 [108]byte
}

func (c sourceExportCursor) body() []byte {
	b := make([]byte, 1+32+4*8+32+108)
	b[0] = 1
	copy(b[1:33], c.Binding[:])
	off := 33
	for _, v := range []int64{c.Position, c.Bytes, c.TotalRecords, c.TotalBytes} {
		binary.BigEndian.PutUint64(b[off:off+8], uint64(v))
		off += 8
	}
	copy(b[off:off+32], c.Digest[:])
	copy(b[off+32:], c.HashState[:])
	return b
}
func cursorHash(body []byte) []byte {
	h := sha256.New()
	sourceHash(h, []byte(sourceExportCursorDomain), body)
	return h.Sum(nil)
}
func (c sourceExportCursor) encode(key *ecdsa.PrivateKey) (string, error) {
	body := c.body()
	// Go1.26 nil randomness selects standard RFC6979; SignASN1 does not.
	sig, err := key.Sign(nil, cursorHash(body), crypto.SHA256)
	if err != nil {
		return "", err
	}
	raw := append(body, sig...)
	out := base64.RawURLEncoding.EncodeToString(raw)
	if len(out) > AutomationExportMaxCursor {
		return "", errors.New("export cursor exceeds bound")
	}
	return out, nil
}
func decodeSourceExportCursor(raw string, key *ecdsa.PublicKey) (sourceExportCursor, error) {
	var c sourceExportCursor
	if len(raw) == 0 || len(raw) > AutomationExportMaxCursor {
		return c, errors.New("invalid cursor length")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	const bodySize = 1 + 32 + 4*8 + 32 + 108
	if err != nil || len(b) <= bodySize || len(b) > bodySize+256 || b[0] != 1 || base64.RawURLEncoding.EncodeToString(b) != raw {
		return c, errors.New("malformed export cursor")
	}
	if !ecdsa.VerifyASN1(key, cursorHash(b[:bodySize]), b[bodySize:]) {
		return c, errors.New("unauthenticated export cursor")
	}
	copy(c.Binding[:], b[1:33])
	off := 33
	values := []*int64{&c.Position, &c.Bytes, &c.TotalRecords, &c.TotalBytes}
	for _, v := range values {
		*v = int64(binary.BigEndian.Uint64(b[off : off+8]))
		off += 8
		if *v < 0 {
			return c, errors.New("overflowing export cursor")
		}
	}
	copy(c.Digest[:], b[off:off+32])
	copy(c.HashState[:], b[off+32:bodySize])
	if c.Position > c.TotalRecords || c.Bytes > c.TotalBytes {
		return c, errors.New("cursor exceeds terminal inventory")
	}
	if _, err = c.hash(); err != nil {
		return c, err
	}
	return c, nil
}
func (c *sourceExportCursor) setHash(h hash.Hash) error {
	raw, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || len(raw) != len(c.HashState) {
		return errors.New("unsupported cursor hash codec")
	}
	copy(c.HashState[:], raw)
	return nil
}
func (c sourceExportCursor) hash() (hash.Hash, error) {
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(c.HashState[:]); err != nil {
		return nil, errors.New("invalid cursor digest state")
	}
	return h, nil
}
func sourceExportBinding(r AutomationExportRequest) [32]byte {
	// Publication ID is the storage owner's digest of the exact manifest, trust
	// and membership evidence (not its randomized signature wrapper). Bind the
	// opaque identity and normalized intent before
	// loading it; current authority and its terminal inventory are checked later.
	intent, _ := json.Marshal(r.Intent)
	h := sha256.New()
	sourceHash(h, []byte(sourceExportCursorDomain), []byte(r.Publication), intent, automationCutInteger(int64(r.Component)))
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func sourceExportCursorPreflight(r AutomationExportRequest, pair *tls.Certificate) error {
	if r.Cursor == "" {
		return nil
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unsupported cursor signer")
	}
	cursor, err := decodeSourceExportCursor(r.Cursor, &key.PublicKey)
	if err != nil {
		return err
	}
	if cursor.Binding != sourceExportBinding(r) {
		return errors.New("cursor publication/component/request binding differs")
	}
	return nil
}

func sourceExportOpenCursor(r AutomationExportRequest, p sourcePublication, pair *tls.Certificate) (sourceExportCursor, error) {
	var c sourceExportCursor
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return c, errors.New("unsupported cursor signer")
	}
	binding := sourceExportBinding(r)
	if r.Cursor != "" {
		var err error
		c, err = decodeSourceExportCursor(r.Cursor, &key.PublicKey)
		if err != nil {
			return c, err
		}
		if c.Binding != binding {
			return c, errors.New("cursor publication/component/request binding differs")
		}
		if r.Component >= 3 {
			inv := p.manifest.Cut.Inventory[int(r.Component)-3]
			digest, e := hex.DecodeString(inv.Digest)
			if e != nil || len(digest) != 32 || c.TotalRecords != inv.Records || c.TotalBytes != inv.Bytes || !bytes.Equal(c.Digest[:], digest) {
				return c, errors.New("cursor terminal inventory differs")
			}
		}
		return c, nil
	}
	c.Binding = binding
	h := sha256.New()
	if r.Component >= 3 {
		inv := p.manifest.Cut.Inventory[int(r.Component)-3]
		c.TotalRecords, c.TotalBytes = inv.Records, inv.Bytes
		digest, err := hex.DecodeString(inv.Digest)
		if err != nil || len(digest) != 32 {
			return c, errors.New("invalid cut terminal digest")
		}
		copy(c.Digest[:], digest)
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		h.Write(prefix)
	} else {
		raw := [][]byte{p.artifact, p.evidence, p.membership}[r.Component]
		c.TotalBytes = int64(len(raw))
		c.TotalRecords = (c.TotalBytes + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes
		c.Digest = sha256.Sum256(raw)
	}
	return c, c.setHash(h)
}
