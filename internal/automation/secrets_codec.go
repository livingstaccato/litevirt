package automation

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

const effectiveBootstrapDomain = "litevirt/automation/effective-bootstrap\x00"
const effectiveBootstrapVersion = uint32(2)

func (binding SecretBinding) valid() bool {
	for _, s := range []string{binding.ClusterUID, binding.ProjectUID, binding.ResourceUID, binding.OperationID, binding.PayloadID} {
		if !secretStringValid(s) {
			return false
		}
	}
	return binding.AdmittedGeneration > 0
}

func secretStringValid(s string) bool { return len(s) > 0 && len(s) <= contract.MaxStringBytes }

// secretFrame checks the aggregate budget before copying bytes. Each optional
// field has both a presence byte and a length, including absent fields.
type secretFrame struct {
	bytes.Buffer
	invalid bool
}

func (f *secretFrame) raw(b []byte) {
	if f.invalid || len(b) > bootstrapPlaintextMaxBytes-f.Len() {
		f.invalid = true
		return
	}
	f.Write(b)
}
func (f *secretFrame) u32(n uint32)  { var b [4]byte; binary.BigEndian.PutUint32(b[:], n); f.raw(b[:]) }
func (f *secretFrame) u64(n uint64)  { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); f.raw(b[:]) }
func (f *secretFrame) text(s string) { f.u32(uint32(len(s))); f.raw([]byte(s)) }
func (f *secretFrame) optional(b []byte) {
	if b == nil {
		f.raw([]byte{0})
	} else {
		f.raw([]byte{1})
	}
	if len(b) > bootstrapPlaintextMaxBytes {
		f.invalid = true
		return
	}
	f.u32(uint32(len(b)))
	f.raw(b)
}

func encodeBootstrap(binding SecretBinding, files EffectiveBootstrap) ([]byte, error) {
	if !binding.valid() {
		return nil, errBootstrapSecret
	}
	var f secretFrame
	f.raw([]byte(effectiveBootstrapDomain))
	f.u32(effectiveBootstrapVersion)
	for _, s := range []string{binding.ClusterUID, binding.ProjectUID, binding.ResourceUID, binding.OperationID, binding.PayloadID} {
		f.text(s)
	}
	f.u64(binding.AdmittedGeneration)
	for _, b := range [][]byte{files.UserData, files.Metadata, files.NetworkConfig, files.VendorData} {
		f.optional(b)
	}
	if f.invalid {
		return nil, errBootstrapSecret
	}
	return f.Bytes(), nil
}

func decodeBootstrap(binding SecretBinding, plaintext []byte) (EffectiveBootstrap, error) {
	fail := func() (EffectiveBootstrap, error) { return EffectiveBootstrap{}, errBootstrapSecret }
	if !binding.valid() || len(plaintext) > bootstrapPlaintextMaxBytes {
		return fail()
	}
	r := bytes.NewReader(plaintext)
	domain := make([]byte, len(effectiveBootstrapDomain))
	if _, err := io.ReadFull(r, domain); err != nil || string(domain) != effectiveBootstrapDomain {
		return fail()
	}
	var version uint32
	if binary.Read(r, binary.BigEndian, &version) != nil || (version != 1 && version != effectiveBootstrapVersion) {
		return fail()
	}
	for _, expected := range []string{binding.ClusterUID, binding.ProjectUID, binding.ResourceUID, binding.OperationID, binding.PayloadID} {
		b, ok := readSecretField(r, contract.MaxStringBytes)
		if !ok || string(b) != expected {
			return fail()
		}
	}
	var generation uint64
	if binary.Read(r, binary.BigEndian, &generation) != nil || generation != binding.AdmittedGeneration {
		return fail()
	}
	var files EffectiveBootstrap
	fields := []*[]byte{&files.UserData, &files.Metadata, &files.NetworkConfig}
	// Version1 has exactly three fields. Its absent vendor-data is never inferred
	// from newer defaults; original accepted bytes remain unchanged.
	if version == 2 {
		fields = append(fields, &files.VendorData)
	}
	for _, dst := range fields {
		present, err := r.ReadByte()
		if err != nil || present > 1 {
			return fail()
		}
		b, ok := readSecretField(r, bootstrapPlaintextMaxBytes)
		if !ok {
			return fail()
		}
		if present == 0 {
			if len(b) != 0 {
				return fail()
			}
		} else {
			*dst = b
		}
	}
	if r.Len() != 0 {
		return fail()
	}
	return files, nil
}

func readSecretField(r *bytes.Reader, max int) ([]byte, bool) {
	var n uint32
	if binary.Read(r, binary.BigEndian, &n) != nil || uint64(n) > uint64(max) || uint64(n) > uint64(r.Len()) {
		return nil, false
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, false
	}
	return b, true
}
