package custody

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Internal safety caps are not advertised public admission/electorate limits.
const bootstrapPlaintextMaxBytes = contract.MaxDecisionBytes / 2
const bootstrapCiphertextMaxBytes = contract.MaxDecisionBytes * 3 / 4
const bootstrapRecipientsMax = 64

// SecretBinding identifies the original admitted payload. AdmittedGeneration is
// immutable; a later wrapping generation belongs to certified Assignment facts.
// These data arguments are not evidence of authorization.
type SecretBinding = contract.SecretBinding

// EffectiveBootstrap contains exact admitted files. Nil means absent and a
// nonnil empty slice means an existing empty file. No defaults are applied here.
type EffectiveBootstrap struct{ UserData, Metadata, NetworkConfig, VendorData []byte }

var errBootstrapSecret = errors.New("invalid bootstrap secret")

// EncryptBootstrap seals one complete bundle with native X25519 recipients.
// Recipient authentication, custody and admission authority must be established
// separately. Each recipient can decrypt alone; this is not threshold encryption.
// The caller must still validate the final complete decision/claim size.
func EncryptBootstrap(binding SecretBinding, files EffectiveBootstrap, recipients []*age.X25519Recipient) ([]byte, error) {
	plaintext, err := encodeBootstrap(binding, files)
	if err != nil || len(recipients) == 0 || len(recipients) > bootstrapRecipientsMax {
		return nil, errBootstrapSecret
	}
	native := make([]age.Recipient, 0, len(recipients))
	seen := make(map[string]bool, len(recipients))
	for _, recipient := range recipients {
		if recipient == nil {
			return nil, errBootstrapSecret
		}
		encoded := recipient.String()
		if seen[encoded] {
			return nil, errBootstrapSecret
		}
		seen[encoded] = true
		native = append(native, recipient)
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, native...)
	if err != nil {
		return nil, errBootstrapSecret
	}
	if _, err = writer.Write(plaintext); err != nil {
		return nil, errBootstrapSecret
	}
	// Close emits the final authenticated chunk, including for empty input.
	if writer.Close() != nil || ciphertext.Len() > bootstrapCiphertextMaxBytes {
		return nil, errBootstrapSecret
	}
	return ciphertext.Bytes(), nil
}

// DecryptBootstrap returns no files until bounded decryption reaches fully
// authenticated EOF and every original application binding matches. The expected
// binding must come from the certified original decision at integration; these
// arguments alone grant neither custody nor execution authority.
func DecryptBootstrap(binding SecretBinding, ciphertext []byte, identities []*age.X25519Identity) (EffectiveBootstrap, error) {
	fail := func() (EffectiveBootstrap, error) { return EffectiveBootstrap{}, errBootstrapSecret }
	if !validSecretBinding(binding) || len(ciphertext) == 0 || len(ciphertext) > bootstrapCiphertextMaxBytes || len(identities) == 0 || len(identities) > bootstrapRecipientsMax {
		return fail()
	}
	native := make([]age.Identity, 0, len(identities))
	seen := make(map[string]bool, len(identities))
	for _, identity := range identities {
		if identity == nil {
			return fail()
		}
		// Validate every native identity before age can stop at the first match.
		// Canonical public recipients identify duplicate keys, not just pointers.
		parsed, err := age.ParseX25519Identity(identity.String())
		if err != nil {
			return fail()
		}
		recipient := parsed.Recipient().String()
		if seen[recipient] {
			return fail()
		}
		seen[recipient] = true
		native = append(native, parsed)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), native...)
	if err != nil {
		return fail()
	}
	// The extra byte distinguishes authentic EOF at the cap from a limit-reader
	// EOF hiding additional plaintext. Any read/authentication error discards all
	// recovered bytes, even if earlier chunks authenticated successfully.
	plaintext, err := io.ReadAll(io.LimitReader(reader, bootstrapPlaintextMaxBytes+1))
	if err != nil || len(plaintext) > bootstrapPlaintextMaxBytes {
		return fail()
	}
	return decodeBootstrap(binding, plaintext)
}
